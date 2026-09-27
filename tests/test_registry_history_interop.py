from __future__ import annotations

import hashlib
from typing import Any

import pytest
from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.durable_store import LMDBDatastore
from decent_registry.encoding import (
    OPERATION_ORDINARY_UPDATE,
    OPERATION_OWNER_KEY_ROTATION,
    OPERATION_REPLACE_SIGNERS,
    RECORD_KIND_IDENTITY,
    encode_multisignature_signed_update,
    encode_signed_update,
)
from decent_registry.multisig_bundle import (
    draft_identity_bundle,
    finalize_bundle,
    merge_proof,
    sign_bundle,
)
from decent_registry.signed_envelope import (
    encode_multisignature_envelope,
    encode_signed_envelope,
)
from decent_registry.verification import make_signed_update_signature
from libp2p.crypto.ed25519 import create_new_key_pair

from decent_identity.identity_resolver import (
    IdentityResolutionResult,
    get_identity_record,
    put_identity,
)

OWNER_NAME = b"post-genesis-identity"


def _keypairs(count: int = 4) -> list[Any]:
    return [create_new_key_pair() for _ in range(count)]


def _signer_set(keypairs: list[Any]) -> list[dict[int, Any]]:
    return [
        {1: chr(ord("a") + index), 2: keypair.public_key.to_bytes()}
        for index, keypair in enumerate(keypairs)
    ]


def _finalize(bundle: Any, keypairs: list[Any]) -> bytes:
    first = merge_proof(bundle, sign_bundle(bundle, keypairs[0].private_key))
    complete = merge_proof(first, sign_bundle(bundle, keypairs[1].private_key))
    return finalize_bundle(complete)


def _peer_address(registry: Libp2pKadDHT) -> str:
    address = registry.get_listen_multiaddr()
    if "/p2p/" not in address:
        address = f"{address}/p2p/{registry.host.get_id().to_string()}"
    return address


@pytest.mark.trio
async def test_identity_api_reads_and_publishes_with_registry_owned_history(tmp_path):
    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()

    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis = _finalize(genesis_bundle, keypairs)
    update_two_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=2,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            genesis_bundle.signed_update_bytes
        ).digest(),
    )
    update_two = _finalize(update_two_bundle, keypairs)
    update_three_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=3,
        signer_set=signer_set,
        operation=OPERATION_ORDINARY_UPDATE,
        predecessor_state_hash=hashlib.sha256(
            update_two_bundle.signed_update_bytes
        ).digest(),
    )
    update_three = _finalize(update_three_bundle, keypairs)
    replacement_signers = _signer_set(keypairs[1:4])
    replacement_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=4,
        signer_set=replacement_signers,
        epoch=2,
        operation=OPERATION_REPLACE_SIGNERS,
        predecessor_state_hash=hashlib.sha256(
            update_three_bundle.signed_update_bytes
        ).digest(),
    )
    replacement = encode_multisignature_envelope(
        signed_update_bytes=replacement_bundle.signed_update_bytes,
        proofs=[
            {
                1: "a",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=replacement_bundle.signed_update_bytes,
                    owner_private_key=keypairs[0].private_key,
                ),
            },
            {
                1: "b",
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=replacement_bundle.signed_update_bytes,
                    owner_private_key=keypairs[1].private_key,
                ),
            },
        ],
    )

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "registry-history.lmdb"),
    ) as registry:
        await registry.put_signed_identity_record(identity_key, genesis)
        await registry.put_signed_identity_record(identity_key, update_two)
        peer = _peer_address(registry)

        resolved = await get_identity_record(
            identifier=OWNER_NAME.decode("utf-8"),
            host="127.0.0.1",
            port=0,
            bootstrap=[peer],
        )
        assert isinstance(resolved, IdentityResolutionResult)
        assert resolved.seq == 2

        await put_identity(
            identifier=OWNER_NAME.decode("utf-8"),
            host="127.0.0.1",
            port=0,
            bootstrap=[peer],
            finalized_envelope_cbor=update_three,
        )

        assert registry._durable_get(
            kind="identity", key=bytes.fromhex(identity_key)
        ) == update_three

        resolved_after_write = await get_identity_record(
            identifier=OWNER_NAME.decode("utf-8"),
            host="127.0.0.1",
            port=0,
            bootstrap=[peer],
        )

        await put_identity(
            identifier=OWNER_NAME.decode("utf-8"),
            host="127.0.0.1",
            port=0,
            bootstrap=[peer],
            finalized_envelope_cbor=replacement,
        )
        assert registry._durable_get(
            kind="identity", key=bytes.fromhex(identity_key)
        ) == replacement
        resolved_after_replacement = await get_identity_record(
            identifier=OWNER_NAME.decode("utf-8"),
            host="127.0.0.1",
            port=0,
            bootstrap=[peer],
        )

    assert isinstance(resolved_after_write, IdentityResolutionResult)
    assert resolved_after_write.seq == 3
    assert resolved_after_write.owner_public_key_hex == keypairs[0].public_key.to_bytes().hex()
    assert isinstance(resolved_after_replacement, IdentityResolutionResult)
    assert resolved_after_replacement.seq == 4
    assert resolved_after_replacement.owner_public_key_hex == keypairs[0].public_key.to_bytes().hex()
    assert resolved_after_replacement.authorization is not None
    assert resolved_after_replacement.authorization.operation == OPERATION_REPLACE_SIGNERS
    assert tuple(
        signer.public_key_hex
        for signer in resolved_after_replacement.authorization.signer_set
    ) == tuple(keypair.public_key.to_bytes().hex() for keypair in keypairs[1:4])


@pytest.mark.trio
async def test_identity_api_publishes_operation_five_from_legacy_history(tmp_path):
    keypairs = _keypairs()
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    previous = encode_signed_update(
        record_fields={1: OWNER_NAME, 2: keypairs[0].public_key.to_bytes()},
        payload={},
        seq=1,
    )
    legacy = encode_signed_envelope(
        signed_update_bytes=previous,
        signature=make_signed_update_signature(
            signed_update_bytes_canonical=previous,
            owner_private_key=keypairs[0].private_key,
        ),
    )
    rotation_update = encode_multisignature_signed_update(
        record_fields={1: OWNER_NAME, 2: keypairs[3].public_key.to_bytes()},
        payload={},
        seq=2,
        authorization={
            1: 1,
            2: RECORD_KIND_IDENTITY,
            3: OPERATION_OWNER_KEY_ROTATION,
            4: 1,
            5: 2,
            6: _signer_set([keypairs[3], keypairs[1], keypairs[2]]),
            7: hashlib.sha256(previous).digest(),
        },
    )
    rotation = encode_multisignature_envelope(
        signed_update_bytes=rotation_update,
        proofs=[
            {
                1: None,
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=rotation_update,
                    owner_private_key=keypairs[0].private_key,
                ),
            }
        ],
    )

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "registry-legacy.lmdb"),
    ) as registry:
        await registry.put_signed_identity_record(identity_key, legacy)
        peer = _peer_address(registry)

        await put_identity(
            identifier=OWNER_NAME.decode("utf-8"),
            host="127.0.0.1",
            port=0,
            bootstrap=[peer],
            finalized_envelope_cbor=rotation,
        )

        assert registry._durable_get(
            kind="identity", key=bytes.fromhex(identity_key)
        ) == rotation

        resolved = await get_identity_record(
            identifier=OWNER_NAME.decode("utf-8"),
            host="127.0.0.1",
            port=0,
            bootstrap=[peer],
        )

    assert isinstance(resolved, IdentityResolutionResult)
    assert resolved.seq == 2
    assert resolved.owner_public_key_hex == keypairs[3].public_key.to_bytes().hex()
    assert resolved.authorization is not None
    assert resolved.authorization.operation == OPERATION_OWNER_KEY_ROTATION


@pytest.mark.trio
async def test_identity_api_distinguishes_missing_history_from_missing_identity(tmp_path):
    from decent_identity.identity_resolver import IdentityHistoryUnavailable

    keypairs = _keypairs()
    signer_set = _signer_set(keypairs[:3])
    identity_key = hashlib.sha256(OWNER_NAME).hexdigest()
    genesis_bundle = draft_identity_bundle(
        owner_name=OWNER_NAME,
        owner_public_key=keypairs[0].public_key.to_bytes(),
        seq=1,
        signer_set=signer_set,
    )
    genesis_hash = hashlib.sha256(genesis_bundle.signed_update_bytes).digest()
    update = _finalize(
        draft_identity_bundle(
            owner_name=OWNER_NAME,
            owner_public_key=keypairs[0].public_key.to_bytes(),
            seq=2,
            signer_set=signer_set,
            operation=OPERATION_ORDINARY_UPDATE,
            predecessor_state_hash=genesis_hash,
        ),
        keypairs,
    )

    async with Libp2pKadDHT() as peer:
        current_key = peer._kad_key(identity_key, kind="identity")
        peer.dht.value_store.put(current_key.encode("utf-8"), update)
        bootstrap = _peer_address(peer)

        with pytest.raises(IdentityHistoryUnavailable, match="history"):
            await get_identity_record(
                identifier=OWNER_NAME.decode("utf-8"),
                host="127.0.0.1",
                port=0,
                bootstrap=[bootstrap],
            )
