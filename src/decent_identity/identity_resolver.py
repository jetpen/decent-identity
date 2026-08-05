from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path



@dataclass(frozen=True, slots=True)
class IdentityResolutionResult:
    owner_name_hex: str
    owner_public_key_hex: str
    seq: int


async def resolve_identity_record(
    *,
    owner_name_hex: str,
    # Connection params intentionally left generic: this repo delegates
    # DHT/network concerns to `decent-registry`.
    host: str,
    port: int,
    bootstrap: list[str],
    quorum: int = 0,
) -> IdentityResolutionResult | None:
    """Resolve and verify the latest verified Identity Record for `owner_name_hex`.

    Uses decent-registry primitives to:
    - connect a temporary libp2p Kad-DHT node to provided bootstrap peers
    - resolve and verify the latest Identity Record state (seq monotonic)

    Out of scope:
    - DID method / DID Documents
    """

    # Import inside function so this repo can be imported without installing
    # the sibling `decent-registry` package.
    from decent_registry.dht.libp2p_dht import Libp2pKadDHT
    from decent_registry.registry_service import RegistryService

    async with Libp2pKadDHT(listen=f"/ip4/{host}/tcp/{port}") as dht:
        for seed in bootstrap:
            await dht.bootstrap(seed)
        svc = RegistryService(dht=dht)
        res = await svc.get_identity(owner_name_hex=owner_name_hex, quorum=quorum)
        if res is None:
            return None

        # `decent_registry.registry_service.RegistryService.get_identity()`
        # returns a plain dict with keys: owner_name, owner_public_key, seq.
        owner_name_raw = res["owner_name"]
        if isinstance(owner_name_raw, (bytes, bytearray)):
            owner_name_hex = owner_name_raw.hex()
        else:
            owner_name_hex = str(owner_name_raw)

        owner_public_key_raw = res["owner_public_key"]
        owner_public_key_hex = (
            owner_public_key_raw.hex()
            if isinstance(owner_public_key_raw, (bytes, bytearray))
            else str(owner_public_key_raw)
        )

        return IdentityResolutionResult(
            owner_name_hex=owner_name_hex,
            owner_public_key_hex=owner_public_key_hex,
            seq=int(res["seq"]),
        )


def _derive_owner_name_hex_from_identifier(identifier: str) -> str:
    # Raw UTF-8 bytes; no normalization.
    if identifier is None or identifier == "":
        raise ValueError("identifier must be a non-empty string")
    return identifier.encode("utf-8").hex()


def _read_finalized_envelope(
    *,
    finalized_envelope_path: str | Path | None,
    finalized_envelope_cbor: bytes | bytearray | None,
) -> bytes | None:
    if finalized_envelope_path is not None and finalized_envelope_cbor is not None:
        raise ValueError(
            "provide exactly one of finalized_envelope_path or finalized_envelope_cbor"
        )

    if finalized_envelope_path is not None:
        try:
            return Path(finalized_envelope_path).read_bytes()
        except (OSError, TypeError):
            raise ValueError("cannot read finalized identity envelope file") from None

    if finalized_envelope_cbor is not None:
        if not isinstance(finalized_envelope_cbor, (bytes, bytearray)):
            raise ValueError("finalized_envelope_cbor must be bytes")
        return bytes(finalized_envelope_cbor)

    return None


async def put_identity(
    *,
    identifier: str,
    owner_privkey_pem_path: str | None = None,
    seq: int | None = None,
    host: str,
    port: int,
    bootstrap: list[str],
    finalized_envelope_path: str | Path | None = None,
    finalized_envelope_cbor: bytes | bytearray | None = None,
) -> None:
    """Store a legacy or finalized identity binding for `identifier`.

    Legacy mode delegates signing to ``decent-registry`` using
    ``owner_privkey_pem_path`` and ``seq``. Finalized mode accepts the exact
    versioned SignedEnvelope bytes and delegates envelope validation and
    publication without private-key material.
    """
    finalized_mode = (
        finalized_envelope_path is not None or finalized_envelope_cbor is not None
    )
    if finalized_mode and (
        owner_privkey_pem_path is not None or seq is not None
    ):
        raise ValueError(
            "finalized envelope cannot be combined with legacy identity signing arguments"
        )

    finalized_envelope = _read_finalized_envelope(
        finalized_envelope_path=finalized_envelope_path,
        finalized_envelope_cbor=finalized_envelope_cbor,
    )

    if finalized_envelope is None:
        if owner_privkey_pem_path is None or seq is None:
            raise ValueError(
                "legacy identity put requires owner_privkey_pem_path and seq"
            )
        assert owner_privkey_pem_path is not None
        assert seq is not None

    owner_name_hex = _derive_owner_name_hex_from_identifier(identifier)

    from decent_registry.dht.libp2p_dht import Libp2pKadDHT
    from decent_registry.registry_service import RegistryService

    async with Libp2pKadDHT(listen=f"/ip4/{host}/tcp/{port}") as dht:
        for seed in bootstrap:
            await dht.bootstrap(seed)
        svc = RegistryService(dht=dht)
        if finalized_envelope is not None:
            await svc.put_identity(
                owner_name_hex=owner_name_hex,
                envelope_cbor=finalized_envelope,
            )
        else:
            await svc.put_identity(
                owner_name_hex=owner_name_hex,
                owner_privkey_pem_path=owner_privkey_pem_path,
                seq=int(seq),
            )


async def get_identity_record(
    *,
    identifier: str,
    host: str,
    port: int,
    bootstrap: list[str],
    quorum: int = 0,
) -> IdentityResolutionResult | None:
    """Resolve the latest verified identity binding for `identifier`."""
    owner_name_hex = _derive_owner_name_hex_from_identifier(identifier)
    return await resolve_identity_record(
        owner_name_hex=owner_name_hex,
        host=host,
        port=port,
        bootstrap=bootstrap,
        quorum=quorum,
    )
