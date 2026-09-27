from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class SignerMetadata:
    """Stable public representation of one authorized signer."""

    signer_id: str
    public_key_hex: str

    def to_dict(self) -> dict[str, str]:
        return {
            "signer_id": self.signer_id,
            "public_key": self.public_key_hex,
        }


@dataclass(frozen=True, slots=True)
class AuthorizationMetadata:
    """Public v1 authorization metadata with a registry-compatible mapping shape.

    Registry-side protocol validation occurs before this adapter maps the result;
    this model validates the stable Python representation exposed to callers.
    """
    version: int
    operation: int
    epoch: int
    threshold: int
    signer_set: tuple[SignerMetadata, ...]
    predecessor_state_hash: str
    state_hash: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AuthorizationMetadata":
        signer_set_value = value.get("signer_set")
        if not isinstance(signer_set_value, (list, tuple)):
            raise ValueError("identity authorization signer_set must be a sequence")

        signer_set: list[SignerMetadata] = []
        for entry in signer_set_value:
            if not isinstance(entry, Mapping):
                raise ValueError("identity authorization signer entry must be a mapping")
            signer_id = entry.get("signer_id")
            public_key_hex = entry.get("public_key")
            if not isinstance(signer_id, str) or not isinstance(public_key_hex, str):
                raise ValueError("identity authorization signer fields must be strings")
            signer_set.append(
                SignerMetadata(
                    signer_id=signer_id,
                    public_key_hex=public_key_hex,
                )
            )

        integer_fields = ("version", "operation", "epoch", "threshold")
        integers: dict[str, int] = {}
        for field_name in integer_fields:
            field_value = value.get(field_name)
            if isinstance(field_value, bool) or not isinstance(field_value, int):
                raise ValueError(
                    f"identity authorization {field_name} must be an integer"
                )
            integers[field_name] = field_value

        predecessor_state_hash = value.get("predecessor_state_hash")
        state_hash = value.get("state_hash")
        if not isinstance(predecessor_state_hash, str) or not isinstance(
            state_hash, str
        ):
            raise ValueError("identity authorization state hashes must be strings")

        return cls(
            version=integers["version"],
            operation=integers["operation"],
            epoch=integers["epoch"],
            threshold=integers["threshold"],
            signer_set=tuple(signer_set),
            predecessor_state_hash=predecessor_state_hash,
            state_hash=state_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "operation": self.operation,
            "epoch": self.epoch,
            "threshold": self.threshold,
            "signer_set": [entry.to_dict() for entry in self.signer_set],
            "predecessor_state_hash": self.predecessor_state_hash,
            "state_hash": self.state_hash,
        }


def _authorization_from_result(result: Any) -> AuthorizationMetadata | None:
    if isinstance(result, Mapping):
        raw_authorization = result.get("authorization")
    else:
        raw_authorization = getattr(result, "authorization", None)

    if raw_authorization is None:
        return None

    to_dict = getattr(raw_authorization, "to_dict", None)
    if callable(to_dict):
        raw_authorization = to_dict()
    if not isinstance(raw_authorization, Mapping):
        raise ValueError("identity authorization metadata must be a mapping")
    return AuthorizationMetadata.from_mapping(raw_authorization)


class IdentityHistoryUnavailable(RuntimeError):
    """A current Identity state was observed, but its predecessor history was unavailable."""


@dataclass(frozen=True, slots=True)
class IdentityResolutionResult:
    owner_name_hex: str
    owner_public_key_hex: str
    seq: int
    authorization: AuthorizationMetadata | None = None


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
    from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
    try:
        from decent_registry.exceptions import (
            IdentityHistoryUnavailable as RegistryIdentityHistoryUnavailable,
        )
    except ImportError:
        RegistryIdentityHistoryUnavailable = ()
    from decent_registry.registry_service import RegistryService

    async with Libp2pKadDHT(
        listen=f"/ip4/{host}/tcp/{port}", dht_mode=DHTMode.CLIENT
    ) as dht:
        for seed in bootstrap:
            await dht.bootstrap(seed)
        svc = RegistryService(dht=dht)
        try:
            res = await svc.get_identity(owner_name_hex=owner_name_hex, quorum=quorum)
        except RegistryIdentityHistoryUnavailable as exc:
            raise IdentityHistoryUnavailable(str(exc)) from exc
        if res is None:
            return None

        if isinstance(res, Mapping):
            owner_name_raw = res["owner_name"]
            owner_public_key_raw = res["owner_public_key"]
            seq_raw = res["seq"]
        else:
            owner_name_raw = getattr(res, "owner_name_hex", None)
            if owner_name_raw is None:
                owner_name_raw = getattr(res, "owner_name")
            owner_public_key_raw = getattr(res, "owner_public_key")
            seq_raw = getattr(res, "seq")

        owner_name_hex = (
            owner_name_raw.hex()
            if isinstance(owner_name_raw, (bytes, bytearray))
            else str(owner_name_raw)
        )
        owner_public_key_hex = (
            owner_public_key_raw.hex()
            if isinstance(owner_public_key_raw, (bytes, bytearray))
            else str(owner_public_key_raw)
        )

        return IdentityResolutionResult(
            owner_name_hex=owner_name_hex,
            owner_public_key_hex=owner_public_key_hex,
            seq=int(seq_raw),
            authorization=_authorization_from_result(res),
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

    from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
    try:
        from decent_registry.exceptions import (
            IdentityHistoryUnavailable as RegistryIdentityHistoryUnavailable,
        )
    except ImportError:
        RegistryIdentityHistoryUnavailable = ()
    from decent_registry.registry_service import RegistryService

    async with Libp2pKadDHT(
        listen=f"/ip4/{host}/tcp/{port}", dht_mode=DHTMode.CLIENT
    ) as dht:
        for seed in bootstrap:
            await dht.bootstrap(seed)
        svc = RegistryService(dht=dht)
        try:
            if finalized_envelope is not None:
                await svc.put_identity(
                    owner_name_hex=owner_name_hex,
                    envelope_cbor=finalized_envelope,
                )
            else:
                assert seq is not None
                await svc.put_identity(
                    owner_name_hex=owner_name_hex,
                    owner_privkey_pem_path=owner_privkey_pem_path,
                    seq=seq,
                )
        except RegistryIdentityHistoryUnavailable as exc:
            raise IdentityHistoryUnavailable(str(exc)) from exc


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
