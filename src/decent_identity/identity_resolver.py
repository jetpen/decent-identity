from __future__ import annotations

from dataclasses import dataclass



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


async def put_identity(
    *,
    identifier: str,
    owner_privkey_pem_path: str,
    seq: int,
    host: str,
    port: int,
    bootstrap: list[str],
) -> None:
    """Store a signed identity binding for `identifier`.

    Delegates verification and "latest" selection to `decent-registry`.
    """
    owner_name_hex = _derive_owner_name_hex_from_identifier(identifier)

    from decent_registry.dht.libp2p_dht import Libp2pKadDHT
    from decent_registry.registry_service import RegistryService

    async with Libp2pKadDHT(listen=f"/ip4/{host}/tcp/{port}") as dht:
        for seed in bootstrap:
            await dht.bootstrap(seed)
        svc = RegistryService(dht=dht)
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
