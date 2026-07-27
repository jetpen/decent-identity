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
