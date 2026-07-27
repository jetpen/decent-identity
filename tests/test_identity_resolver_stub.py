import pytest


@pytest.mark.trio
async def test_resolve_identity_record_parses_success(monkeypatch):
    # Unit test: avoid network by monkeypatching decent-registry calls.
    import decent_identity.identity_resolver as m

    class FakeDHT:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def bootstrap(self, seed: str):
            return None

    class FakeLibp2pKadDHT:
        def __init__(self, listen: str):
            self.listen = listen

        async def __aenter__(self):
            return FakeDHT()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    # Patch import targets for the inside-function imports.
    import sys
    import types

    decent_registry_pkg = types.ModuleType("decent_registry")
    decent_registry_pkg.__path__ = []
    dht_pkg = types.ModuleType("decent_registry.dht")
    dht_pkg.__path__ = []

    libp2p_dht_mod = types.ModuleType("decent_registry.dht.libp2p_dht")
    libp2p_dht_mod.Libp2pKadDHT = FakeLibp2pKadDHT

    class FakeRegistryService:
        def __init__(self, dht):
            self.dht = dht

        async def get_identity(
            self, *, owner_name_hex: str, quorum: int = 0
        ):
            return {
                "owner_name": bytes.fromhex(owner_name_hex),
                "owner_public_key": "aa",
                "seq": 7,
            }

    reg_service_mod = types.ModuleType("decent_registry.registry_service")
    reg_service_mod.RegistryService = FakeRegistryService

    monkeypatch.setitem(sys.modules, "decent_registry", decent_registry_pkg)
    monkeypatch.setitem(sys.modules, "decent_registry.dht", dht_pkg)
    monkeypatch.setitem(
        sys.modules,
        "decent_registry.dht.libp2p_dht",
        libp2p_dht_mod,
    )
    monkeypatch.setitem(
        sys.modules,
        "decent_registry.registry_service",
        reg_service_mod,
    )

    res = await m.resolve_identity_record(
        owner_name_hex="11" * 16,
        host="127.0.0.1",
        port=0,
        bootstrap=["/ip4/127.0.0.1/tcp/0/p2p/peer"],
        quorum=0,
    )

    assert res is not None
    assert res.owner_name_hex == "11" * 16
    assert res.owner_public_key_hex == "aa"
    assert res.seq == 7


@pytest.mark.trio
async def test_resolve_identity_record_not_found_returns_none(monkeypatch):
    import decent_identity.identity_resolver as m

    class FakeDHT:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def bootstrap(self, seed: str):
            return None

    class FakeLibp2pKadDHT:
        def __init__(self, listen: str):
            self.listen = listen

        async def __aenter__(self):
            return FakeDHT()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    # Patch import targets for the inside-function imports.
    import sys
    import types

    decent_registry_pkg = types.ModuleType("decent_registry")
    decent_registry_pkg.__path__ = []
    dht_pkg = types.ModuleType("decent_registry.dht")
    dht_pkg.__path__ = []

    libp2p_dht_mod = types.ModuleType("decent_registry.dht.libp2p_dht")
    libp2p_dht_mod.Libp2pKadDHT = FakeLibp2pKadDHT

    class FakeRegistryService:
        def __init__(self, dht):
            self.dht = dht

        async def get_identity(
            self, *, owner_name_hex: str, quorum: int = 0
        ):
            return None

    reg_service_mod = types.ModuleType("decent_registry.registry_service")
    reg_service_mod.RegistryService = FakeRegistryService

    monkeypatch.setitem(sys.modules, "decent_registry", decent_registry_pkg)
    monkeypatch.setitem(sys.modules, "decent_registry.dht", dht_pkg)
    monkeypatch.setitem(
        sys.modules,
        "decent_registry.dht.libp2p_dht",
        libp2p_dht_mod,
    )
    monkeypatch.setitem(
        sys.modules,
        "decent_registry.registry_service",
        reg_service_mod,
    )

    res = await m.resolve_identity_record(
        owner_name_hex="22" * 16,
        host="127.0.0.1",
        port=0,
        bootstrap=[],
    )
    assert res is None
