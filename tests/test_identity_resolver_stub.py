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


@pytest.mark.trio
async def test_put_identity_derives_owner_name_hex_and_calls_registry(monkeypatch):
    import decent_identity.identity_resolver as m

    identifier = "Ben"
    expected_owner_name_hex = identifier.encode("utf-8").hex()
    owner_privkey_pem_path = "priv.pem"
    seq = 3

    class FakeDHT:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def bootstrap(self, seed: str):
            dht_bootstrap_seeds.append(seed)

    class FakeLibp2pKadDHT:
        def __init__(self, listen: str):
            self.listen = listen

        async def __aenter__(self):
            return FakeDHT()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    dht_bootstrap_seeds: list[str] = []
    put_calls: dict[str, object] = {}

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

        async def put_identity(
            self,
            *,
            owner_name_hex: str,
            owner_privkey_pem_path: str,
            seq: int,
        ):
            put_calls["owner_name_hex"] = owner_name_hex
            put_calls["owner_privkey_pem_path"] = owner_privkey_pem_path
            put_calls["seq"] = seq

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

    await m.put_identity(
        identifier=identifier,
        owner_privkey_pem_path=owner_privkey_pem_path,
        seq=seq,
        host="127.0.0.1",
        port=0,
        bootstrap=["/ip4/127.0.0.1/tcp/0/p2p/peer"],
    )

    assert put_calls["owner_name_hex"] == expected_owner_name_hex
    assert put_calls["owner_privkey_pem_path"] == owner_privkey_pem_path
    assert put_calls["seq"] == seq
    assert dht_bootstrap_seeds == ["/ip4/127.0.0.1/tcp/0/p2p/peer"]


@pytest.mark.trio
async def test_get_identity_record_derives_owner_name_hex_and_maps_result(monkeypatch):
    import decent_identity.identity_resolver as m

    identifier = "hello"
    expected_owner_name_hex = identifier.encode("utf-8").hex()

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

    get_calls: dict[str, object] = {}

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
            self,
            *,
            owner_name_hex: str,
            quorum: int = 0,
        ):
            get_calls["owner_name_hex"] = owner_name_hex
            get_calls["quorum"] = quorum
            return {
                "owner_name": bytes.fromhex(owner_name_hex),
                "owner_public_key": b"\xaa",
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

    res = await m.get_identity_record(
        identifier=identifier,
        host="127.0.0.1",
        port=0,
        bootstrap=["/ip4/127.0.0.1/tcp/0/p2p/peer"],
        quorum=3,
    )

    assert res is not None
    assert get_calls["owner_name_hex"] == expected_owner_name_hex
    assert get_calls["quorum"] == 3
    assert res.owner_name_hex == expected_owner_name_hex
    assert res.owner_public_key_hex == "aa"
    assert res.seq == 7


@pytest.mark.trio
async def test_get_identity_record_not_found_returns_none(monkeypatch):
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
            self,
            *,
            owner_name_hex: str,
            quorum: int = 0,
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

    res = await m.get_identity_record(
        identifier="missing",
        host="127.0.0.1",
        port=0,
        bootstrap=[],
        quorum=0,
    )

    assert res is None


def test_derive_owner_name_hex_from_identifier_empty_raises():
    import decent_identity.identity_resolver as m

    with pytest.raises(ValueError):
        m._derive_owner_name_hex_from_identifier("")
