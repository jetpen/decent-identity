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


@pytest.mark.trio
async def test_put_identity_finalized_envelope_passes_exact_bytes_without_private_key(
    monkeypatch, tmp_path
):
    import sys
    import types
    from pathlib import Path

    import decent_identity.identity_resolver as m

    identifier = "Ben"
    envelope_bytes = b"exact-finalized-envelope-bytes"
    envelope_path = tmp_path / "identity.signed-envelope.cbor"
    envelope_path.write_bytes(envelope_bytes)
    put_calls: dict[str, object] = {}
    dht_bootstrap_seeds: list[str] = []
    envelope_reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def tracked_read_bytes(path: Path) -> bytes:
        envelope_reads.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", tracked_read_bytes)

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

    decent_registry_pkg = types.ModuleType("decent_registry")
    decent_registry_pkg.__path__ = []
    dht_pkg = types.ModuleType("decent_registry.dht")
    dht_pkg.__path__ = []
    libp2p_dht_mod = types.ModuleType("decent_registry.dht.libp2p_dht")
    libp2p_dht_mod.Libp2pKadDHT = FakeLibp2pKadDHT

    class FakeRegistryService:
        def __init__(self, dht):
            self.dht = dht

        async def put_identity(self, *, owner_name_hex: str, envelope_cbor: bytes):
            put_calls["owner_name_hex"] = owner_name_hex
            put_calls["envelope_cbor"] = envelope_cbor

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
        finalized_envelope_path=envelope_path,
        host="127.0.0.1",
        port=0,
        bootstrap=["/ip4/127.0.0.1/tcp/0/p2p/peer"],
    )

    assert put_calls == {
        "owner_name_hex": identifier.encode("utf-8").hex(),
        "envelope_cbor": envelope_bytes,
    }
    assert dht_bootstrap_seeds == ["/ip4/127.0.0.1/tcp/0/p2p/peer"]
    assert envelope_reads == [envelope_path]


@pytest.mark.trio
async def test_put_identity_rejects_mixed_finalized_and_legacy_arguments(
    monkeypatch, tmp_path
):
    from pathlib import Path

    import decent_identity.identity_resolver as m

    envelope_reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def tracked_read_bytes(path: Path) -> bytes:
        envelope_reads.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", tracked_read_bytes)
    envelope_path = tmp_path / "missing.signed-envelope.cbor"

    with pytest.raises(
        ValueError,
        match="finalized envelope cannot be combined with legacy identity signing arguments",
    ):
        await m.put_identity(
            identifier="Ben",
            owner_privkey_pem_path="owner.pem",
            seq=1,
            finalized_envelope_path=envelope_path,
            host="127.0.0.1",
            port=0,
            bootstrap=[],
        )

    assert envelope_reads == []


@pytest.mark.trio
async def test_put_identity_rejects_unreadable_finalized_envelope_before_network(
    tmp_path,
):
    import decent_identity.identity_resolver as m

    with pytest.raises(
        ValueError, match="cannot read finalized identity envelope file"
    ):
        await m.put_identity(
            identifier="Ben",
            finalized_envelope_path=tmp_path / "missing.signed-envelope.cbor",
            host="127.0.0.1",
            port=0,
            bootstrap=[],
        )


@pytest.mark.trio
async def test_put_identity_rejects_two_finalized_envelope_sources(tmp_path):
    import decent_identity.identity_resolver as m

    envelope_path = tmp_path / "identity.signed-envelope.cbor"
    envelope_path.write_bytes(b"finalized-envelope")

    with pytest.raises(
        ValueError,
        match="provide exactly one of finalized_envelope_path or finalized_envelope_cbor",
    ):
        await m.put_identity(
            identifier="Ben",
            finalized_envelope_path=envelope_path,
            finalized_envelope_cbor=b"finalized-envelope",
            host="127.0.0.1",
            port=0,
            bootstrap=[],
        )
