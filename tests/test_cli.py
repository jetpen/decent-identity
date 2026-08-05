from __future__ import annotations

import json
import pytest

from decent_identity.identity_resolver import IdentityResolutionResult


def test_cli_get_not_found_exit1_prints_not_found(monkeypatch, capsys):
    import decent_identity.cli as c

    async def fake_get_identity_record(**kwargs):
        return None

    monkeypatch.setattr(c, "get_identity_record", fake_get_identity_record)

    with pytest.raises(SystemExit) as exc:
        c.main(
            [
                "get",
                "--identifier",
                "Ben",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]
        )

    assert exc.value.code == 1
    assert capsys.readouterr().out.strip() == "not found"


def test_cli_get_success_prints_json(monkeypatch, capsys):
    import decent_identity.cli as c

    async def fake_get_identity_record(**kwargs):
        return IdentityResolutionResult(
            owner_name_hex="aa",
            owner_public_key_hex="bb",
            seq=7,
        )

    monkeypatch.setattr(c, "get_identity_record", fake_get_identity_record)

    with pytest.raises(SystemExit) as exc:
        c.main(
            [
                "get",
                "--identifier",
                "Ben",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]
        )

    assert exc.value.code == 0
    stdout = capsys.readouterr().out
    payload = json.loads(stdout)
    assert payload["identifier"] == "Ben"
    assert payload["owner_name_hex"] == "aa"
    assert payload["owner_public_key_hex"] == "bb"
    assert payload["seq"] == 7


def test_cli_put_success_prints_1(monkeypatch, capsys):
    import decent_identity.cli as c

    calls: dict[str, object] = {}

    async def fake_put_identity(**kwargs):
        calls.update(kwargs)
        return None

    monkeypatch.setattr(c, "put_identity", fake_put_identity)

    with pytest.raises(SystemExit) as exc:
        c.main(
            [
                "put",
                "--identifier",
                "Ben",
                "--owner-privkey",
                "priv.pem",
                "--seq",
                "2",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]
        )

    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "1"
    assert calls["identifier"] == "Ben"
    assert calls["owner_privkey_pem_path"] == "priv.pem"
    assert calls["seq"] == 2
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 0


def test_cli_put_value_error_exit2(monkeypatch, capsys):
    import decent_identity.cli as c

    async def fake_put_identity(**kwargs):
        raise ValueError("identifier must be a non-empty string")

    monkeypatch.setattr(c, "put_identity", fake_put_identity)

    with pytest.raises(SystemExit) as exc:
        c.main(
            [
                "put",
                "--identifier",
                "",
                "--owner-privkey",
                "priv.pem",
                "--seq",
                "2",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]
        )

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "error:" in err



def test_cli_put_seq_monotonic_value_error_exit2(monkeypatch, capsys):
    import decent_identity.cli as c

    async def fake_put_identity(**kwargs):
        raise ValueError("seq monotonicity violation")

    monkeypatch.setattr(c, "put_identity", fake_put_identity)

    with pytest.raises(SystemExit) as exc:
        c.main(
            [
                "put",
                "--identifier",
                "Ben",
                "--owner-privkey",
                "priv.pem",
                "--seq",
                "0",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]
        )

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert "seq monotonicity" in err



def test_cli_put_runtime_error_exit1(monkeypatch, capsys):
    import decent_identity.cli as c

    async def fake_put_identity(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(c, "put_identity", fake_put_identity)

    with pytest.raises(SystemExit) as exc:
        c.main(
            [
                "put",
                "--identifier",
                "Ben",
                "--owner-privkey",
                "priv.pem",
                "--seq",
                "0",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]
        )

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "put failed" in err
