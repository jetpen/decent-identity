from __future__ import annotations

import json

import pytest

from decent_identity.identity_resolver import (
    AuthorizationMetadata,
    IdentityResolutionResult,
    SignerMetadata,
)


def _get_args() -> list[str]:
    return [
        "get",
        "--identifier",
        "Ben",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
    ]


def test_put_finalized_envelope_delegates_without_legacy_material(monkeypatch, capsys):
    import decent_identity.cli as c

    calls: dict[str, object] = {}

    async def fake_put_identity(**kwargs):
        calls.update(kwargs)

    monkeypatch.setattr(c, "put_identity", fake_put_identity)

    with pytest.raises(SystemExit) as exc:
        c.main(
            [
                "put",
                "--identifier",
                "Ben",
                "--finalized-envelope",
                "identity.signed-envelope.cbor",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]
        )

    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "1"
    assert calls == {
        "identifier": "Ben",
        "host": "127.0.0.1",
        "port": 0,
        "bootstrap": [],
        "finalized_envelope_path": "identity.signed-envelope.cbor",
    }


def test_put_rejects_mixed_finalized_and_legacy_arguments(monkeypatch, capsys):
    import decent_identity.cli as c

    calls: list[dict[str, object]] = []

    async def fake_put_identity(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(c, "put_identity", fake_put_identity)

    with pytest.raises(SystemExit) as exc:
        c.main(
            [
                "put",
                "--identifier",
                "Ben",
                "--finalized-envelope",
                "identity.signed-envelope.cbor",
                "--owner-privkey",
                "owner.pem",
                "--seq",
                "3",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
            ]
        )

    assert exc.value.code == 2
    assert calls == []
    assert "finalized envelope cannot be combined" in capsys.readouterr().err


def test_get_multisig_result_includes_authorization(monkeypatch, capsys):
    import decent_identity.cli as c

    authorization = AuthorizationMetadata(
        version=1,
        operation=1,
        epoch=2,
        threshold=2,
        signer_set=(
            SignerMetadata(signer_id="alice", public_key_hex="aa" * 32),
            SignerMetadata(signer_id="bob", public_key_hex="bb" * 32),
            SignerMetadata(signer_id="carol", public_key_hex="cc" * 32),
        ),
        predecessor_state_hash="00" * 32,
        state_hash="dd" * 32,
    )

    async def fake_get_identity_record(**kwargs):
        return IdentityResolutionResult(
            owner_name_hex="aa",
            owner_public_key_hex="bb",
            seq=7,
            authorization=authorization,
        )

    monkeypatch.setattr(c, "get_identity_record", fake_get_identity_record)

    with pytest.raises(SystemExit) as exc:
        c.main(_get_args())

    assert exc.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["authorization"] == authorization.to_dict()
    assert payload["authorization"]["threshold"] == 2
    assert payload["authorization"]["signer_set"][1]["signer_id"] == "bob"


def test_get_legacy_result_omits_authorization(monkeypatch, capsys):
    import decent_identity.cli as c

    async def fake_get_identity_record(**kwargs):
        return IdentityResolutionResult(
            owner_name_hex="aa",
            owner_public_key_hex="bb",
            seq=7,
        )

    monkeypatch.setattr(c, "get_identity_record", fake_get_identity_record)

    with pytest.raises(SystemExit) as exc:
        c.main(_get_args())

    assert exc.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert "authorization" not in payload


def test_put_help_documents_finalized_envelope(capsys):
    import decent_identity.cli as c

    with pytest.raises(SystemExit) as exc:
        c.main(["put", "--help"])

    assert exc.value.code == 0
    assert "--finalized-envelope" in capsys.readouterr().out
