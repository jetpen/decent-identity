# Decentralized Identity

Exact-match identity lookup service.

Given an identifier string (full name, email like `mailto:<addr>`, telephone like `tel:+<digits>`), compute `SHA-256` over the identifier’s **raw UTF-8 bytes** (no normalization) and use that as the storage key.

`put` stores a signed binding (identifier + Ed25519 public key + proof-of-possession signature). `get` returns the latest verified public key for the identifier.

## CLI Usage

The `decent-identity` CLI provides `put` and `get` subcommands for exact-match identity lookups.

The `--identifier` argument accepts a user-friendly string (e.g. `"Ben"`, `"mailto:ben@jetpen.com"`). The CLI converts it to `owner_name_hex` internally using the raw UTF-8 bytes with no normalization, per the lookup contract.

### `put` — Publish a signed identity update

```
decent-identity put \
  --identifier "Ben" \
  --owner-privkey ./owner_privkey.pem \
  --seq 1 \
  --host 127.0.0.1 \
  --port 0 \
  --bootstrap /ip4/127.0.0.1/tcp/0/p2p/peer
```

- Exit code `0` on success; prints `1`.
- Argument/validation errors: exit code `2` (stderr prefixed with `error:`).
- Other runtime failures: exit code `1` (stderr `put failed`).

### `get` — Resolve a signed identity record

```
decent-identity get \
  --identifier "Ben" \
  --host 127.0.0.1 \
  --port 0 \
  --bootstrap /ip4/127.0.0.1/tcp/0/p2p/peer
```

- On success (exit code `0`): prints JSON with keys:
  - `identifier`
  - `owner_name_hex`
  - `owner_public_key_hex`
  - `seq`
- On not found (exit code `1`): prints `not found`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Not found (for `get`) or runtime failure |
| 2    | Argument/validation error |

## Development

- Create a venv, then install editable:
  - `python3 -m venv .venv`
  - `source .venv/bin/activate`
  - `pip install -U pip`
  - `pip install -e ".[dev]"`

Note: `pyproject.toml` declares a local-path dependency on `decent-registry`. This repo may reuse `decent-registry` verification primitives, but the lookup service + storage + API shape are defined by the wayfinder map.
