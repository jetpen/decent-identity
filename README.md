# Decent Identity

Exact-match identity lookup service.

Given an identifier string (full name, email like `mailto:<addr>`, telephone like `tel:+<digits>`), compute `SHA-256` over the identifier’s **raw UTF-8 bytes** (no normalization) and use that as the storage key.

`put` stores a signed binding (identifier + Ed25519 public key + proof-of-possession signature). `get` returns the latest verified public key for the identifier.

## Development

- Create a venv, then install editable:
  - `python3 -m venv .venv`
  - `source .venv/bin/activate`
  - `pip install -U pip`
  - `pip install -e ".[dev]"`

Note: `pyproject.toml` declares a local-path dependency on `decent-registry`. This repo may reuse `decent-registry` verification primitives, but the lookup service + storage + API shape are defined by the wayfinder map.
