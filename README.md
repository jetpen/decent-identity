# Decentralized Identity

Exact-match identity lookup service.

Given an identifier string (full name, email like `mailto:<addr>`, telephone like `tel:+<digits>`), compute `SHA-256` over the identifier’s **raw UTF-8 bytes** (no normalization) and use that as the storage key.

`put` stores a signed binding (identifier + Ed25519 public key + proof-of-possession signature). `get` returns the latest verified public key for the identifier.

## Running the Server

`decent-identity` is a client that delegates all networking/DHT/storage to a running `decent-registry` **node**.

The `decent-registry node` process prints an identify-style bootstrap multiaddr in the form:

`[BOOTSTRAP] /ip4/<host>/tcp/<port>/p2p/<PEERID>`

Copy that value (everything after `[BOOTSTRAP]`) and use it as the client `--bootstrap` argument.

### Minimal two-terminal setup (single node)

Terminal 1 (start the node; keep running):

```bash
mkdir -p ~/.decent
cat > ~/.decent/registry.yaml <<'YAML'
network:
  host: 127.0.0.1
  port: 9000
  bootstrap: []

datastore:
  # Stored locally as LMDB durable cache.
  path: ~/.decent/registry

logging:
  verbosity: 1
YAML

decent-registry -v node --config ~/.decent/registry.yaml
```

Terminal 2 (run the client `put`/`get`):

```bash
# Replace with the full bootstrap multiaddr copied from Terminal 1
NODE_BOOTSTRAP="/ip4/127.0.0.1/tcp/9000/p2p/<PEERID>"

# Generate an owner private key (Ed25519, PKCS#8 PEM)
decent-registry keygen --output ~/.decent/owner_privkey.pem

# put (exit 0 on success; prints "1")
decent-identity put \
  --identifier "Ben" \
  --owner-privkey ~/.decent/owner_privkey.pem \
  --seq 1 \
  --host 127.0.0.1 \
  --port 9100 \
  --bootstrap "$NODE_BOOTSTRAP"

# get (exit 0 on success; JSON output; or "not found" with exit code 1)
decent-identity get \
  --identifier "Ben" \
  --host 127.0.0.1 \
  --port 9101 \
  --bootstrap "$NODE_BOOTSTRAP"
```

For full server/node setup details and network scaling options, see:
- `decent-registry/docs/single-node-server-setup.md`
- `decent-registry/docs/multi-node-cluster-setup.md`

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

### Running tests

- Ensure you are in the project root directory.
- Activate your virtual environment: `source .venv/bin/activate`.
- Run tests: `pytest -q`.

This command should pass all tests.

Note: `pyproject.toml` declares a local-path dependency on `decent-registry`. This repo may reuse `decent-registry` verification primitives, but the lookup service + storage + API shape are defined by the wayfinder map.
