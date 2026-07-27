# Decent Identity

Decentralized identity lookup service storing and retrieving **public key bindings** for human-readable identifiers.

## Primary artifact

A service/library exposing exact-match lookups:

- **Input identifier types**: full name (e.g. `"Ben Eng"`), email address (e.g. `mailto:ben@jetpen.com`), telephone number (e.g. `tel:+14699395731`).
- **Hash key**: `SHA-256` over the **raw UTF-8 bytes** of the identifier string (no normalization), used as the lookup/storage key.
- **Output**: the latest verified public key for that hash (optionally with the record metadata used to select “latest”).

## Scope (this effort)

1. **put**: accept an identity binding record for an identifier that includes:
   - the identifier (name/alias)
   - an Ed25519 public key
   - a digital signature that is verified by the provided public key

2. **get**: accept an identifier string, compute its `SHA-256` key using the same raw UTF-8/no-normalization rule, and return the latest verified binding.

3. **Durable storage**: implement/choose a storage backend that supports large key cardinality (billions).

4. **API surface**: define and implement the lookup service contract (library interface and a CLI surface for put/get).

## Out of scope (for now)

- DID method / DID Documents
- Key generation / key management
- Persistent networking node lifecycle/config management (transport/backplane is a later decision unless required by the chosen storage backend)
