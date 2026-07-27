from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import trio

from .identity_resolver import (
    IdentityResolutionResult,
    get_identity_record,
    put_identity,
)


def _parse_endpoints(values: list[str]) -> list[str]:
    # Keep permissive parsing: allow comma-separated repeats.
    eps: list[str] = []
    for v in values:
        if not v:
            continue
        parts = [p.strip() for p in v.split(",") if p.strip()]
        eps.extend(parts)
    return eps


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="decent-identity")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # put
    put_p = subparsers.add_parser("put", help="Publish a signed identity update")
    put_p.add_argument("--identifier", required=True)
    put_p.add_argument(
        "--owner-privkey",
        dest="owner_privkey",
        required=True,
        help="Ed25519 private key PEM path",
    )
    put_p.add_argument("--seq", type=int, required=True, help="Monotonic seq")
    put_p.add_argument("--host", required=True)
    put_p.add_argument("--port", type=int, required=True)
    put_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="libp2p seed multiaddr(s) with /p2p/<peerid>; may repeat and/or be comma-separated",
    )

    # get
    get_p = subparsers.add_parser("get", help="Resolve a signed identity record")
    get_p.add_argument("--identifier", required=True)
    get_p.add_argument("--host", required=True)
    get_p.add_argument("--port", type=int, required=True)
    get_p.add_argument(
        "--bootstrap",
        action="append",
        default=[],
        help="libp2p seed multiaddr(s) with /p2p/<peerid>; may repeat and/or be comma-separated",
    )
    get_p.add_argument(
        "--quorum",
        type=int,
        default=0,
        help="quorum parameter forwarded to registry",
    )

    args = parser.parse_args(argv)

    async def _async_put() -> int:
        try:
            await put_identity(
                identifier=args.identifier,
                owner_privkey_pem_path=args.owner_privkey,
                seq=args.seq,
                host=args.host,
                port=args.port,
                bootstrap=_parse_endpoints(args.bootstrap),
            )
            print(1)
            return 0
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        except Exception:
            print("put failed", file=sys.stderr)
            return 1

    async def _async_get() -> int:
        try:
            res = await get_identity_record(
                identifier=args.identifier,
                host=args.host,
                port=args.port,
                bootstrap=_parse_endpoints(args.bootstrap),
                quorum=args.quorum,
            )
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        except Exception:
            print("get failed", file=sys.stderr)
            return 1

        if res is None:
            print("not found")
            return 1

        if not isinstance(res, IdentityResolutionResult):
            # Defensive: allow test fakes / alternative return types.
            # Convert via attribute access.
            res_dict: dict[str, Any] = {
                "owner_name_hex": getattr(res, "owner_name_hex"),
                "owner_public_key_hex": getattr(res, "owner_public_key_hex"),
                "seq": int(getattr(res, "seq")),
            }
        else:
            res_dict = {
                "owner_name_hex": res.owner_name_hex,
                "owner_public_key_hex": res.owner_public_key_hex,
                "seq": res.seq,
            }

        payload = {
            "identifier": args.identifier,
            **res_dict,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.cmd == "put":
        raise SystemExit(trio.run(_async_put))
    if args.cmd == "get":
        raise SystemExit(trio.run(_async_get))
    raise SystemExit(f"Unknown command: {args.cmd}")
