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


def _identity_result_to_dict(result: Any) -> dict[str, Any]:
    if isinstance(result, IdentityResolutionResult):
        result_dict: dict[str, Any] = {
            "owner_name_hex": result.owner_name_hex,
            "owner_public_key_hex": result.owner_public_key_hex,
            "seq": result.seq,
        }
    else:
        result_dict = {
            "owner_name_hex": getattr(result, "owner_name_hex"),
            "owner_public_key_hex": getattr(result, "owner_public_key_hex"),
            "seq": int(getattr(result, "seq")),
        }

    authorization = getattr(result, "authorization", None)
    if authorization is not None:
        to_dict = getattr(authorization, "to_dict", None)
        serialized_authorization = to_dict() if callable(to_dict) else authorization
        if not isinstance(serialized_authorization, dict):
            raise ValueError("authorization metadata is not serializable")
        # Omit authorization for legacy records to preserve their JSON shape.
        result_dict["authorization"] = serialized_authorization

    return result_dict


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="decent-identity",
        description=(
            "Resolve identity records or publish updates. "
            "Use --finalized-envelope PATH for finalized multisignature put."
        ),
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # put
    put_p = subparsers.add_parser("put", help="Publish a signed identity update")
    put_p.add_argument("--identifier", required=True)
    put_p.add_argument(
        "--owner-privkey",
        dest="owner_privkey",
        default=None,
        help="Ed25519 private key PEM path (legacy mode)",
    )
    put_p.add_argument(
        "--seq",
        type=int,
        default=None,
        help="Monotonic seq (legacy mode)",
    )
    put_p.add_argument(
        "--finalized-envelope",
        dest="finalized_envelope",
        default=None,
        help="Finalized multisignature identity envelope path",
    )
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
            bootstrap = _parse_endpoints(args.bootstrap)
            if args.finalized_envelope is not None:
                if args.owner_privkey is not None or args.seq is not None:
                    raise ValueError(
                        "finalized envelope cannot be combined with legacy identity signing arguments"
                    )
                put_kwargs: dict[str, Any] = {
                    "identifier": args.identifier,
                    "host": args.host,
                    "port": args.port,
                    "bootstrap": bootstrap,
                    "finalized_envelope_path": args.finalized_envelope,
                }
            else:
                if args.owner_privkey is None or args.seq is None:
                    raise ValueError("legacy put requires --owner-privkey and --seq")
                put_kwargs = {
                    "identifier": args.identifier,
                    "owner_privkey_pem_path": args.owner_privkey,
                    "seq": args.seq,
                    "host": args.host,
                    "port": args.port,
                    "bootstrap": bootstrap,
                }
            await put_identity(**put_kwargs)
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

        try:
            res_dict = _identity_result_to_dict(res)
        except (AttributeError, TypeError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

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
