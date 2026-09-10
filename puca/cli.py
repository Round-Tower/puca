"""Puca CLI. Thin entry point; refuses live actions without an authorizing scope.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.6, Prior: Unknown
"""
from __future__ import annotations

import argparse
import sys

from .scope import Scope, ScopeError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="puca", description="Puca security kit")
    parser.add_argument("--scope", default="scope.yaml", help="path to scope file")
    sub = parser.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check-scope", help="validate scope and test a target")
    chk.add_argument("target", help="URL or host to check authorization for")
    args = parser.parse_args(argv)

    if args.cmd == "check-scope":
        try:
            scope = Scope.load(args.scope)
        except FileNotFoundError:
            print(f"no scope file at {args.scope} — copy scope.example.yaml", file=sys.stderr)
            return 2
        try:
            scope.assert_authorized(args.target)
        except ScopeError as e:
            print(f"NOT AUTHORIZED: {e}", file=sys.stderr)
            return 1
        print(f"AUTHORIZED: {args.target} (engagement: {scope.engagement})")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
