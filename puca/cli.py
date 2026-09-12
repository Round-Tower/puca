"""Puca CLI. Thin entry point; refuses live actions without an authorizing scope.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.6, Prior: Unknown
Review: Kev + claude-opus-4-8, 2026-09-10 — Added the "mcp" subcommand:
  enumerate + scan an authorized MCP server through the gated Sender. Live
  actions still refuse without an authorizing scope. Confidence now 0.65.
Review: Kev + claude-opus-4-8, 2026-09-11 — Added the "massassign" subcommand:
  probe an authorized writable endpoint for mass-assignment with non-escalating
  sentinels, through the gated Sender. Still refuses without a scope; the probe
  is state-changing so it only fires against an authorized target. Confidence
  now 0.65.
Review: Kev + muse-spark-1.2-contributor-free, 2026-09-12 — Fix mypy narrowing:
  massassign branch used the same `result` name as mcp, so mypy saw
  ToolFinding vs Finding collisions (6 errors). Switch second branch to
  `elif` and rename to `scan` so each result's findings type is distinct.
  No behavior change; CLIs still scope-gated. Ruff + mypy clean.
  Confidence now 0.85.
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
    mcp = sub.add_parser("mcp", help="enumerate + scan an MCP tool server (scope-gated)")
    mcp.add_argument("target", help="MCP endpoint URL, e.g. http://127.0.0.1:4242/mcp")
    ma = sub.add_parser("massassign",
                        help="probe a writable endpoint for mass assignment (scope-gated, state-changing)")
    ma.add_argument("target", help="URL of your OWN object, e.g. https://staging.example.com/api/settings/42/")
    ma.add_argument("--fields", required=True,
                    help="comma-separated serializer field names to test (e.g. from an OpenAPI dump)")
    ma.add_argument("--header", action="append", default=[],
                    help="request header 'Name: value' (repeatable; your own auth token)")
    ma.add_argument("--method", default="PATCH",
                    help="write method (default PATCH; PUT may full-replace and null other fields — prefer PATCH)")
    ma.add_argument("--no-confirm", action="store_true",
                    help="skip the follow-up GET that confirms persistence")
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
    if args.cmd == "mcp":
        from .http import Sender
        from .mcp import probe
        try:
            scope = Scope.load(args.scope)
        except FileNotFoundError:
            print(f"no scope file at {args.scope} — copy scope.example.yaml", file=sys.stderr)
            return 2
        try:
            result = probe.run(Sender(scope), args.target)
        except ScopeError as e:
            print(f"NOT AUTHORIZED: {e}", file=sys.stderr)
            return 1
        print(f"MCP {result.url} — {len(result.tools)} tools enumerated")
        if not result.findings:
            print("no findings.")
            return 0
        for hit in result.findings:
            print(f"  [{hit.asi}] {hit.kind}: {hit.tool} — {hit.evidence}")
        return 0
    elif args.cmd == "massassign":
        from .http import Sender
        from .massassign import prober
        try:
            scope = Scope.load(args.scope)
        except FileNotFoundError:
            print(f"no scope file at {args.scope} — copy scope.example.yaml", file=sys.stderr)
            return 2
        headers: dict[str, str] = {}
        for h in args.header:
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()
        fields = [f.strip() for f in args.fields.split(",") if f.strip()]
        endpoint = prober.WritableEndpoint(args.target, method=args.method)
        try:
            scan = prober.run(Sender(scope), endpoint, fields, headers,
                              confirm=not args.no_confirm)
        except ScopeError as e:
            print(f"NOT AUTHORIZED: {e}", file=sys.stderr)
            return 1
        probed = len(scan.results)
        print(f"massassign {endpoint.url} — {probed} privileged field(s) probed")
        for name, verdict in scan.results:
            print(f"  {verdict}: {name}")
        if not scan.findings:
            print("no mass-assignment findings.")
            return 0
        for finding in scan.findings:
            print(f"  [{finding.owasp_id}] {finding.severity}: {finding.title}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
