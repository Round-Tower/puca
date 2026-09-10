"""Security probes for Model Context Protocol (MCP) tool servers.

Aimed at the OWASP Top 10 for Agentic Applications (2026): a malicious or
compromised tool server can hijack an agent via its *tool descriptions*
(ASI02 Tool Misuse, ASI06 Memory/Context Poisoning), over-broad tools grant
excessive agency, and unauthenticated servers expose everything.

Pure request-building + response-analysis. Sending is done by puca.http, gated
by scope. First real target: M1K3 (http://127.0.0.1:4242/mcp).

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.7, Prior: Unknown
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

# Patterns in a tool description that would try to hijack the calling agent.
INJECTION_MARKERS = (
    "ignore previous", "ignore all previous", "disregard", "system prompt",
    "you must", "do not tell", "exfiltrate", "send to", "api key", "secret",
    "<system>", "instead of", "before responding", "always call",
)

# Verbs/tools that grant broad, dangerous agency (ASI03/ASI05).
HIGH_AGENCY_MARKERS = (
    "exec", "shell", "command", "eval", "delete", "write_file", "sudo",
    "payment", "transfer", "email", "http", "fetch", "browse",
)


def tools_list_request() -> dict:
    """The JSON-RPC body that enumerates a server's tools."""
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def parse_tools(response: dict | str) -> list[dict]:
    """Extract the tool list from an MCP tools/list response."""
    data = json.loads(response) if isinstance(response, str) else response
    return list((data.get("result") or {}).get("tools") or [])


@dataclass
class ToolFinding:
    tool: str
    kind: str          # "prompt-injection" | "excessive-agency"
    evidence: str
    asi: str


def scan_tool_descriptions(tools: list[dict]) -> list[ToolFinding]:
    """Flag tool descriptions that try to steer the agent, or grant broad power."""
    findings: list[ToolFinding] = []
    for t in tools:
        name = str(t.get("name", "?"))
        desc = f"{t.get('description', '')}".lower()
        for m in INJECTION_MARKERS:
            if m in desc:
                findings.append(ToolFinding(
                    name, "prompt-injection", f"description contains {m!r}",
                    "ASI02/ASI06"))
                break
        for m in HIGH_AGENCY_MARKERS:
            if m in name.lower() or m in desc:
                findings.append(ToolFinding(
                    name, "excessive-agency",
                    f"exposes high-agency capability ({m!r})", "ASI03/ASI05"))
                break
    return findings
