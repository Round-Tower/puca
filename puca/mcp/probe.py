"""Security probes for Model Context Protocol (MCP) tool servers.

Aimed at the OWASP Top 10 for Agentic Applications (2026): a malicious or
compromised tool server can hijack an agent via its *tool descriptions*
(ASI02 Tool Misuse, ASI06 Memory/Context Poisoning), over-broad tools grant
excessive agency, and unauthenticated servers expose everything.

Pure request-building + response-analysis. Sending is done by puca.http, gated
by scope. First real target: M1K3 (http://127.0.0.1:4242/mcp).

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.7, Prior: Unknown
Review: Kev + claude-opus-4-8, 2026-09-10 — Added run() (drives tools/list
  through the scope-gated Sender + flags unauthenticated enumeration), and
  reworked scan_tool_descriptions from substring markers to a word-boundary
  capability taxonomy (kills the "retrieval"->"eval" false positive; adds
  microphone-capture and ASI06 persistent-memory-write detection).
  Confidence now 0.8.
"""
from __future__ import annotations

import json
import re as _re
from dataclasses import dataclass

# Patterns in a tool description that would try to hijack the calling agent.
INJECTION_MARKERS = (
    "ignore previous", "ignore all previous", "disregard", "system prompt",
    "you must", "do not tell", "exfiltrate", "send to", "api key", "secret",
    "<system>", "instead of", "before responding", "always call",
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
    kind: str          # "prompt-injection" | "excessive-agency" | "unauthenticated-enumeration"
    evidence: str
    asi: str


# Capability taxonomy: each entry maps evidence in a tool's name/description to a
# real capability and its OWASP-Agentic mapping. Matched on WORD BOUNDARIES so
# "retrieval" is not mistaken for "eval" and a local doc "fetch" is not egress.
#
#   (label, asi, word_signals, phrase_signals)
# word_signals   : single tokens, matched with boundaries against "name + desc"
# phrase_signals : multi-word substrings, matched against the description
CAPABILITIES = (
    ("code-execution",            "ASI03/ASI05",
     ("exec", "shell", "command", "eval", "subprocess", "sudo", "spawn"), ()),
    ("destructive-state",         "ASI05/ASI08",
     ("delete", "erase", "forget", "destroy", "wipe", "drop"),
     ("permanently forget", "permanently remove")),
    ("persistent-memory-write",   "ASI06",
     ("remember", "memorize"),
     ("store text in", "becomes part of what", "into the assistant's memory",
      "for future conversations")),
    ("microphone-capture",        "ASI05",
     (), ("microphone", "listen on", "record audio", "the mic")),
    ("network-egress",            "ASI05/ASI07",
     ("browse",),
     ("open a web link", "fetch a url", "http request", "make a request to",
      "navigate to")),
    ("financial",                 "ASI05",
     ("payment", "transfer", "refund", "invoice", "charge"), ()),
    ("messaging",                 "ASI05",
     (), ("send an email", "send a message", "post to", "reply to")),
)


def _has_word(haystack: str, word: str) -> bool:
    return _re.search(rf"(?<![a-z0-9]){_re.escape(word)}(?![a-z0-9])", haystack) is not None


def scan_tool_descriptions(tools: list[dict]) -> list[ToolFinding]:
    """Flag tool descriptions that try to steer the agent, or grant broad power.

    Prompt-injection markers use phrase matching (distinctive, low false-positive).
    Capability detection uses word boundaries + a taxonomy so a description is
    flagged for the capability it actually exposes, not an accidental substring.
    """
    findings: list[ToolFinding] = []
    for t in tools:
        name = str(t.get("name", "?"))
        desc = f"{t.get('description', '')}".lower()
        haystack = name.lower().replace("_", " ") + " " + desc
        for m in INJECTION_MARKERS:
            if m in desc:
                findings.append(ToolFinding(
                    name, "prompt-injection", f"description contains {m!r}",
                    "ASI02/ASI06"))
                break
        for label, asi, words, phrases in CAPABILITIES:
            hit = next((w for w in words if _has_word(haystack, w)), None) \
                or next((ph for ph in phrases if ph in desc), None)
            if hit:
                findings.append(ToolFinding(
                    name, "excessive-agency",
                    f"{label}: exposes {label.replace('-', ' ')} (matched {hit!r})",
                    asi))
    return findings


# Headers for MCP Streamable HTTP: a compliant client accepts either a plain
# JSON reply or an SSE stream.
MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


@dataclass
class McpScanResult:
    url: str
    tools: list[dict]
    findings: list[ToolFinding]
    unauthenticated: bool


def run(sender, url: str, *, auth_headers: dict[str, str] | None = None) -> McpScanResult:
    """Enumerate an MCP server's tools *through the gated Sender* and scan them.

    sender is a puca.http.Sender (or anything with the same .send signature): it
    re-checks scope and rate-limits, so this cannot fire at an unauthorized host.
    Read-only — a single tools/list, no tools/call.
    """
    headers = dict(MCP_HEADERS)
    if auth_headers:
        headers.update(auth_headers)
    resp = sender.send("POST", url, headers=headers,
                       body=json.dumps(tools_list_request()))
    tools = parse_tools(resp.body)
    findings = scan_tool_descriptions(tools)
    unauthenticated = bool(tools) and not auth_headers
    if unauthenticated:
        # The server handed its full tool catalogue to a request bearing no
        # credentials and no initialize handshake — anything that can reach the
        # port can enumerate (and likely call) every tool.
        findings.insert(0, ToolFinding(
            tool="<server>", kind="unauthenticated-enumeration",
            evidence=(f"tools/list returned {len(tools)} tools with no auth token "
                      f"and no initialize handshake"),
            asi="ASI05"))
    return McpScanResult(url=url, tools=tools, findings=findings,
                         unauthenticated=unauthenticated)
