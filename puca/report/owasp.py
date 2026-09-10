"""OWASP catalogues (2026) + a Finding model + Markdown renderer.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.8, Prior: Unknown
"""
from __future__ import annotations

from dataclasses import dataclass, field

WEB_TOP_10_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

LLM_TOP_10_2026 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Excessive Agency",
    "LLM04": "Supply Chain",
    "LLM05": "Data and Model Poisoning",
    "LLM06": "Unbounded Consumption",
    "LLM07": "Misinformation",
    "LLM08": "Hidden Context Exposure",
    "LLM09": "Vector and Embedding Weaknesses",
    "LLM10": "Improper Output Handling",
}

AGENTIC_TOP_10_2026 = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

_CATALOGUES = {**WEB_TOP_10_2021, **LLM_TOP_10_2026, **AGENTIC_TOP_10_2026}
SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def owasp_name(owasp_id: str) -> str:
    return _CATALOGUES.get(owasp_id, "Unknown category")


@dataclass
class Finding:
    title: str
    severity: str
    owasp_id: str
    evidence: str
    remediation: str
    confidence: float = 0.5
    target: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if self.owasp_id not in _CATALOGUES:
            raise ValueError(f"unknown OWASP id {self.owasp_id!r}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0,1]")


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEV_ORDER[f.severity], -f.confidence))


def render_markdown(findings: list[Finding], *, engagement: str,
                    target: str, generated: str) -> str:
    findings = sort_findings(findings)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    out: list[str] = []
    out.append(f"# Puca report — {engagement}")
    out.append("")
    out.append(f"- **Target:** {target}")
    out.append(f"- **Generated:** {generated}")
    out.append(f"- **Findings:** {len(findings)}  "
               + "  ".join(f"{s}={counts[s]}" for s in SEVERITIES if counts[s]))
    out.append("")
    if not findings:
        out.append("_No findings recorded._")
        return "\n".join(out) + "\n"
    out.append("| # | Severity | OWASP | Finding | Confidence |")
    out.append("|---|----------|-------|---------|------------|")
    for i, f in enumerate(findings, 1):
        out.append(f"| {i} | {f.severity} | {f.owasp_id} "
                   f"{owasp_name(f.owasp_id)} | {f.title} | {f.confidence:.2f} |")
    out.append("")
    for i, f in enumerate(findings, 1):
        out.append(f"## {i}. {f.title}")
        out.append("")
        out.append(f"- **Severity:** {f.severity}")
        out.append(f"- **OWASP:** {f.owasp_id} — {owasp_name(f.owasp_id)}")
        out.append(f"- **Confidence:** {f.confidence:.2f}")
        if f.target:
            out.append(f"- **Target:** {f.target}")
        out.append("")
        out.append(f"**Evidence**\n\n{f.evidence}")
        out.append("")
        out.append(f"**Remediation**\n\n{f.remediation}")
        out.append("")
    return "\n".join(out) + "\n"
