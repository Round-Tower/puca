"""Parse pip-audit / npm audit output into OWASP A06 findings.

The parsers are pure and testable; run_* are thin subprocess wrappers.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.7, Prior: Unknown
"""
from __future__ import annotations

import json
import subprocess

from ..report.owasp import Finding

# npm severity -> puca severity
_NPM_SEV = {"info": "info", "low": "low", "moderate": "medium",
            "high": "high", "critical": "critical"}


def parse_pip_audit(data: str | dict) -> list[Finding]:
    """pip-audit --format json -> Findings. Handles both list and {dependencies:[]}."""
    obj = json.loads(data) if isinstance(data, str) else data
    deps = obj.get("dependencies", obj) if isinstance(obj, dict) else obj
    out: list[Finding] = []
    for dep in deps or []:
        name, version = dep.get("name", "?"), dep.get("version", "?")
        for v in dep.get("vulns", []) or []:
            vid = v.get("id", "?")
            fixes = v.get("fix_versions") or []
            # No fix available for a real advisory is worse.
            sev = "high" if not fixes else "medium"
            out.append(Finding(
                title=f"{name} {version}: {vid} ({'no fix' if not fixes else 'fix '+fixes[0]})",
                severity=sev, owasp_id="A06",
                evidence=(v.get("description") or "").strip()[:300] or f"{vid} affects {name} {version}",
                remediation=(f"Upgrade {name} to {fixes[0]}" if fixes
                             else f"No fix yet for {vid}; pin/monitor or remove {name}"),
                confidence=0.85))
    return out


def parse_npm_audit(data: str | dict) -> list[Finding]:
    """npm audit --json (npm v7+) -> Findings."""
    obj = json.loads(data) if isinstance(data, str) else data
    out: list[Finding] = []
    for name, info in (obj.get("vulnerabilities") or {}).items():
        sev = _NPM_SEV.get(str(info.get("severity", "medium")).lower(), "medium")
        via = info.get("via", [])
        titles = [x.get("title") for x in via if isinstance(x, dict) and x.get("title")]
        detail = titles[0] if titles else f"{name} has a known advisory"
        fix = info.get("fixAvailable")
        rem = ("Run `npm audit fix`" if fix is True else
               f"Upgrade to {fix.get('name')}@{fix.get('version')}" if isinstance(fix, dict)
               else "No safe automatic fix; review manually")
        out.append(Finding(
            title=f"{name}: {detail}", severity=sev, owasp_id="A06",
            evidence=f"npm audit: {name} severity={info.get('severity')} via={titles or via}",
            remediation=rem, confidence=0.85))
    return out


def run_pip_audit(project_dir: str) -> list[Finding]:  # pragma: no cover - I/O
    r = subprocess.run(["pip-audit", "--format", "json"], cwd=project_dir,
                       capture_output=True, text=True)
    return parse_pip_audit(r.stdout or "[]")


def run_npm_audit(project_dir: str) -> list[Finding]:  # pragma: no cover - I/O
    r = subprocess.run(["npm", "audit", "--json"], cwd=project_dir,
                       capture_output=True, text=True)
    return parse_npm_audit(r.stdout or "{}")
