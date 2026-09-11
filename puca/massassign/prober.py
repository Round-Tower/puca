"""Mass-assignment prober (A08 — Software and Data Integrity Failures).

A writable endpoint that binds a serializer with `fields='__all__'` (or a broad
allowlist) lets a client set fields it should never control — membership,
staff/admin flags, ownership FKs, billing ids. The classic edtech critical is
`PATCH /api/settings/<own_id>/ {"membership_identifier":"lifetime"}` self-granting
premium.

This module builds the probes and classifies the responses. Sending is done by
puca.http.Sender (scope-gated + rate-limited); a live run writes to the tester's
OWN object only.

SAFETY: probes carry a NON-ESCALATING sentinel value (`puca-probe:<field>`), never
a privilege-granting value like "lifetime" or `true`. If the sentinel persists,
the field is client-writable (the vulnerability) — but nobody was actually granted
premium or made staff. Detection without escalation, matching Puca's benign-payload
rule.

Signed: Kev + claude-opus-4-8, 2026-09-11, Confidence 0.75, Prior: Unknown
  Companion to puca.access.idor: idor is the cross-account READ (A01); this is the
  privileged-field WRITE (A08). Would have caught the engagement's self-grant
  critical. Pure logic + a gated run(); no test touches the network.
Review: Kev + claude-opus-4-8, 2026-09-11 — code-quality-reviewer pass. Fixes:
  classify() now OR's the PATCH echo with the confirm-GET (was override-only — a
  false negative when write/read serializers differ); field-name detection in
  classify() is word-boundary matched (_names_field), not substring; run() wraps
  each probe in try/except -> "other" + records errors, and skips the confirm-GET
  on non-2xx; writable-error findings get accurate evidence phrasing (no false
  "was accepted"); taxonomy folds plurals (roles/permissions) and drops the
  over-broad bare "admin" marker. Confidence now 0.8.
"""
from __future__ import annotations

import re as _re
from dataclasses import dataclass, field as _field
from typing import Any

from ..report.owasp import SEVERITIES, Finding

# Privileged-field taxonomy. "strong" markers are distinctive privilege words
# matched on snake_case token boundaries (so "user_role" hits "role" but
# "payroll" does not). "fk" markers are ownership references matched only in
# FK shape (exact, `<m>`, `<m>_id`, `..._<m>`, `..._<m>_id`) so an unrelated
# field like "user_interests" is NOT flagged for the token "user".
_STRONG: tuple[tuple[str, str], ...] = (
    ("membership", "critical"), ("entitlement", "critical"), ("premium", "critical"),
    ("subscription", "critical"), ("is_staff", "critical"), ("is_superuser", "critical"),
    ("superuser", "critical"), ("is_admin", "critical"),
    ("role", "critical"),
    ("stripe", "high"), ("expires", "high"), ("expiry", "high"), ("verified", "high"),
    ("credit", "high"), ("balance", "high"), ("permission", "high"),
    ("plan", "high"), ("tier", "high"),
)
_FK: tuple[tuple[str, str], ...] = (
    ("user", "high"), ("owner", "high"), ("account", "high"), ("tenant", "high"),
)

_SENTINEL = "puca-probe"
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = critical (worst)

_READONLY_MARKERS = ("read only", "read-only", "readonly", "cannot be set",
                     "not allowed", "may not", "immutable", "not editable")
_TYPE_MARKERS = ("valid", "must be", "invalid", "expected", "not a valid",
                 "incorrect type", "a number", "a boolean", "a date", "datetime")


@dataclass
class WritableEndpoint:
    url: str                # full, scope-authorized URL of the tester's OWN object
    method: str = "PATCH"


@dataclass
class Probe:
    field: str
    value: Any
    payload: dict
    severity: str
    label: str


@dataclass
class ScanResult:
    endpoint: WritableEndpoint
    results: list[tuple[str, str]] = _field(default_factory=list)   # (field, verdict)
    findings: list[Finding] = _field(default_factory=list)
    errors: list[tuple[str, str]] = _field(default_factory=list)    # (field, error repr)


def _tokens(name: str) -> list[str]:
    return [t for t in _re.split(r"[^a-z0-9]+", name.lower()) if t]


def _singular(tok: str) -> str:
    # light plural fold so 'roles'/'permissions'/'balances' match their markers
    return tok[:-1] if len(tok) > 3 and tok.endswith("s") else tok


def _strong_match(name: str, marker: str) -> bool:
    toks = [_singular(t) for t in _tokens(name)]
    mt = [_singular(t) for t in marker.split("_")]
    return any(toks[i:i + len(mt)] == mt for i in range(len(toks) - len(mt) + 1))


def _fk_match(name: str, marker: str) -> bool:
    n = name.lower()
    return n in (marker, f"{marker}_id") or n.endswith(f"_{marker}") or n.endswith(f"_{marker}_id")


def _worst(a: str | None, b: str) -> str:
    if a is None:
        return b
    return a if _SEV_RANK[a] <= _SEV_RANK[b] else b


def privileged_candidates(field_names: list[str]) -> list[tuple[str, str]]:
    """Filter serializer/OpenAPI field names to the privileged ones worth probing.

    Returns [(field, severity)] in input order, deduped, worst severity per field.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name in field_names:
        sev: str | None = None
        for marker, s in _STRONG:
            if _strong_match(name, marker):
                sev = _worst(sev, s)
        for marker, s in _FK:
            if _fk_match(name, marker):
                sev = _worst(sev, s)
        if sev is not None and name not in seen:
            out.append((name, sev))
            seen.add(name)
    return out


def severity_for(field: str) -> str:
    cands = dict(privileged_candidates([field]))
    return cands.get(field, "high")


def probe_value_for(field: str, token: str = _SENTINEL) -> str:
    """A unique, detectable, NON-escalating sentinel for `field`.

    A plain string for every field: if a loose CharField persists it we see it
    (accepted); if a typed field (bool/int/date) is writable, the wrong type
    triggers a field-named validation error (writable-error). Either way the
    field's writability is proven without ever sending "lifetime"/true.
    """
    return f"{token}:{field}"


def build_probes(field_names: list[str], token: str = _SENTINEL) -> list[Probe]:
    probes: list[Probe] = []
    for name, sev in privileged_candidates(field_names):
        value = probe_value_for(name, token)
        probes.append(Probe(field=name, value=value, payload={name: value},
                            severity=sev, label=f"massassign:{name}"))
    return probes


def _persisted(value: Any, body: str) -> bool:
    return str(value).lower() in (body or "").lower()


def _has_any(body: str, markers: tuple[str, ...]) -> bool:
    b = (body or "").lower()
    return any(m in b for m in markers)


def _names_field(body: str, field: str) -> bool:
    """True if `body` references `field` as a whole token (not a substring).

    Word-boundary matched (underscore counts as a boundary char) so a probed
    field 'role' is not considered "named" by an unrelated 'roles' in the body.
    """
    return _re.search(rf"(?<![a-z0-9_]){_re.escape(field.lower())}(?![a-z0-9_])",
                      (body or "").lower()) is not None


def classify(field: str, value: Any, status: int, body: str,
             confirm_body: str | None = None) -> str:
    """Classify one mass-assignment probe.

    accepted       : 2xx and the sentinel persisted (echoed, or confirmed by GET)
                     -> the field is client-writable. THE VULNERABILITY.
    writable-error : 4xx whose validation error NAMES the field with a type
                     complaint -> the serializer treats it as writable (our
                     sentinel's type was just wrong). Still an exposure.
    rejected       : 4xx that read-only-refuses it, or doesn't recognise it.
    ignored        : 2xx but the sentinel did not persist -> dropped/read-only.
    other          : anything else (5xx, redirects).
    """
    if 200 <= status < 300:
        # OR semantics: the write is proven if the PATCH echoed the sentinel OR a
        # confirm-GET shows it. A common DRF split (write serializer != read
        # serializer) means the echo can prove persistence even when the GET's
        # read view omits the field — checking only the GET would miss the vuln.
        if _persisted(value, body) or (confirm_body is not None and _persisted(value, confirm_body)):
            return "accepted"
        return "ignored"
    if 400 <= status < 500:
        named = _names_field(body, field)
        if named and _has_any(body, _READONLY_MARKERS):
            return "rejected"
        if named and _has_any(body, _TYPE_MARKERS):
            return "writable-error"
        return "rejected"
    return "other"


def finding_for_accepted(field: str, location: str, value: Any, *,
                         severity: str | None = None, confidence: float = 0.9,
                         target: str = "", kind: str = "accepted", note: str = "") -> Finding:
    sev = severity or severity_for(field)
    extra = f" {note}." if note else ""
    if kind == "writable-error":
        lead = (f"A PATCH to {location} setting {field!r} returned a validation error that names "
                f"the field by type — the serializer binds it as writable (our non-escalating "
                f"sentinel's type was rejected, but a correctly-typed value would be accepted).")
    else:
        lead = (f"A PATCH to {location} with {{{field!r}: <sentinel>}} was accepted — the field is "
                f"bound as writable by the serializer.")
    return Finding(
        title=f"Mass assignment: client can set privileged field {field!r}",
        severity=sev, owasp_id="A08",
        evidence=(f"{lead} A client can thus set a value it must not control (e.g. entitlement, "
                  f"staff, or ownership).{extra} Probed with a non-escalating sentinel "
                  f"({value!r}); no privilege was actually granted."),
        remediation=("Restrict writable fields to an explicit preferences allowlist, or mark the "
                     "privileged fields read_only=True on the serializer. Never bind "
                     "fields='__all__' on a client-writable endpoint. Add a regression test."),
        confidence=confidence, target=target)


def run(sender, endpoint: WritableEndpoint, field_names: list[str],
        headers: dict[str, str], *, confirm: bool = True, token: str = _SENTINEL) -> ScanResult:
    """Probe an authorized writable endpoint for mass assignment, through the gated Sender.

    Writes ONLY to `endpoint.url` (the tester's own object) with non-escalating
    sentinels; optionally re-GETs to confirm persistence. State-changing by
    nature (it PATCHes), so it only fires against a scope-authorized target.
    """
    import json

    result = ScanResult(endpoint=endpoint)
    base = {**headers, "Content-Type": "application/json"}  # JSON body; overrides client Content-Type
    for probe in build_probes(field_names, token):
        try:
            resp = sender.send(endpoint.method, endpoint.url, headers=base,
                               body=json.dumps(probe.payload))
            confirm_body = None
            if confirm and 200 <= resp.status < 300:  # a GET only helps confirm a 2xx write
                confirm_body = sender.send("GET", endpoint.url, headers=headers).body
            verdict = classify(probe.field, probe.value, resp.status, resp.body, confirm_body)
        except Exception as exc:  # one transient error must not sink the whole scan
            result.results.append((probe.field, "other"))
            result.errors.append((probe.field, repr(exc)))
            continue
        result.results.append((probe.field, verdict))
        if verdict == "accepted":
            result.findings.append(finding_for_accepted(
                probe.field, endpoint.url, probe.value,
                severity=probe.severity, confidence=0.9, target=endpoint.url))
        elif verdict == "writable-error":
            result.findings.append(finding_for_accepted(
                probe.field, endpoint.url, probe.value,
                severity=probe.severity, confidence=0.6, target=endpoint.url,
                kind="writable-error", note="a correctly-typed value would be accepted"))
    return result
