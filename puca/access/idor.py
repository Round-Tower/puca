"""Cross-account (IDOR) access-control fuzzer.

Given two authenticated identities and resources each owns, request one
identity's resources AS the other and classify the result. The dangerous
outcome for an edtech app with schools/minors is a cross-tenant READ — one
account pulling another's data (COPPA-relevant).

Pure logic: request-matrix building + response classification. Sending is done
by puca.http.Sender (scope-gated); a live run needs two test-account tokens.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.7, Prior: Unknown
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..report.owasp import Finding


@dataclass
class Identity:
    name: str
    headers: dict[str, str] = field(default_factory=dict)  # auth token / cookie


@dataclass
class Resource:
    """A concrete object owned by `owner`, addressable at `path`.

    `owner_marker` is a string that appears in the resource body ONLY when the
    owner's real data is returned (e.g. the owner's email or a unique id) — the
    signal that a cross-account read actually leaked data rather than being
    filtered to the requester's own/empty view.
    """
    path: str
    owner: str          # Identity.name
    owner_marker: str
    method: str = "GET"


@dataclass
class Probe:
    requester: str
    resource: Resource
    label: str


def build_matrix(identities: list[Identity], resources: list[Resource]) -> list[Probe]:
    """Every (identity, resource-not-owned-by-it) pair — the cross-account tests."""
    probes: list[Probe] = []
    for ident in identities:
        for res in resources:
            if ident.name == res.owner:
                continue  # skip own resources; we test cross-account only
            probes.append(Probe(ident.name, res,
                                f"idor:{ident.name}->{res.owner}:{res.path}"))
    return probes


def classify(requester: str, resource: Resource, status: int, body: str) -> str:
    """Classify a cross-account access attempt.

    idor-leak    : 200 AND the owner's marker is in the body -> data leaked
    blocked      : 401/403/404 -> access control worked
    filtered-ok  : 200 but no owner marker -> returned requester's own/empty view
    other        : anything else, worth a look
    """
    if requester == resource.owner:
        return "own"
    if status in (401, 403, 404):
        return "blocked"
    if status == 200 and resource.owner_marker and resource.owner_marker in (body or ""):
        return "idor-leak"
    if status == 200:
        return "filtered-ok"
    return "other"


def finding_for_leak(requester: str, resource: Resource, target: str = "") -> Finding:
    return Finding(
        title=f"IDOR: {requester} can read {resource.owner}'s resource at {resource.path}",
        severity="high", owasp_id="A01",
        evidence=(f"Cross-account read: identity {requester!r} requested {resource.path} "
                  f"(owned by {resource.owner!r}) and received 200 with the owner's data "
                  f"(marker {resource.owner_marker!r} present in the response)."),
        remediation=("Scope the queryset/object lookup to the requesting identity and enforce "
                     "an object-level ownership check before returning the resource."),
        confidence=0.9, target=target)
