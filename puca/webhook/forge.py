"""Build forged webhook request variants to test whether an endpoint verifies.

A `Request` is a plain, inert description of an HTTP request. Nothing is sent
here — puca.http does the sending, and only after the scope gate passes.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.75, Prior: Unknown
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import signing


@dataclass
class Request:
    url: str
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    label: str = ""


def _base(url: str, body: str, headers: dict[str, str] | None) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    return h


def unsigned(url: str, body: str, headers: dict[str, str] | None = None) -> Request:
    """No signature header at all — does the endpoint accept it?"""
    return Request(url=url, headers=_base(url, body, headers), body=body,
                   label="forge:unsigned")


def wrong_signature(url: str, body: str, sig_header: str,
                    headers: dict[str, str] | None = None) -> Request:
    """A syntactically valid but bogus signature."""
    h = _base(url, body, headers)
    h[sig_header] = "sha256=" + "0" * 64
    return Request(url=url, headers=h, body=body, label="forge:wrong-signature")


def tampered_body(url: str, original_body: str, sig_header: str,
                  signature: str, injected: str,
                  headers: dict[str, str] | None = None) -> Request:
    """Keep a captured signature but change the body — tests body binding."""
    h = _base(url, injected, headers)
    h[sig_header] = signature
    return Request(url=url, headers=h, body=injected,
                   label="forge:tampered-body")


def valid_if_secret_known(url: str, body: str, sig_header: str, scheme: str,
                          secret: str, headers: dict[str, str] | None = None) -> Request:
    """Lab-only: a genuinely valid signature, to confirm the round trip."""
    h = _base(url, body, headers)
    h[sig_header] = signing.compute(scheme, secret, body)
    return Request(url=url, headers=h, body=body, label="forge:valid")
