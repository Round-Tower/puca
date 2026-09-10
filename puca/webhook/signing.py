"""HMAC signature schemes for common webhook providers, plus safe-compare tests.

Pure logic — no network. Lets you (a) compute a *valid* signature when the
secret is known (to prove forgery end to end in a lab), and (b) build the
tampered/absent-signature variants you fire at an endpoint whose secret you do
NOT know, to check it actually verifies.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.75, Prior: Unknown
"""
from __future__ import annotations

import hashlib
import hmac
import time as _time

# scheme name -> how the signature string is built
SCHEMES = ("hmac_sha256_header", "hmac_sha256_stripe", "hmac_sha1_header")


def _as_bytes(v: str | bytes) -> bytes:
    return v if isinstance(v, bytes) else v.encode("utf-8")


def compute(scheme: str, secret: str | bytes, body: str | bytes,
            timestamp: int | None = None) -> str:
    """Return the signature string a correctly-signed request would carry."""
    key = _as_bytes(secret)
    payload = _as_bytes(body)
    if scheme == "hmac_sha256_header":
        return "sha256=" + hmac.new(key, payload, hashlib.sha256).hexdigest()
    if scheme == "hmac_sha1_header":
        return "sha1=" + hmac.new(key, payload, hashlib.sha1).hexdigest()
    if scheme == "hmac_sha256_stripe":
        ts = int(timestamp if timestamp is not None else _time.time())
        signed = _as_bytes(f"{ts}.") + payload
        v1 = hmac.new(key, signed, hashlib.sha256).hexdigest()
        return f"t={ts},v1={v1}"
    raise ValueError(f"unknown scheme {scheme!r}; known: {SCHEMES}")


def constant_time_equal(a: str | bytes, b: str | bytes) -> bool:
    """What a correct verifier should use (hmac.compare_digest)."""
    return hmac.compare_digest(_as_bytes(a), _as_bytes(b))


def stripe_timestamp(signature: str) -> int | None:
    """Pull the `t=` timestamp out of a Stripe-style signature."""
    for part in signature.split(","):
        if part.startswith("t="):
            try:
                return int(part[2:])
            except ValueError:
                return None
    return None
