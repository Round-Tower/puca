"""Replay attacks: resend a captured event, age its timestamp, duplicate it.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.75, Prior: Unknown
"""
from __future__ import annotations

from dataclasses import replace

from .forge import Request
from . import signing


def replay(captured: Request) -> Request:
    """Resend a genuine captured request verbatim — tests nonce/replay defence."""
    return replace(captured, label="replay:verbatim")


def with_stale_timestamp(captured: Request, sig_header: str,
                         age_seconds: int, secret: str | None = None) -> Request:
    """Re-time a Stripe-style signature into the past.

    If `secret` is given the signature is recomputed (valid but old); otherwise
    only the visible `t=` is rewound, testing servers that read t= but never
    re-verify against it.
    """
    old_sig = captured.headers.get(sig_header, "")
    ts = signing.stripe_timestamp(old_sig)
    if ts is None:
        raise ValueError("captured request has no Stripe-style t= timestamp")
    new_ts = ts - age_seconds
    if secret is not None:
        new_sig = signing.compute("hmac_sha256_stripe", secret, captured.body,
                                   timestamp=new_ts)
    else:
        new_sig = ",".join(
            (f"t={new_ts}" if p.startswith("t=") else p)
            for p in old_sig.split(",")
        )
    h = dict(captured.headers)
    h[sig_header] = new_sig
    return replace(captured, headers=h, label=f"replay:stale-{age_seconds}s")


def duplicate_event(captured: Request, times: int = 2) -> list[Request]:
    """Fire the same event N times — tests idempotency (double-processing)."""
    return [replace(captured, label=f"replay:idempotency-{i+1}/{times}")
            for i in range(times)]
