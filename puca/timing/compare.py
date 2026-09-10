"""Detect non-constant-time comparisons via response-time statistics.

Pure statistics so it is testable with synthetic samples. Feed it two lists of
measured latencies (e.g. correct-prefix vs wrong-prefix guesses); it reports
whether the medians separate enough to suggest a timing leak.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.65, Prior: Unknown
Note: a real leak needs many samples and a quiet network. Treat a positive as a
lead to confirm, not proof.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass


@dataclass
class TimingVerdict:
    median_a: float
    median_b: float
    delta: float
    leak_suspected: bool
    note: str


def median(samples: list[float]) -> float:
    if not samples:
        raise ValueError("no samples")
    return statistics.median(samples)


def compare(samples_a: list[float], samples_b: list[float],
            rel_threshold: float = 0.10) -> TimingVerdict:
    """Suspect a leak when medians differ by more than rel_threshold (fraction)."""
    ma, mb = median(samples_a), median(samples_b)
    base = max(min(ma, mb), 1e-9)
    delta = abs(ma - mb) / base
    leak = delta >= rel_threshold
    note = (f"medians differ by {delta*100:.1f}% "
            f"(threshold {rel_threshold*100:.0f}%)")
    return TimingVerdict(ma, mb, delta, leak, note)
