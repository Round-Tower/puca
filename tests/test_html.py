from puca.report.owasp import Finding
from puca.report.html import render_html


def _f():
    return [
        Finding("Mass assignment self-grant premium", "critical", "A08",
                "PATCH /api/settings/<id>/ writes membership fields", "Allowlist fields",
                confidence=0.9, target="staging.example.com"),
        Finding("Permissions-Policy missing", "low", "A05", "no header", "add header",
                confidence=0.7),
    ]


def test_standalone_and_themed():
    h = render_html(_f(), engagement="dyslexia staging", target="staging.example.com",
                    generated="2026-09-10", positives=["TLS solid"], method="scope-gated",
                    tickets=["#841"])
    assert h.startswith("<!doctype html>")
    assert 'lang="en"' in h                              # language set
    assert "prefers-color-scheme: dark" in h             # theme-aware
    assert "Mass assignment self-grant premium" in h
    assert "A08" in h
    assert "TLS solid" in h and "#841" in h


def test_accessibility_features():
    h = render_html(_f(), engagement="e", target="t", generated="g")
    assert 'class="skip"' in h and 'href="#main"' in h   # skip link
    assert 'id="main"' in h                              # landmark target
    assert "<article" in h and "aria-labelledby" in h    # semantic findings
    assert "aria-label" in h                             # labelled nav/tally
    assert "prefers-reduced-motion" in h                 # motion respected
    # severity is conveyed as a WORD, not colour alone
    assert "critical" in h and "low" in h


def test_severity_triple_encoded():
    h = render_html(_f(), engagement="e", target="t", generated="g")
    assert 'class="pill"' in h        # word pill
    assert 'class="dot"' in h         # shape
    assert "--c:#a11235" in h         # critical hue on the rule/dot/pill


def test_escapes_content():
    h = render_html([Finding("<script>x</script>", "low", "A05", "e&e", "r",
                             confidence=0.5)],
                    engagement="e", target="t", generated="g")
    assert "<script>x</script>" not in h
    assert "&lt;script&gt;" in h


def test_empty_findings():
    h = render_html([], engagement="e", target="t", generated="g")
    assert h.startswith("<!doctype html>")
    assert "findings" in h            # empty tally reads "0 findings"


def test_murphysig_footer():
    h = render_html([Finding("x", "low", "A05", "e", "r", confidence=0.5)],
                    engagement="e", target="t", generated="g",
                    signature="kevin + claude-opus-4-8, 2026-09-10, confidence 0.85 — test")
    assert "MurphySig" in h                       # visible provenance
    assert "murphysig.dev" in h
    assert "<!-- Signed:" in h                     # machine-readable
    # no signature -> no MurphySig block
    assert "MurphySig" not in render_html([], engagement="e", target="t", generated="g")
