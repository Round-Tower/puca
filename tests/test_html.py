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


def test_html_is_standalone_and_themed():
    h = render_html(_f(), engagement="dyslexia staging", target="staging.example.com",
                    generated="2026-09-10", positives=["TLS solid"], method="scope-gated",
                    tickets=["#841"])
    assert h.startswith("<!doctype html>")
    assert "prefers-color-scheme: dark" in h        # theme-aware
    assert "Mass assignment self-grant premium" in h
    assert "critical" in h and "A08" in h
    assert "TLS solid" in h and "#841" in h


def test_html_escapes_content():
    h = render_html([Finding("<script>x</script>", "low", "A05", "e&e", "r",
                             confidence=0.5)],
                    engagement="e", target="t", generated="g")
    assert "<script>x</script>" not in h            # escaped
    assert "&lt;script&gt;" in h


def test_html_empty_findings():
    h = render_html([], engagement="e", target="t", generated="g")
    assert "no findings" in h and h.startswith("<!doctype html>")
