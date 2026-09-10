import pytest
from puca.report import owasp


def test_finding_validates_severity_and_owasp():
    with pytest.raises(ValueError):
        owasp.Finding("t", "nope", "A01", "e", "r")
    with pytest.raises(ValueError):
        owasp.Finding("t", "high", "ZZ99", "e", "r")


def test_owasp_names_cover_all_three_catalogues():
    assert owasp.owasp_name("A10").startswith("Server-Side")
    assert owasp.owasp_name("LLM03") == "Excessive Agency"
    assert owasp.owasp_name("ASI02") == "Tool Misuse"


def test_sort_orders_by_severity_then_confidence():
    fs = [
        owasp.Finding("low1", "low", "A01", "e", "r", confidence=0.9),
        owasp.Finding("crit", "critical", "A10", "e", "r", confidence=0.5),
        owasp.Finding("high", "high", "A03", "e", "r", confidence=0.8),
    ]
    ordered = [f.title for f in owasp.sort_findings(fs)]
    assert ordered == ["crit", "high", "low1"]


def test_render_markdown_includes_title_and_findings():
    fs = [owasp.Finding("Unsigned webhook accepted", "critical", "A08",
                        "POST with no signature returned 200", "Verify HMAC",
                        confidence=0.9, target="https://staging.example.com/w")]
    md = owasp.render_markdown(fs, engagement="dyslexia staging",
                               target="staging.example.com", generated="2026-09-10")
    assert "# Puca report" in md
    assert "Unsigned webhook accepted" in md
    assert "A08" in md


def test_render_markdown_empty():
    md = owasp.render_markdown([], engagement="e", target="t", generated="g")
    assert "No findings recorded" in md
