"""Render findings as an accessible, readable, self-contained HTML report.

Accessibility- and readability-first (the primary reader is dyslexic):
- Single reading column, ~40rem line length, 1.72 line-height, left-aligned.
- Severity is TRIPLE-encoded — word + dot + left rule — never colour alone.
- Semantic landmarks, skip link, th[scope], heading hierarchy, focus-visible,
  print styles, prefers-reduced-motion, prefers-color-scheme, lang.
Design informed by the frontend-design skill; standalone file for private view.

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.75, Prior: Unknown
Review: Kev + claude-opus-4-8, 2026-09-10 — full redesign for accessibility +
  readability (was info-dense but poor for both). Severity now triple-encoded;
  semantic landmarks + skip link + scoped headers; readable type scale; the
  design is built into the renderer so every report inherits it. Confidence now 0.8.
"""
from __future__ import annotations

import html as _h
from string import Template

from .owasp import Finding, owasp_name, sort_findings, SEVERITIES

# Severity hue — used for dot + left rule + pill (always paired with the word).
_SEV = {"critical": "#a11235", "high": "#b4530a", "medium": "#8a6d1f",
        "low": "#3a6a8a", "info": "#5a5560"}


def _esc(s) -> str:
    return _h.escape(str(s if s is not None else ""))


def _slug(i: int) -> str:
    return f"f{i}"


def render_html(findings, *, engagement: str, target: str, generated: str,
                positives=None, method: str = "", tickets=None) -> str:
    findings = sort_findings(findings)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    pos = positives or []
    tix = tickets or []

    # Severity tally (the one bold, anchoring element) — honest counts, no gradient.
    tally = "".join(
        f'<li class="tally-item"><span class="tally-n" style="--c:{_SEV[s]}">{counts[s]}</span>'
        f'<span class="tally-label">{s}</span></li>'
        for s in SEVERITIES if counts[s]
    ) or '<li class="tally-item"><span class="tally-n">0</span>'\
         '<span class="tally-label">findings</span></li>'

    # Findings index (jump links) — a real ranked list, so numbering is meaningful.
    toc = "".join(
        f'<li><a href="#{_slug(i)}"><span class="dot" style="--c:{_SEV[f.severity]}" aria-hidden="true"></span>'
        f'<span class="sev-word">{f.severity}</span> {_esc(f.title)}</a></li>'
        for i, f in enumerate(findings, 1)
    )

    # Detailed articles.
    arts = "".join(
        f'<article id="{_slug(i)}" class="finding" style="--c:{_SEV[f.severity]}" '
        f'aria-labelledby="{_slug(i)}-h">'
        f'<h3 id="{_slug(i)}-h"><span class="pill" style="--c:{_SEV[f.severity]}">{f.severity}</span>'
        f'<span class="num">{i}.</span> {_esc(f.title)}</h3>'
        f'<p class="ref"><b>OWASP</b> {_esc(f.owasp_id)} &mdash; {_esc(owasp_name(f.owasp_id))}'
        f' &nbsp;<b>Confidence</b> {f.confidence:.2f}'
        f'{(" &nbsp;<b>Target</b> " + _esc(f.target)) if f.target else ""}</p>'
        f'<h4>Evidence</h4><p>{_esc(f.evidence)}</p>'
        f'<h4>How to fix it</h4><p>{_esc(f.remediation)}</p>'
        f'</article>'
        for i, f in enumerate(findings, 1)
    )

    positives_html = ("<section aria-labelledby='held-h'><h2 id='held-h'>What held up</h2>"
                      "<ul class='held'>" +
                      "".join(f"<li>{_esc(p)}</li>" for p in pos) + "</ul></section>") if pos else ""
    method_html = (f"<section aria-labelledby='method-h'><h2 id='method-h'>Method &amp; scope</h2>"
                   f"<p>{_esc(method)}</p></section>") if method else ""
    tix_html = ("<p class='tickets'><b>Tracked in</b> " +
                ", ".join(_esc(t) for t in tix) + "</p>") if tix else ""

    doc = Template("""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Púca report — $engagement</title>
<style>
  :root {
    --bg:#f7f5f2; --panel:#fffdfb; --fg:#232027; --muted:#5b5660;
    --line:#e2ddd6; --accent:#5c4b8c; --focus:#5c4b8c;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14131a; --panel:#1d1b24; --fg:#e8e5ee; --muted:#a49fb0;
      --line:#312e3a; --accent:#b9a6e6; --focus:#b9a6e6; }
  }
  * { box-sizing:border-box; }
  html { -webkit-text-size-adjust:100%; }
  body { margin:0; background:var(--bg); color:var(--fg);
    font:1.0625rem/1.72 "Segoe UI",system-ui,-apple-system,"Helvetica Neue",sans-serif;
    word-spacing:.02em; }
  .skip { position:absolute; left:-9999px; top:0; background:var(--accent); color:#fff;
    padding:10px 16px; border-radius:0 0 8px 0; z-index:10; }
  .skip:focus { left:0; }
  .wrap { max-width:44rem; margin:0 auto; padding:3rem 1.25rem 6rem; }
  header .title { font-size:2rem; line-height:1.15; margin:0 0 .3em; font-weight:700;
    letter-spacing:-.01em; }
  header .lede { color:var(--muted); font-size:1.05rem; margin:0; max-width:40rem; }
  header .lede b { color:var(--fg); font-weight:600; }
  .tally { list-style:none; display:flex; flex-wrap:wrap; gap:1.4rem 2rem; padding:1.4rem 0;
    margin:1.6rem 0; border-top:2px solid var(--line); border-bottom:2px solid var(--line); }
  .tally-item { display:flex; flex-direction:column; align-items:flex-start; }
  .tally-n { font-size:2.2rem; font-weight:700; line-height:1; color:var(--fg);
    border-bottom:4px solid var(--c,var(--line)); padding-bottom:.12em; }
  .tally-label { margin-top:.35em; color:var(--muted); font-size:.95rem; }
  .tickets { color:var(--muted); }
  h2 { font-size:1.4rem; margin:2.4rem 0 .8rem; font-weight:700; }
  nav.index h2 { margin-bottom:.4rem; }
  nav.index ol { padding-left:1.4rem; margin:0; }
  nav.index li { margin:.5em 0; }
  nav.index a { color:var(--fg); text-decoration:none; border-bottom:1px solid transparent; }
  nav.index a:hover { border-bottom-color:var(--accent); }
  .dot { display:inline-block; width:.62em; height:.62em; border-radius:50%;
    background:var(--c,var(--muted)); margin-right:.5em; vertical-align:baseline; }
  .sev-word { text-transform:capitalize; font-weight:600; }
  .finding { border-top:1px solid var(--line); border-left:5px solid var(--c,var(--line));
    padding:1.3rem 0 1.3rem 1.2rem; margin:1.4rem 0; }
  .finding h3 { font-size:1.2rem; line-height:1.3; margin:0 0 .5rem; font-weight:700;
    display:flex; flex-wrap:wrap; align-items:baseline; gap:.5em; }
  .finding .num { color:var(--muted); font-weight:600; }
  .pill { color:#fff; background:var(--c); padding:.12em .6em; border-radius:5px;
    font-size:.72rem; font-weight:700; text-transform:capitalize; letter-spacing:.02em; }
  .finding h4 { font-size:.82rem; color:var(--muted); margin:1.1em 0 .25em; font-weight:700; }
  .finding p { margin:.2em 0; max-width:40rem; }
  .ref { color:var(--muted); font-size:.95rem; }
  .ref b { color:var(--fg); }
  ul.held { list-style:none; padding:0; margin:0; }
  ul.held li { position:relative; padding-left:1.7em; margin:.55em 0; max-width:40rem; }
  ul.held li::before { content:"\\2713"; position:absolute; left:0; color:var(--accent);
    font-weight:700; }
  a { color:var(--accent); }
  :focus-visible { outline:3px solid var(--focus); outline-offset:2px; border-radius:3px; }
  footer { margin-top:3.5rem; border-top:1px solid var(--line); padding-top:1.2rem;
    color:var(--muted); font-size:.9rem; max-width:40rem; }
  @media (prefers-reduced-motion: no-preference) { a { transition:border-color .12s ease; } }
  @media print { body { background:#fff; color:#000; } .skip,nav.index { display:none; }
    .finding { break-inside:avoid; } }
</style></head>
<body>
<a class="skip" href="#main">Skip to findings</a>
<div class="wrap">
<header>
  <p class="title">Púca security report</p>
  <p class="lede">$engagement. Target <b>$target</b>. Assessed $generated.</p>
</header>
<ul class="tally" aria-label="Findings by severity">$tally</ul>
$tickets
<nav class="index" aria-label="Findings index"><h2>Findings</h2><ol>$toc</ol></nav>
<main id="main">
$arts
$positives
$method
</main>
<footer>Generated by Púca 0.1.0 — Round&nbsp;Tower. White-hat, scope-gated assessment.
This is a private report describing live systems; do not distribute.</footer>
</div>
</body></html>
""")
    return doc.substitute(
        engagement=_esc(engagement), target=_esc(target), generated=_esc(generated),
        tally=tally, tickets=tix_html, toc=toc, arts=arts,
        positives=positives_html, method=method_html,
    )
