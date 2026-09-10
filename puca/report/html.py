"""Render findings as a polished, self-contained, theme-aware HTML report.

Standalone file (full <!doctype html>) meant to be viewed privately, not hosted —
a security report naming live findings should not get a shareable URL by default.
Readable-first: system sans, generous spacing, high contrast (dyslexia-friendly).

Signed: Kev + claude-opus-4-8, 2026-09-10, Confidence 0.75, Prior: Unknown
"""
from __future__ import annotations

import html as _h

from .owasp import Finding, owasp_name, sort_findings, SEVERITIES

_SEV_COLOR = {
    "critical": "#b3123b", "high": "#d9480f", "medium": "#b8860b",
    "low": "#2b6cb0", "info": "#4a5568",
}


def _esc(s: str) -> str:
    return _h.escape(str(s or ""))


def render_html(findings: list[Finding], *, engagement: str, target: str,
                generated: str, positives: list[str] | None = None,
                method: str = "", tickets: list[str] | None = None) -> str:
    findings = sort_findings(findings)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    pos = positives or []
    tix = tickets or []

    chips = "".join(
        f'<span class="chip" style="--c:{_SEV_COLOR[s]}">{counts[s]} {s}</span>'
        for s in SEVERITIES if counts[s]
    )
    rows = "".join(
        f'<tr><td>{i}</td>'
        f'<td><span class="badge" style="--c:{_SEV_COLOR[f.severity]}">{f.severity}</span></td>'
        f'<td class="mono">{_esc(f.owasp_id)}</td>'
        f'<td>{_esc(f.title)}</td><td class="mono">{f.confidence:.2f}</td></tr>'
        for i, f in enumerate(findings, 1)
    )
    cards = "".join(
        f'<section class="card" style="--c:{_SEV_COLOR[f.severity]}">'
        f'<h3><span class="badge" style="--c:{_SEV_COLOR[f.severity]}">{f.severity}</span> '
        f'{i}. {_esc(f.title)}</h3>'
        f'<p class="meta"><b>OWASP</b> {_esc(f.owasp_id)} — {_esc(owasp_name(f.owasp_id))} · '
        f'<b>Confidence</b> {f.confidence:.2f}{(" · <b>Target</b> " + _esc(f.target)) if f.target else ""}</p>'
        f'<h4>Evidence</h4><p>{_esc(f.evidence)}</p>'
        f'<h4>Remediation</h4><p>{_esc(f.remediation)}</p></section>'
        for i, f in enumerate(findings, 1)
    )
    pos_html = ("<h2>What held up well</h2><ul class='held'>" +
                "".join(f"<li>{_esc(p)}</li>" for p in pos) + "</ul>") if pos else ""
    tix_html = ("<p class='tickets'>Tickets: " +
                " · ".join(_esc(t) for t in tix) + "</p>") if tix else ""
    method_html = f"<h2>Method &amp; scope</h2><p>{_esc(method)}</p>" if method else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Púca report — {_esc(engagement)}</title>
<style>
  :root {{ --bg:#faf9f7; --fg:#1a1a1a; --muted:#5a5a5a; --card:#fff; --line:#e6e3de; --accent:#6b4f8a; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#16151a; --fg:#ece9f0; --muted:#a29db0; --card:#201e28; --line:#332f3d; --accent:#b9a3d9; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
    letter-spacing:.01em; }}
  .wrap {{ max-width:860px; margin:0 auto; padding:40px 22px 80px; }}
  header h1 {{ font-size:1.7rem; margin:0 0 .2em; }}
  .sub {{ color:var(--muted); margin:0 0 1.4em; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:8px; margin:1em 0 1.6em; }}
  .chip {{ padding:5px 12px; border-radius:999px; font-weight:600; font-size:.85rem;
    color:#fff; background:var(--c); }}
  .badge {{ display:inline-block; padding:2px 9px; border-radius:6px; color:#fff;
    background:var(--c); font-size:.72rem; font-weight:700; text-transform:uppercase;
    letter-spacing:.05em; vertical-align:middle; }}
  table {{ width:100%; border-collapse:collapse; margin:0 0 2em; font-size:.94rem; }}
  th,td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.88rem; }}
  h2 {{ font-size:1.25rem; margin:1.8em 0 .6em; padding-bottom:.2em; border-bottom:2px solid var(--line); }}
  .card {{ background:var(--card); border:1px solid var(--line); border-left:5px solid var(--c);
    border-radius:10px; padding:16px 20px; margin:0 0 16px; }}
  .card h3 {{ margin:.1em 0 .5em; font-size:1.08rem; }}
  .card h4 {{ margin:1em 0 .3em; font-size:.8rem; text-transform:uppercase;
    letter-spacing:.05em; color:var(--muted); }}
  .card p {{ margin:.2em 0; }}
  .meta {{ color:var(--muted); font-size:.9rem; }}
  ul.held li {{ margin:.3em 0; }}
  .tickets {{ font-weight:600; }}
  footer {{ margin-top:3em; color:var(--muted); font-size:.82rem;
    border-top:1px solid var(--line); padding-top:1em; }}
</style></head>
<body><div class="wrap">
<header>
  <h1>Púca security report</h1>
  <p class="sub">{_esc(engagement)} · target <b>{_esc(target)}</b> · {_esc(generated)}</p>
</header>
<div class="chips">{chips or '<span class="chip" style="--c:#4a5568">no findings</span>'}</div>
{tix_html}
<h2>Findings</h2>
<table><thead><tr><th>#</th><th>Severity</th><th>OWASP</th><th>Finding</th><th>Conf.</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5>None recorded.</td></tr>'}</tbody></table>
{cards}
{pos_html}
{method_html}
<footer>Generated by Púca 0.1.0 · Round-Tower/puca · white-hat, scope-gated assessment.
Private report — findings describe live systems; do not distribute.</footer>
</div></body></html>
"""
