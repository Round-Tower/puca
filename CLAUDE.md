@.claude/project-memory.md

# Púca

Round Tower's open-source, OWASP-mapped white-hat security testing kit.
Named after the Irish folklore shapeshifter. MIT. Public: github.com/Round-Tower/puca.

## The one rule
Every dynamic test is gated on `scope.yaml` and fails closed — `puca.scope`
raises unless the exact target is authorized. Production systems are never in
scope; staging is the only ground. No engagement data (scope.yaml, reports/,
.env, secrets) is ever committed — the self-contained `.gitignore` enforces it.
Secrets/tokens are never printed.

## Shape
- `puca/` — package. `scope.py` (the gate), `http.py` (the ONLY network egress:
  scope-gated + rate-limited `Sender`), `cli.py`.
- Modules: `webhook/`, `ssrf/`, `timing/`, `mcp/`, `access/` (IDOR), `sca/`, `llm/`.
- `report/owasp.py` (Finding + OWASP catalogues) + `report/html.py`
  (accessible, MurphySig-signed report; built with the frontend-design skill).
- `docker/` — disposable Kali box.
- Skill lives at `~/.claude/skills/puca/`.

## Workflow
TDD (tests-first, in `tests/`; 63 green). MurphySig Review-on-Touch on signed
files. Findings from real engagements go to tickets, never into this repo.
