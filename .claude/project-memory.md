# Project Memory — Púca

Durable context for AI-assisted work on Púca, Round Tower's open-source
OWASP-mapped white-hat security testing kit. Managed by /debrief.

**Engagement detail is kept out of this file by design.** Púca's one-rule is that
the public repo carries NO engagement data — real targets, findings, tickets and
test accounts. Session-by-session engagement memory lives in
`.claude/project-memory.private.md` (gitignored). What stays here is the durable
*tool*-development context: architecture, methodology, and the gotchas worth not
re-discovering. When you /debrief, put engagement specifics in the private file.

---

## Architecture (the safety model)

- **Fail-closed scope gate is the whole safety model.** Every dynamic call asserts
  the target is authorized in `scope.yaml` (exact host + window + `authorization:
  true`) or raises. Building a module never fires it.
- **One egress point.** All network traffic goes through `puca/http.py` `Sender`
  (scope-gated + rate-limited). No module reaches the network any other way — the
  MCP arm was deliberately routed through it too.
- **Repo carries NO engagement data.** `scope.yaml`, `scope.*.yaml`, `reports/`,
  `.env`, secrets are gitignored self-contained (not relying on a global ignore).
  Real targets/findings live in each product's private tracker; session memory
  in the private file above.
- **Method:** confirm findings by READING the code first (check-the-premise), then
  an adversarial multi-agent verify pass to refute before reporting. Reports render
  via `puca/report/{owasp.py,html.py}` — accessible (dyslexia-first audience:
  severity encoded three ways — word + colour + rule, not colour alone; redundant
  ordinal numbering dropped), theme-aware, MurphySig-signed.

## Build gotchas (tool development — not engagement data)

- **Editable install:** `pyproject` needs `[tool.setuptools.packages.find]
  include=["puca*"]` or setuptools trips on the top-level `docker/` dir.
- **README ASCII-art centering:** GitHub won't center a ```` ``` ```` code fence
  (even inside `<div align="center">`). Use `<pre>` with every line padded to equal
  display width — but the pre-commit trailing-whitespace cleaner strips space
  padding, and NBSP too (Python counts U+00A0 as whitespace). Pad the right edge
  with **U+2800 (braille blank)**: renders empty, `isspace()` is false, survives the
  hook. Verify in a live GitHub preview, not just source (line-height only shows
  there).
- **Pre-commit MurphySig Review gate:** blocks edits to a signed file that add no
  `Review:` entry, and the anchor text must match the signed block EXACTLY — a
  leading-space mismatch fails silently as "review added: False". Fix the anchor;
  don't reach for SIG_SKIP.
- **MCP description scanner — substrings lie.** The first pass used substring
  markers and produced false positives (`"retrieval"` matched `eval`; a local doc
  `fetch` looked like egress) while MISSING real capabilities (microphone,
  memory-write). Reworked to a word-boundary capability taxonomy (`CAPABILITIES` +
  `_has_word`, adds `microphone-capture` + ASI06 persistent-memory-write). If you
  extend it, add words to the taxonomy, not more substrings.
- **Bound block edits tightly.** A `str.replace` from an early anchor to
  end-of-function once swallowed neighbouring defs between the anchors. Replace the
  smallest unique span, not "from here to the end".

## Modules

`webhook/` (signing/forge/replay), `ssrf/imds.py` (cloud metadata), `timing/`,
`mcp/probe.py` (gated `run()` + capability scanner), `access/idor.py`
(cross-account fuzzer), `sca/audit.py` (pip-audit + npm audit), `llm/probes.py`
(LLM01/02/06). Report catalogues: WEB_TOP_10_2021, LLM_TOP_10_2026,
AGENTIC_TOP_10_2026 / ASI01-10. Roadmap deferred: mass-assignment prober (#2),
full agentic ASI01-10 battery (#5). Kali box in `docker/` (macOS VM networking
caveat in README).
