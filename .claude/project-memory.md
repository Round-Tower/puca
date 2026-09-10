# Project Memory — Púca

Durable context for AI-assisted work on Púca, Round Tower's open-source
OWASP-mapped white-hat security testing kit. Managed by /debrief.
Edit freely — the skill only appends new session blocks.

---

## Session — 2026-09-10 · Púca born (build + first engagement: example.com staging)

**Shipped:**
- **The repo**: `github.com/Round-Tower/puca` (MIT, public). Python package `puca/`
  with a fail-closed scope gate (`scope.py` — no dynamic test fires unless
  `scope.yaml` names the exact target), one network egress point (`http.py`
  `Sender`, scope-gated + rate-limited), and modules: `webhook/` (signing/forge/
  replay), `ssrf/imds.py` (Azure IMDS 169.254.169.254), `timing/compare.py`,
  `mcp/probe.py`, `access/idor.py` (cross-account fuzzer), `sca/audit.py`
  (pip-audit + npm audit), `llm/probes.py` (LLM01/02/06). 63 tests green.
- **Report engine**: `puca/report/owasp.py` (Finding + OWASP catalogues:
  WEB_TOP_10_2021, LLM_TOP_10_2026, AGENTIC_TOP_10_2026/ASI01-10) +
  `puca/report/html.py` (`render_html` — accessible, theme-aware, severity
  triple-encoded, MurphySig-signed footer, ~40rem measure).
- **The skill**: `~/.claude/skills/puca/SKILL.md` — composes security-auditor +
  /security-review, scope-gated, wires the report to render_html.
- **Kali box**: `docker/Dockerfile.kali` + `compose.yaml` (disposable, macOS VM
  networking caveat noted in README).
- **First engagement — example.com STAGING** (findings ticketed in
  Round-Tower/example-ai, NOT committed here): CRITICAL mass-assignment
  self-grant premium (#841); HIGH Wonde webhook fail-open (#841 / existing #636);
  HIGH TutorViewSet write-side IDOR (#844, 3/3 adversarial verifiers). MEDIUM ×2
  (client-side entitlement cap bypass; child name reaching Gemini). SCA clean.

**Decisions:**
- **Fail-closed scope gate is the whole safety model.** Every dynamic call
  asserts the target is authorized in scope.yaml or raises. Production
  (example.com) is deliberately NOT in scope — staging is the only ground.
- **Repo carries NO engagement data.** scope.yaml, reports/, .env, secrets are
  gitignored self-contained (not reliant on Kev's global ignore); verified
  `git ls-files` clean. Real targets/findings live in tickets, never in the OS repo.
- **Report went through frontend-design** for accessibility (dyslexia-first
  audience): dropped redundant ordinal numbering to cut cognitive load; severity
  encoded three ways (word + colour + rule) not colour alone.
- Findings confirmed by READING code (Kev's check-the-premise rule), then a
  65-agent adversarial workflow — which also REFUTED an ArtworkViewSet read-IDOR.

**Blockers / gotchas:**
- **The auto-mode classifier blocks, correctly, in a security session:** live
  exploitation JS (self-grant PATCH, IDOR reads), production active-probing
  (forged Wonde POST/PATCH), and at times `git push`. Pattern that works: stop
  retrying, do the read-only equivalent, hand Kev the PoC curl to run himself.
  Never worked around — respected every time.
- **Staging web signup `/accounts/signup/` 500s** — use the API instead:
  `POST /api/sign-up/` with nested `settings:{locale:-1}`. Created test users
  7654 (bob) + 7655 (alice); JWT Bearer auth. Delete them if not reused.
- **file:// nav rejected by the chrome extension** — serve locally
  (`python3 -m http.server`) then navigate, or `open -a "Google Chrome"`.
- **Pre-commit MurphySig Review gate** blocks edits to a signed file that add no
  `Review:` entry — the anchor text must match the signed block EXACTLY (a
  leading-space mismatch failed silently as "review added: False"). Not SIG_SKIP.
- Editable install needs `[tool.setuptools.packages.find] include=["puca*"]` or
  setuptools trips on the `docker/` top-level dir.
- **README ASCII art centering**: GitHub won't center a ``` code fence (even in
  `<div align="center">`) — use `<pre>` with every line padded to equal display
  width. But the pre-commit trailing-whitespace cleaner strips space padding, and
  NBSP too (Python counts U+00A0 as whitespace). Pad the right edge with **U+2800
  (braille blank)** — renders as an empty cell, `isspace()` is false, survives the
  hook. The hero art is a Rubin-reduced flat 16×15 púca (horns + two asymmetric
  negative-space eyes + frayed shadow tail); verify any change in a live GitHub
  preview, not just source (line-height only shows there).

**Next up:**
- Draft the TutorViewSet fix (#844) on a branch in example-ai (object-level
  IsOwner + get_queryset scoping; the serializer's writable user FK is the hole).
- Optional: Kev runs the provided curl PoCs against staging to prove the
  critical + IDOR live; delete the puca-bob/puca-alice staging accounts.
- ROADMAP deferred modules: mass-assignment prober (#2), full agentic ASI01-10
  suite for M1K3 (#5).

---
## Session — 2026-09-10 · MCP arm goes live (first real target: M1K3 itself)

**Shipped:**
- `puca/mcp/probe.py` `run(sender, url)` — enumerates `tools/list` **through**
  the scope-gated `Sender` (no route around `http.py`), flags
  `unauthenticated-enumeration`. Plus `McpScanResult`. `puca mcp <target>` CLI.
- Reworked `scan_tool_descriptions`: substring markers → **word-boundary
  capability taxonomy** (`CAPABILITIES` + `_has_word`). Kills the
  `"retrieval"`→`eval` false positive; adds `microphone-capture` + **ASI06
  persistent-memory-write** detection. 72 tests green, ruff clean. Commit `0406b85`, pushed.
- Local ticket `reports/TICKET-m1k3-mcp-2026-09-10.md` (gitignored). Assessment
  filed as **Round-Tower/M1K3#274**, cross-linked to remediation **#270**.

**Decisions:**
- **New engagement = new scope, don't co-mingle.** Preserved the dyslexia scope
  as `scope.dyslexia.yaml` (also gitignored via `scope.*.yaml`) and wrote a fresh
  single-host `scope.yaml` for `127.0.0.1`, so no dyslexia test can fire while on
  M1K3 work. Verified the gate refuses staging/prod/non-loopback.
- **Didn't duplicate #270.** It already existed and named listen/forget_memory/
  open_link. Filed #274 as the *assessment record* that backs it with evidence +
  the ASI06 `remember` angle #270's title omits.
- **Committed direct to master (repo pattern), pushed only when Kev said so.**

**Blockers / gotchas:**
- **M1K3's transport is well-defended — check before crying wolf.** Bound
  `127.0.0.1` only; `Host: evil` → `421`; valid-Host + foreign `Origin` → `403`;
  `OPTIONS` → `405` (no CORS). Remote + browser vectors are CLOSED. Residual is
  **local non-browser** callers (omit `Origin` → served all 18 tools). Severity
  Medium (local), not Critical. The first scan's severity would've been wrong
  without these read-only checks.
- **Naive substring scanning lies.** `"retrieval"` matched `eval`; local doc
  `fetch` looked like egress; the **mic and memory-write were missed entirely**.
  Word boundaries + a capability taxonomy are the fix. (Minor residual: a tool
  whose *description* says "counterpart to remember" double-tags — acceptable,
  deletion is a memory mutation.)
- **My own `run()` block-edit swallowed neighbouring defs.** A Python
  `str.replace` from an early anchor to end-of-function deleted
  `tools_list_request`/`parse_tools`/`ToolFinding` that sat between. Re-inserted.
  Lesson: bound block replacements tightly.

**Next up:**
- If Kev wants: promote the report through `puca.report.html`/`owasp.py` (the arm
  currently prints; the render engine exists and would give a signed HTML report).
- ROADMAP: full agentic ASI01–10 suite for M1K3 (#5) — this session did ASI02/03/
  05/06/07/08; the rest (tool-chaining, excessive autonomy, HITL bypass) are open.

---
