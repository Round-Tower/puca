<div align="center">
<pre>
  ██        ██⠀⠀
  ██        ██⠀⠀
 ▄████████████▄⠀
████████████████
████████████████
███  ████   ███⠀
███  ████   ███⠀
████████████████
████████████████
████████████████
████████████████
███ ██ ██ ██ ███
█▀  ▀█ ▀█ █▀  ▀█
 ▘   ▘  ▘   ▘  ▘
</pre>

# Púca

**A white-hat security kit that meets your systems on the road and tests them.**

[![License: MIT](https://img.shields.io/badge/license-MIT-black.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-63%20passing-brightgreen.svg)](tests/)
[![OWASP](https://img.shields.io/badge/OWASP-Web%20%2B%20LLM%20%2B%20Agentic-5b2a86.svg)](#what-púca-tests)
[![Scope](https://img.shields.io/badge/no%20scope-no%20fire-red.svg)](#the-one-rule)

*Built by [Round Tower](https://round-tower.ie).*

</div>

---

> In Irish folklore the **púca** is a shapeshifter that waits on the road and
> tests the travellers it meets. This one does the same to your systems — probing
> for the weak spot so you can shore it up before someone less friendly finds it.

Púca is a reusable security testing kit for **web, API, and agentic / MCP**
systems. Every finding it raises is mapped to the relevant OWASP catalogue and
rendered into a report a human can actually read.

## The one rule

**No scope, no fire.** 🔴

Every dynamic test refuses to run unless `scope.yaml` explicitly authorizes the
exact target — authorization flag set, host in scope, inside the time window.
Building the kit is never the same as pointing it at a host. The gate fails
**closed**: silence means *no*.

```yaml
# scope.yaml — the gate. Absent or false → nothing fires.
authorization: true
targets:
  - host: staging.example.com
    window: { from: 2026-09-10, to: 2026-09-17 }
```

Authorized-target testing only. Follow the Azure and Google Cloud
penetration-testing Rules of Engagement: never DoS, never touch assets you do
not own. See [`SECURITY.md`](SECURITY.md).

## Two halves

**🧰 A portable toolbox** — a disposable Kali container (`docker/`) plus a small,
tested Python harness (`puca/`) for the attacks that still pay off on modern
apps: webhook signature forgery, replay, SSRF (including cloud metadata), timing
side-channels, cross-account access (IDOR), dependency audit, and MCP
tool-server probing.

**📋 A report engine** — findings mapped to the OWASP Web/API Top 10, the **LLM
Top 10 (2026)** and the **Agentic Applications Top 10 (ASI01–ASI10)**, rendered
to an accessible, MurphySig-signed HTML page (or Markdown). Drive the whole thing
from the `puca` Claude Code skill.

## Quick start

```bash
# 1. Author your engagement (this is the safety gate — fill it in honestly)
cp scope.example.yaml scope.yaml && $EDITOR scope.yaml

# 2. Local harness — no Kali needed for webhook / MCP / report work
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                               # 63 green

# 3. Full Kali toolbox when you want the network / fuzzing arsenal
docker compose -f docker/compose.yaml run --rm puca
```

## What Púca tests

| Module         | Attack                                             | OWASP mapping             |
|----------------|----------------------------------------------------|---------------------------|
| `puca.webhook` | Signature forgery, tamper, replay                  | A01 / A08 · API2 / API8   |
| `puca.ssrf`    | SSRF → Azure IMDS / GCP metadata                   | A10 (SSRF)                |
| `puca.timing`  | Non-constant-time signature compare                | A02 (Crypto failures)     |
| `puca.access`  | Cross-account (IDOR / BOLA) detection              | A01 (Broken access)       |
| `puca.mcp`     | Tool enumeration, prompt-injection in tool         | LLM01 · ASI02 / ASI06 /   |
|                | descriptions, excessive agency                     | ASI09                     |
| `puca.sca`     | Dependency vulnerability audit (pip / npm)         | A06 (Vuln components)     |
| `puca.llm`     | Prompt injection · secret leak · unbounded use     | LLM01 · LLM02 · LLM06     |
| `puca.report`  | OWASP-mapped, accessible findings report           | —                         |

Every network call funnels through one scope-gated, rate-limited `Sender`
(`puca/http.py`) — the single point of egress, so the gate can't be sidestepped.

## Contributing

Coding agents and humans both welcome. Read [`AGENTS.md`](AGENTS.md) first — it's
short, and the first rule is the one above. TDD is the house style; findings from
real engagements never land in this repo.

## Status

Early, and earning its keep. First engagement: `staging.example.com`. The MCP
and agentic modules are aimed at [M1K3](https://round-tower.ie) next. Roadmap in
[`ROADMAP.md`](ROADMAP.md).

<div align="center">
<sub>The púca tests you so a stranger doesn't. 🐴👻</sub>
</div>
