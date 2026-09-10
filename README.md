# Púca

> *In Irish folklore the púca is a shapeshifter that meets travellers on the road
> and tests them. Puca tests your systems the same way — probing for weakness so
> you can shore it up before someone less friendly does.*

**Puca** is a reusable, white-hat security testing kit for web, API, and
**agentic / MCP** systems, with every finding mapped to the relevant OWASP
catalogue. Built by [Round Tower](https://round-tower.ie).

## Two halves

1. **A portable toolbox** — a disposable Kali container (`docker/`) plus a small,
   tested Python harness (`puca/`) for the attacks that pay off on modern apps:
   webhook signature forgery, replay, SSRF (incl. cloud metadata), timing
   side-channels, and MCP tool-server probing.
2. **A report engine** — findings mapped to OWASP Web/API Top 10, the
   **LLM Top 10 (2026)** and the **Agentic Applications Top 10 (ASI01–ASI10)**,
   rendered to Markdown. Drive it from the `puca` Claude Code skill.

## The one rule

**No scope, no fire.** Every dynamic test refuses to run unless `scope.yaml`
explicitly authorizes the exact target (`authorization: true`, host in scope,
inside the window). Building the kit is not the same as pointing it at a host.
See `scope.example.yaml`.

Authorized-target testing only. Follow the Microsoft Azure and Google Cloud
penetration-testing Rules of Engagement: never DoS, never touch assets you do
not own.

## Quick start

```bash
# 1. Author your engagement
cp scope.example.yaml scope.yaml && $EDITOR scope.yaml

# 2. Local harness (no Kali needed for webhook/MCP work)
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest

# 3. Full Kali toolbox when you want the network/fuzzing arsenal
docker compose -f docker/compose.yaml run --rm puca
```

## What Puca tests

| Module            | Attack                                   | OWASP mapping            |
|-------------------|------------------------------------------|--------------------------|
| `puca.webhook`    | Signature forgery, tamper, replay        | A01/A08, API2/API8       |
| `puca.ssrf`       | SSRF → Azure IMDS / GCP metadata         | A10 (SSRF)               |
| `puca.timing`     | Non-constant-time signature compare      | A02 (Crypto failures)    |
| `puca.mcp`        | Tool enumeration, prompt-injection in    | LLM01, ASI02, ASI06,     |
|                   | tool descriptions, excessive agency      | ASI09                    |
| `puca.access`    | Cross-account (IDOR) read detection      | A01 (Broken Access)      |
| `puca.sca`        | Dependency vuln audit (pip/npm)          | A06 (Vuln Components)    |
| `puca.llm`        | Prompt injection / secret leak / DoS     | LLM01, LLM02, LLM06      |
| `puca.report`     | OWASP-mapped Markdown findings report    | —                        |

## Status

Early. First engagement: `staging.example.com`. MCP module aimed at M1K3 next.
