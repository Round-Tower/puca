# Púca battery — roadmap

The "battery" is Púca's set of test modules. Priority order set by Kev
(2026-09-10), scoped for an edtech app with schools + minors (COPPA-relevant).

## Shipped

| # | Module | What it does | OWASP |
|---|--------|--------------|-------|
| — | `puca.webhook` | Signature forgery, tamper, replay, idempotency | A08, API |
| — | `puca.ssrf` | SSRF probes → Azure IMDS / GCP metadata | A10 |
| — | `puca.timing` | Non-constant-time signature compare | A02 |
| — | `puca.mcp` | MCP tool enumeration, injection/excessive-agency scan | ASI02/03/05/06 |
| — | `puca.report` | OWASP-mapped Markdown report engine | — |
| 1 | `puca.access` | **Cross-account (IDOR) fuzzer** — two identities, cross-tenant read detection | A01 |
| 2 | `puca.massassign` | **Mass-assignment prober** — non-escalating sentinel probes on every privileged writable field (membership / staff / ownership FK) + persistence diff. Catches the self-grant-premium class without granting anything. | A08 |
| 3 | `puca.sca` | **Dependency audit** — pip-audit / npm audit → findings | A06 |
| 4 | `puca.llm` | **LLM-app suite** — prompt injection, secret disclosure, unbounded consumption | LLM01/02/06 |

## Planned (deferred, keep on the battery)

| # | Module | What it does | OWASP |
|---|--------|--------------|-------|
| 5 | `puca.mcp` (agentic suite) | **Full ASI01–10 battery for M1K3** — tool poisoning, memory poisoning, excessive agency, rogue-agent. Separate scoped engagement (127.0.0.1). | ASI01–10 |

## Live-run prerequisites
- **Mass-assignment (2):** one test-account token + your OWN object's URL + its
  serializer field names (OpenAPI dump or the DRF browsable API). Writes only to
  your own object, with non-escalating sentinels; state-changing, so staging only.
- **IDOR (1):** two authorized test-account tokens for the target (own + other).
- **SCA (3):** `pip-audit` and/or `npm` available (in the Kali box or a venv).
- **LLM (4):** an authorized LLM endpoint + a canary; run against staging only.
