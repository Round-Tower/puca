# Contributing to Púca

Welcome — coding agents and humans alike. This file is the contract. It's short
on purpose; read all of it before you touch anything.

```
   ▟██▙   You met the púca on the road.
   ▔██▔   Prove you belong here: read the one rule.
```

## 0. The one rule (non-negotiable)

**No scope, no fire.** Púca is offensive tooling. It only ever runs against a
target that `scope.yaml` explicitly authorizes, inside its window, with the
authorization flag set. This is enforced in code (`puca/scope.py`) and it fails
**closed**.

- Never weaken, bypass, or add a flag that skips the scope gate.
- Never route a network call around `puca/http.py` — the `Sender` there is the
  single, rate-limited point of egress by design. New network features extend it.
- Never commit a real `scope.yaml`, a real report, a captured token, or any
  engagement data. The `.gitignore` blocks the common paths; you are the backstop.
- Secrets and tokens are never printed, logged, or echoed. Presence checks only.

If a change would let Púca fire at something it can't today, that's a design
conversation in an issue first — not a PR.

## 1. Repo shape

| Path            | What lives there                                              |
|-----------------|--------------------------------------------------------------|
| `puca/`         | The package. One module per attack class; `report/` renders. |
| `puca/scope.py` | The gate. Treat as security-critical; changes get scrutiny.  |
| `puca/http.py`  | The only network egress (`Sender`). Scope-gated, rate-limited.|
| `tests/`        | Pytest suite. New behaviour arrives with its test.           |
| `docker/`       | Disposable Kali box + compose.                               |
| `scripts/`      | Dev helpers; not shipped as package API.                     |

## 2. House style

- **TDD, tests-first.** Write the failing test, then the code. The pre-commit
  hook blocks new source files that arrive with no test. Bypass intentionally
  only with `TDD_SKIP=1 git commit …`, never `--no-verify`.
- **Type hints everywhere**, Pydantic for validation, `ruff` + `mypy` clean.
- Small, focused functions. Explicit over implicit. Comments explain *why*.
- Keep the OWASP mapping honest — a finding's catalogue tag is part of its truth.

## 3. MurphySig — Review-on-Touch

Files may carry a `Signed:` provenance block. If you make a substantive edit
(>5 changed lines) to a signed file, **add a `Review:` entry** — what changed,
why, and `Confidence now`. The pre-commit hook enforces this; the anchor text
must match the signed block exactly. Never fabricate a signature for an unsigned
file — sign only your own contribution with `Prior: Unknown`.
See <https://murphysig.dev/spec>.

## 4. Workflow

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                 # must stay green (63+)
ruff check . && mypy puca
```

- Branch off `master`. One logical change per PR.
- Commit messages: imperative subject, a short body saying *why*.
- PRs use the template in `.github/`. Green tests + a clean scope story merge.

## 5. Reporting a vulnerability

Don't open a public issue for a security flaw in Púca itself. Follow
[`SECURITY.md`](SECURITY.md).

---

<sub>Signed: kevin+claude-opus-4-8, 2026-09-10, Confidence 0.85, Prior: Unknown —
the contributor contract for Púca; the scope rule is load-bearing, keep it first.</sub>
