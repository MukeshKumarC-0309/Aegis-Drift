# Contributing

## Setup

```bash
git clone https://github.com/MukeshKumarC-0309/Aegis-Drift.git
cd Aegis Drift
make setup
make dev
```

Requires Python 3.11+ and Node 20+. No database needed — it falls back to SQLite.

```bash
pip install pre-commit && pre-commit install
```

## Before you push

```bash
make check   # ruff, ruff format, eslint, tsc, pytest
```

## Conventions

**Python.** Ruff at 110 columns, double quotes, full type hints on public functions. Comments
explain *why*, never *what* — if a line needs a comment to say what it does, rename something
instead.

**TypeScript.** Strict mode, no `any` without justification. Server state belongs in TanStack Query,
not `useState`.

**Commits.** Conventional Commits: `feat(engine): add device-fingerprint vector`.

## The architectural rule

> **`backend/app/engine/` must not import SQLAlchemy or FastAPI.**

The engine operates on frozen dataclasses in `engine/types.py`. Adapters in `services/adapters.py`
translate at the boundary. This is what makes the detection logic exhaustively testable without a
database, and it is the constraint most worth protecting.

## Adding a detection vector

1. Add it to `RiskVector` in `core/enums.py`.
2. Add a default weight in `DEFAULT_VECTOR_WEIGHTS` (`engine/types.py`). The others renormalise.
3. Implement `_your_vector(...)` on `BaselineEngine`, returning 0–100, and call it from
   `score_event`.
4. If it needs new learned state, extend `BaselineView`, the `Baseline` model, `build()`, and the
   adapter — then generate a migration.
5. Add a label and explanation in `engine/explain.py` and `frontend/src/lib/format.ts`.
6. **Write the test that would fail without it**, and check the benign-control test still passes.

That last step matters most. Every vector makes the system more sensitive; the discipline is proving
it does not also make it noisier.

## Adding an endpoint

1. Schemas in `schemas/`, never inline dicts.
2. Handler in `api/v1/endpoints/`, with the right RBAC dependency.
3. Business logic in `services/` — handlers validate and shape, they do not decide.
4. `await audit.record(...)` for anything state-changing.
5. Register the router if the module is new.
6. Integration test covering the happy path, the RBAC denial, and the validation failure.

## Tests

```bash
make test
make test-cov
.venv/bin/pytest backend/tests/unit/test_engine_scoring.py -v
```

Unit tests cover the engine with no database. Integration tests drive the real app over HTTP with an
in-memory database. `scripts/smoke_test.py` runs against a live deployment.

Write tests that assert *behaviour a user would notice*, not implementation detail. Compare
`test_low_and_slow_chain_reaches_critical` with a test that asserts an internal counter — only one
of those still passes after a justified refactor.

## Database changes

```bash
make migration m="describe the change"
# read the generated file — autogenerate is a draft, not an author
make migrate
make db-check
```

Never edit a migration that has been applied anywhere but your laptop.
