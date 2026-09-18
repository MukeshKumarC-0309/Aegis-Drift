<div align="center">

# Aegis Drift

**Identity Threat Detection & Response**

Catching the account compromise that behaves normally for six weeks and then drifts.

[![CI](https://github.com/MukeshKumarC-0309/Aegis-Drift/actions/workflows/ci.yml/badge.svg)](https://github.com/MukeshKumarC-0309/Aegis-Drift/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![React 19](https://img.shields.io/badge/react-19-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

</div>

---

## The problem

A stolen credential does not trip a per-event rule. It logs in at a plausible hour, reads a schema
document, queries a replica, and three days later exports two million customer records. Every one of
those steps clears whatever threshold you set. Only the **sequence** is damning.

Meanwhile the rules you *do* have fire constantly on people who changed teams, joined an on-call
rotation, or were handed a migration project last Tuesday. Analysts stop reading the queue, and the
one alert that mattered scrolls past at 3 a.m.

Aegis Drift is built around both halves of that problem: **accumulate weak signals over time**, and
**suppress the ones a business reason already explains** — with a hard floor that no approval can
cross.

## How it works

```
 telemetry ──▶ ┌──────────────┐   per-event scores   ┌──────────────────┐
               │  8 vectors   │ ───────────────────▶ │  leaky risk      │
               │  per event   │                      │  accumulator     │
               └──────────────┘                      │  R·e^(−λΔt)+ΔR   │
                      ▲                              └────────┬─────────┘
                      │                                       │
          ┌───────────┴───────────┐              ┌────────────▼───────────┐
          │ learned baseline      │              │ context damping        │
          │ (this identity's own  │              │ (approved tickets)     │
          │  circadian rhythm,    │              │   ↓ anti-tamper floor  │
          │  resources, devices,  │              │   never suppressible   │
          │  geography, volume)   │              └────────────┬───────────┘
          └───────────────────────┘                           │
                                                   ┌──────────▼──────────┐
                                                   │ STABLE → EARLY_DRIFT│
                                                   │ → ESCALATING        │
                                                   │ → CRITICAL          │
                                                   └─────────────────────┘
```

**1 — Baselines.** Each identity's own history becomes the reference: a Laplace-smoothed circadian
histogram, the resources it touches and how often, its network origins and device fingerprints, its
daily event and byte volume with standard deviations, and a 95th-percentile sensitivity ceiling
(a percentile, not a max, so one outlier in the training window cannot permanently raise the bar).

**2 — Eight vectors.** Every event is scored independently on *temporal*, *resource*, *privilege*,
*peer divergence*, *geo-velocity*, *volume*, *device* and *threat intel*, each normalised to 0–100.

**3 — Sequence correlation.** Risk accumulates into a leaky integrator that decays continuously:

$$R(t_i) = R(t_{i-1}) \cdot e^{-\lambda \Delta t} + \Delta R_i, \qquad \lambda = \frac{\ln 2}{T_{1/2}}$$

An unbroken run of anomalies compounds — and a run with **monotonically rising data sensitivity**
(recon → access → exfiltration) compounds harder still, because that shape is deliberate rather than
noisy. Isolated oddities decay away. A single catastrophic act also pins a severity floor, so one
crown-jewel export is never averaged out by a quiet history.

**4 — Context damping.** Approved change tickets, on-call rotations and role transfers reduce risk
inside their validity window, scaled by how specifically they match. **Evidence-destroying actions —
deleting audit logs, disabling MFA, dumping credentials — bypass damping entirely.** No approval, of
any breadth, from anyone, can hide them. This is enforced [before context is even
consulted](backend/app/engine/context.py) and is covered by a dedicated test.

**5 — Explainability.** Every verdict is traceable to specific events, with vector attribution,
peer-cohort z-scores, ATT&CK mapping, a quantified blast radius — and an explicit
**"considerations against this verdict"** section, because a tool that only ever prosecutes is one
analysts learn to distrust.

## Quick start

```bash
./start.sh
```

That is the whole thing. It checks what you have, installs whatever is missing, builds the
console, creates and seeds the database, starts the server and opens your browser.

No `.env` to write. No secrets to generate. No database to provision. First run takes two or
three minutes while it installs dependencies and learns behavioural baselines for 24 synthetic
identities; after that it starts in about a second.

**Requirements:** Python 3.11+. Node 20+ is optional — without it you still get the full API,
just not the console, and the script tells you so rather than failing.

| Command | What it does |
|---|---|
| `./start.sh` | Install what is missing, then start |
| `./start.sh dev` | Same, with hot reload on both backend and console |
| `./start.sh secure` | Serve at `https://aegisdrift.local` with a trusted certificate |
| `./start.sh docker` | Run the full stack (Postgres, Redis, nginx) in containers |
| `./start.sh stop` | Stop whatever is running |
| `./start.sh reset` | Wipe local data and start fresh |
| `./start.sh logs` | Follow the server log |

`PORT=8010 ./start.sh` runs somewhere else. `NO_OPEN=1` skips opening a browser.
`make start` / `make stop` / `make reset` do the same things if you prefer Make.

### A proper hostname instead of localhost

```bash
./start.sh secure
```

Gives you **`https://aegisdrift.local:8443`** with a real padlock and no browser warning.

It installs [mkcert](https://github.com/FiloSottile/mkcert), creates a development certificate
authority, issues a certificate for the hostname, and adds one line to `/etc/hosts`. Two of those
steps need your password. Nothing is exposed to the internet — the name resolves to `127.0.0.1`
on this machine only.

- `SITE_HOST=soc.mycompany.test ./start.sh secure` — pick a different name
- `HTTPS_PORT=443 ./start.sh secure` — drop the `:8443`, at the cost of running under `sudo`
  (ports below 1024 require root)
- `./start.sh unsecure` — remove the certificate and hosts entry
- `mkcert -uninstall` — remove the development CA from your trust store

> Use a `.local`, `.test` or `.localhost` suffix. Avoid inventing a name under a real TLD like
> `.com` — if that domain ever becomes real, your machine would keep hijacking it.

### Sign in

The script prints these when it finishes:

| Role | Email | Password | Can do |
|---|---|---|---|
| Admin | `admin@aegisdrift.com` | `ChangeMe_Aeg1sDrift!` | Everything, including engine tuning and estate reset |
| Responder | `responder@aegisdrift.com` | `ResponderDemo_2026!` | Analyst permissions plus containment actions |
| Analyst | `analyst@aegisdrift.com` | `AnalystDemo_2026!` | Triage, cases, rules, context records |
| Viewer | `viewer@aegisdrift.com` | `ViewerDemo_2026!` | Read-only |

### Running it for real

Local runs generate and cache a signing key so you stay logged in across restarts. **Production
does not get that convenience** — the application refuses to start with `ENVIRONMENT=production`
unless you supply your own `SECRET_KEY`, change the default superuser password, and restrict
`CORS_ORIGINS`. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## See it work

Open **Threat Simulator** and press *Run all scenarios*. Each one injects real telemetry through the
live ingestion pipeline, and **declares the outcome it expects** — so the simulator doubles as a
regression harness rather than a scripted demo.

| Scenario | What it proves |
|---|---|
| **The Slow Poisoner** | Five days of drift ending in a crown-jewel export. No single step trips a threshold; the sequence reaches `CRITICAL_TRANSITION`. |
| **The Compromised Admin** | Bucharest login four hours after San Francisco, then IAM escalation, then CloudTrail deletion. An active on-call approval covers the production access — and cannot touch the tampering. |
| **The Legitimate Project Switcher** | Statistically identical to staged exfiltration. A scoped change ticket damps it to `STABLE` and nobody gets paged. |
| **Privilege Creep** | Entitlement accumulation toward org-admin, carried by peer-cohort divergence. |
| **Impossible Travel** | 11,000 km in 20 minutes. Conclusive on its own; no accumulation needed. |
| **The Departing Employee** | Bulk collection during a notice period, scored more aggressively via a watchlist multiplier. |

Or drive the whole thing from the outside:

```bash
python scripts/smoke_test.py http://localhost:8000
```

49 assertions across auth, RBAC, ingestion, detection, explainability, response and export.

## Architecture

```
Aegis-Drift/
├── backend/
│   ├── app/
│   │   ├── core/            config, logging, security, middleware, metrics, enums
│   │   ├── db/              SQLAlchemy 2.0 models, session, seed data
│   │   ├── engine/          ◀ pure detection engine — no DB, no framework
│   │   │   ├── baseline.py      learns norms, scores events on 8 vectors
│   │   │   ├── sequence.py      the leaky risk accumulator
│   │   │   ├── context.py       damping + the anti-tamper floor
│   │   │   ├── rules.py         declarative JSON rule DSL
│   │   │   ├── peer.py          cohort statistics
│   │   │   ├── mitre.py         ATT&CK technique mapping
│   │   │   ├── blast_radius.py  reachable assets, regulatory exposure
│   │   │   ├── explain.py       the analyst-facing brief
│   │   │   └── copilot.py       grounded Q&A over computed evidence
│   │   ├── services/        orchestration between the DB and the engine
│   │   ├── api/v1/          66 REST endpoints + WebSocket
│   │   └── workers/         background scoring, retention, expiry
│   ├── alembic/             migrations
│   └── tests/               137 tests
├── frontend/                React 19 · TypeScript · Vite · Tailwind 4
│   └── src/features/        11 routed pages
├── deploy/                  nginx, Postgres init
├── docs/                    architecture, detection, API, deployment
└── scripts/smoke_test.py    end-to-end deployment gate
```

**The engine imports nothing from SQLAlchemy or FastAPI.** It operates on frozen dataclasses, which
is why it can be unit-tested exhaustively without a database and why the scoring logic reads as
mathematics rather than plumbing. Adapters in `services/` translate at the boundary.

### Stack

| Layer | Choice | Why |
|---|---|---|
| API | FastAPI + Pydantic v2 | Async, and the OpenAPI schema is generated from the types that actually validate |
| Database | PostgreSQL 16 / SQLite | Async SQLAlchemy 2.0; SQLite fallback means `git clone && make dev` works with zero dependencies |
| Migrations | Alembic | Custom types render as plain DDL so frozen history never couples to live code |
| Cache / bus | Redis (optional) | Fans the live WebSocket feed across replicas; degrades to in-process cleanly |
| Console | React 19 + TanStack Query | Code-split per route, typed against the API |
| Charts | Recharts + custom SVG | The blast-radius graph is a deterministic radial layout, not a force simulation, so the same estate always renders identically |
| Observability | structlog + Prometheus | JSON logs with request correlation IDs; metrics for latency, ingestion, scoring and fleet state |

## Security

- **JWT access/refresh** with type confusion rejected (a refresh token cannot authenticate a request)
- **Argon2** password hashing; lockout after repeated failures
- **RBAC** across four tiers, enforced as a dependency rather than per-handler checks
- **API keys** for machine ingest — SHA-256 hashed, shown once, never retrievable
- **Audit log** on every state change, with credentials scrubbed (covered by a regression test)
- **Rate limiting** in the app and at nginx, with a separate higher budget for ingest
- Uniform login failures, so the API does not leak which addresses are registered
- Security headers, non-root container, no build toolchain in the runtime image

See [docs/SECURITY.md](docs/SECURITY.md).

## Documentation

| Document | Contents |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | Layering, data model, request lifecycle, design decisions |
| [Detection engine](docs/DETECTION.md) | The mathematics, every vector, tuning guidance |
| [API reference](docs/API.md) | All 66 endpoints, auth, ingestion, rule DSL |
| [Deployment](docs/DEPLOYMENT.md) | Docker, Kubernetes, scaling, backups, observability |
| [Security](docs/SECURITY.md) | Threat model, controls, hardening checklist |
| [Contributing](CONTRIBUTING.md) | Setup, conventions, how to add a detection vector |

## Testing

```bash
make test       # 137 tests
make test-cov   # with coverage
make check      # everything CI runs
```

The tests worth reading are in
[`backend/tests/unit/test_engine_scoring.py`](backend/tests/unit/test_engine_scoring.py) — they
assert the product claims rather than the implementation:

- a benign control group stays `STABLE` (a detector that alerts on normal behaviour is worse than none)
- the low-and-slow chain reaches `CRITICAL_TRANSITION`
- **no individual step in that chain would trip a per-event threshold on its own**
- risk decays when drift stops
- a scoped context suppresses while preserving the raw score for audit
- a lapsed or out-of-scope context does not damp
- **no context, however broad, can suppress evidence destruction** (parametrised over four actions)
- a rejected engine-tuning request leaves the live detector byte-for-byte unchanged
- re-scoring the same events never inflates a detection rule's match count
- production refuses to start on the cached development key or a default password

## Honest limitations

- The demonstration estate is synthetic. The engine is real; the people are not.
- Exposure figures use published per-record breach costs. "Exposure under management" sizes what an
  incident on the monitored assets could cost — it is deliberately **not** framed as loss the
  platform prevented, because that would not be defensible. They are planning estimates for routing
  a decision, not actuarial or legal determinations, and the UI says so wherever they appear.
- The SOC Copilot is a deterministic intent classifier over computed evidence, **not** a language
  model. It declines rather than speculating. That is a deliberate constraint, not a missing feature.
- The MTTD comparison baseline is a published industry aggregate; only the measured side comes from
  your own deployment.
- The background scheduler runs in the API process. That is honest at this scale; a separate worker
  is the next step under real load.
- Integration connectors (Okta, Splunk, ServiceNow) are modelled as status and configuration. The
  ingest API is real and documented — wiring a live source is a webhook away.

## License

Apache 2.0 — see [LICENSE](LICENSE).
