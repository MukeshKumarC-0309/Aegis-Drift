# Architecture

## Layering

```
┌──────────────────────────────────────────────────────────────┐
│  api/v1/endpoints   HTTP surface: validation, RBAC, shaping  │
├──────────────────────────────────────────────────────────────┤
│  services/          orchestration — knows the DB and engine  │
├──────────────────────────────────────────────────────────────┤
│  engine/            pure analytics — knows neither           │
├──────────────────────────────────────────────────────────────┤
│  db/                SQLAlchemy models, session, migrations   │
├──────────────────────────────────────────────────────────────┤
│  core/              config, security, logging, middleware    │
└──────────────────────────────────────────────────────────────┘
```

Dependencies point downward only. The rule that does the most work:

> **`app/engine/` imports nothing from SQLAlchemy or FastAPI.**

It operates on frozen dataclasses (`EventView`, `BaselineView`, `ContextView`). Consequences:

- Scoring is synchronous and pure, so it reads as mathematics rather than plumbing.
- The full engine test suite runs without a database, in well under a second.
- Changing persistence never touches detection logic.
- The engine can be lifted into a batch job or a separate worker unchanged.

Adapters in [`services/adapters.py`](../backend/app/services/adapters.py) translate at the boundary
in one place.

## Request lifecycle

```
request
  → RequestContextMiddleware   correlation ID, timing, structured access log, metrics
  → CORS
  → SecurityHeadersMiddleware  nosniff, DENY, referrer policy, HSTS in production
  → RateLimitMiddleware        fixed window per IP + API-key prefix
  → GZip
  → route
      → deps.get_current_user  JWT decode, user load, RBAC rank check
      → deps.get_db            request-scoped session, commit on success
      → handler                Pydantic in, Pydantic out
        → service              orchestration, audit, event-bus publish
          → engine             pure scoring
  → exception handlers         typed errors → consistent JSON problem bodies
```

Middleware order is deliberate: the context middleware is outermost so that even a rate-limit
rejection carries a correlation ID and is logged.

## Data model

Twenty tables in five groups.

**Platform** — `users`, `api_keys`, `audit_logs`, `integrations`
**Identity** — `identities`, `baselines`, `peer_groups`
**Telemetry** — `security_events`, `assets`, `threat_indicators`
**Detection** — `alerts`, `context_records`, `detection_rules`, `risk_snapshots`, `watchlists`
**Response** — `cases`, `case_entries`, `playbooks`, `action_records`

### Decisions worth explaining

**Prefixed string primary keys** (`idn_a279acdc8cda4515`). Readable in logs and URLs, and the prefix
makes it obvious when an ID has been passed to the wrong lookup. Assigned at construction via a
SQLAlchemy `init` event, so `obj.id` is readable before the flush.

**Python-side defaults applied eagerly.** That same event materialises every column default at
construction. Without it a freshly built object exposes `None` for defaulted columns until flush,
and code like `row.version += 1` fails — which is exactly the bug that surfaced during development.

**`StrEnumType` rather than bare `String`.** SQLite returns plain strings for enum columns, so
`user.role.rank` — the RBAC check — silently breaks. The type decorator rehydrates the enum on read
and tolerates unknown values from an older schema rather than failing the query.

**Denormalised scores on `identities`.** `risk_score`, `transition_state`, `vector_scores` and
friends are cached on the row and refreshed by the scoring worker. The estate list is the most
frequently loaded view in the product; re-running correlation for 24 identities to render a table
would be indefensible.

**`risk_snapshots` as a separate time series.** Trend charts and backtesting need history that the
denormalised cache cannot provide. Pruned by the retention worker.

**One open alert per identity.** A drifting account is one story. Repeat detections increment
`occurrence_count` rather than flooding the queue — alert fatigue is the problem being solved, so
the product must not cause it.

## Detection pipeline

```
DetectionService.score_identity(identity)
  ├─ load events in the 14-day correlation window
  ├─ load baseline, contexts, enabled rules, active indicators
  ├─ resolve peer cohort (cached, 120s TTL)
  ├─ resolve watchlist multiplier
  ├─ SequenceEngine.correlate(...)          ← pure
  ├─ persist per-event scores and the identity cache
  ├─ optionally snapshot for trends
  └─ reconcile the alert (create / update / auto-close)
```

The 14-day window is bounded deliberately: older events are already reflected in the baseline and
would be decayed to irrelevance by a 48-hour half-life anyway.

## Background worker

A single asyncio task in the API process ([`workers/scheduler.py`](../backend/app/workers/scheduler.py)):

- Re-score the fleet every `RECOMPUTE_INTERVAL_SECONDS` (default 45s)
- Snapshot risk every 10 minutes
- Hourly housekeeping: expire lapsed contexts and watchlists, prune telemetry past retention
- Publish Prometheus gauges for fleet state

A failed cycle logs and continues; it never kills the loop. This is the honest choice at this scale
— a separate worker process is the next step under real load, and the engine's purity means moving
it is a deployment change, not a rewrite.

## Live feed

The WebSocket at `/api/v1/stream/live` carries scoring results, ingestion, response actions and case
events.

Without Redis, an in-process pub/sub fans out to local subscribers. With `REDIS_URL` set, messages
publish to a Redis channel and a relay task delivers them back — so every replica sees every event.
Slow consumers are dropped at a 256-message queue rather than being allowed to stall the publisher.

The client reconnects with exponential backoff **plus jitter**, so a server restart does not produce
a synchronised reconnect storm from every open console.

Authentication uses a query-string token because browsers cannot set headers on a WebSocket
handshake. The token is a normal short-lived access JWT; the endpoint accepts nothing else and grants
read-only streaming. The trade-off — the token appears in proxy access logs — is documented in the
module itself.

## Frontend

React 19, TypeScript, Vite, Tailwind 4, TanStack Query, React Router 7.

- **Server state lives in TanStack Query**, not component state. Cache policy is declared once per
  endpoint in [`lib/queries.ts`](../frontend/src/lib/queries.ts).
- **Routes are code-split.** The initial bundle carries the shell and dashboard; the workbench and
  its charts load on demand.
- **Colour is load-bearing.** A transition state renders in the same hue in every chart, badge and
  table, so the estate can be scanned rather than read.
- **The API client owns token refresh.** A 401 triggers exactly one refresh, and concurrent 401s
  share that single in-flight promise rather than stampeding the endpoint.
- **The investigation view is one request.** `GET /identities/{id}/investigation` returns the scored
  timeline, explanation, blast radius, baseline, contexts, alerts and action history together —
  a six-request waterfall would be visible to the user.

## Configuration

Pydantic Settings, environment-driven, resolved once into a cached singleton.

The database URL resolves `DATABASE_URL` → Postgres from parts → local SQLite. That fallback is why
`git clone && make dev` works with no external dependencies, and why the test suite runs against
in-memory SQLite while production runs Postgres — the same code path, one URL apart.

## Observability

- **Structured logs** via structlog, JSON in production, with a request-scoped correlation ID
  injected through a `ContextVar` and echoed as `X-Request-ID`.
- **Prometheus** at `/metrics`: request latency histograms, ingestion and alert counters, scoring
  duration, fleet gauges, WebSocket client count.
- **Health probes** separated on purpose. `/health/live` touches no dependency, so a database blip
  cannot cause an orchestrator to restart an otherwise healthy pod. `/health/ready` checks the
  database. `/health` reports everything.
