# API reference

Base URL `/api/v1`. Interactive docs at `/docs` (Swagger) and `/redoc`, disabled in production.

## Authentication

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@aegisdrift.com","password":"ChangeMe_Aeg1sDrift!"}'
```

```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Send `Authorization: Bearer <access_token>`. On expiry, POST the refresh token to
`/auth/refresh`. A refresh token cannot be used as an access token and vice versa — token-type
confusion is rejected explicitly.

### Roles

`viewer` < `analyst` < `responder` < `admin`. A 403 names both the required role and yours.

| Capability | Minimum |
|---|---|
| Read anything | viewer |
| Triage, cases, rules, contexts, scenarios | analyst |
| Containment actions, playbook execution | responder |
| Engine tuning, operator admin, estate reset | admin |

### API keys (machine ingest)

```bash
curl -X POST .../auth/api-keys -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"splunk-forwarder","scopes":["ingest:write"],"expires_in_days":365}'
```

The plaintext key is returned **once**. Only a SHA-256 hash is stored. Use it as `X-API-Key`.

## Errors

Every error returns the same envelope:

```json
{
  "error": {
    "code": "validation_error",
    "message": "The request payload failed validation.",
    "details": { "fields": [{ "location": "body → sensitivity_level", "message": "...", "type": "..." }] }
  }
}
```

| Status | Code | Meaning |
|---|---|---|
| 401 | `unauthenticated`, `token_expired`, `wrong_token_type` | Credentials missing or invalid |
| 403 | `permission_denied` | Authenticated, insufficient role |
| 404 | `not_found` | No such resource |
| 409 | `conflict` | Duplicate, or a state transition that is not allowed |
| 422 | `validation_error` | Payload failed validation |
| 429 | `rate_limited` | Includes a `Retry-After` header |
| 503 | `service_unavailable` | A dependency is down |

## Pagination

List endpoints take `page`, `page_size` (max 200), `sort_by`, `sort_dir` and return:

```json
{
  "items": [],
  "meta": { "page": 1, "page_size": 25, "total": 142, "total_pages": 6,
            "has_next": true, "has_previous": false }
}
```

## Telemetry ingestion

`POST /events/ingest` — up to 1,000 events per call. Authenticate with `X-API-Key` or a bearer token.

```json
{
  "events": [
    {
      "identity": "alex.mercer",
      "occurred_at": "2026-09-17T02:14:00Z",
      "event_type": "NETWORK_EGRESS",
      "resource": "crown_jewel_customer_pii_export",
      "action": "export_all",
      "sensitivity_level": 5,
      "ip_address": "185.220.101.5",
      "country": "RO",
      "latitude": 44.43,
      "longitude": 26.10,
      "device_id": "unknown-device",
      "bytes_transferred": 890000000,
      "record_count": 2400000,
      "context_tags": ["ticket:CHG-2024-9182"]
    }
  ],
  "recompute": true
}
```

Response `202`:

```json
{
  "accepted": 1, "rejected": 0,
  "identities_rescored": ["idn_..."], "alerts_raised": ["idn_..."],
  "errors": [], "duration_ms": 34
}
```

**Per-event error isolation.** One malformed record does not reject the batch — it is itemised in
`errors` with its index and reason, and the rest are accepted. A partial success is far more useful
to a forwarder than a 400.

`identity` accepts either an identity ID or a username. `occurred_at` defaults to now; timestamps
more than 10 minutes in the future or older than the retention window are rejected. `is_off_hours`
is inferred when omitted.

Set `recompute: false` for bulk backfill, then re-score once via `POST /simulator/rescore-all`.

## Endpoints

### Identities
| Method | Path | Role |
|---|---|---|
| GET | `/identities` | viewer |
| POST | `/identities` | analyst |
| GET | `/identities/departments` | viewer |
| GET | `/identities/{id}` | viewer |
| PATCH | `/identities/{id}` | analyst |
| DELETE | `/identities/{id}` | analyst |
| GET | `/identities/{id}/investigation` | viewer |
| GET | `/identities/{id}/baseline` | viewer |
| POST | `/identities/{id}/baseline/rebuild` | analyst |
| POST | `/identities/{id}/rescore` | analyst |
| POST | `/identities/{id}/copilot` | viewer |

`/investigation` is the one to know — it returns the entire workbench payload (scored timeline,
explanation, blast radius, baseline comparison, contexts, alerts, action history, matched rules) in
a single response.

### Alerts
`GET /alerts` · `GET /alerts/stats` · `GET /alerts/{id}` · `PATCH /alerts/{id}` ·
`POST /alerts/{id}/assign` · `POST /alerts/{id}/false-positive`

Filters: `status`, `severity`, `state`, `department`, `min_risk`, `damped`, `anti_tamper`,
`unassigned`, `open_only`.

Marking a false positive credits the matched rules, which feeds the precision statistics on
`/detections/stats` — the tuning loop is closed through analyst dispositions.

### Cases
`GET|POST /cases` · `GET /cases/stats` · `GET|PATCH /cases/{id}` · `GET|POST /cases/{id}/entries`

SLA is set from priority: P1 1h, P2 4h, P3 24h, P4 72h.

### Context registry
`GET|POST /contexts` · `GET|PATCH|DELETE /contexts/{id}`

Creating or revoking a context re-scores the affected identity immediately, so the analyst sees the
effect of what they just approved.

### Detection rules
`GET|POST /detections` · `GET /detections/schema` · `GET /detections/stats` ·
`POST /detections/test` · `GET|PATCH|DELETE /detections/{id}`

`/detections/test` validates a condition tree and evaluates it against a representative high-risk
event before you commit it. `/detections/schema` returns the operator list and every queryable
field, which is what the console's rule builder reads.

Built-in rule *logic* is immutable — clone and modify rather than editing in place — though built-ins
can be disabled.

### Response
`POST /response/identities/{id}/actions` · `GET /response/actions` ·
`GET /response/playbooks` · `POST /response/playbooks/{slug}/run`

Playbook runs default to `dry_run: true`, returning the plan without enforcing anything.

### Analytics
`GET /analytics/overview` · `/metrics` · `/mitre/coverage` · `/trends/risk` · `/peer-outliers` ·
`/integrations` · `/audit` · `/system` · `GET|PUT /analytics/hyperparameters` ·
`GET|POST /analytics/watchlists`

`PUT /analytics/hyperparameters` enforces strictly ordered thresholds and renormalises vector
weights to sum to 1. Pass `recompute: true` to re-score the fleet immediately.

The update is **atomic**: a 422 leaves the running engine entirely unchanged, including any valid
fields sent alongside the invalid ones.

### Catalogue
`GET /catalog/assets` · `/assets/summary` · `GET|POST /catalog/indicators` ·
`DELETE /catalog/indicators/{id}`

### Simulator
`GET /simulator/scenarios` · `POST /simulator/scenarios/{id}/run` · `POST /simulator/rescore-all` ·
`POST /simulator/reset` (admin) · `GET /simulator/estate`

Each scenario declares its expected outcome; the run result reports
`outcome_matches_expectation`.

### Forensic export
`GET /export/identities/{id}/dossier.md` · `dossier.json` · `events.csv`

The dossier includes a SHA-256 digest per evidence record, computed over a canonical field set.
These verify the export against the datastore; they are not a signature over the document.

### Live stream
`WS /api/v1/stream/live?token=<access_token>`

Message types: `connected`, `heartbeat`, `event.ingested`, `identity.rescored`, `action.executed`,
`case.created`, `scenario.completed`, `fleet.rescored`, `estate.reset`.

### Health
`/health` · `/health/live` · `/health/ready` · `/metrics` (Prometheus)

## Rate limits

| Scope | Default |
|---|---|
| General API | 300 req / 60s per IP |
| `/events/*` | 2,000 req / 60s per IP |

Keyed on client IP plus API-key prefix. Responses carry `X-RateLimit-Limit` and
`X-RateLimit-Remaining`; a 429 carries `Retry-After`. nginx applies a second, coarser limit at the
edge — the application limiter protects one replica, the edge protects the fleet.
