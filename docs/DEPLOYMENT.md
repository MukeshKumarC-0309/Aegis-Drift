# Deployment

## Trying it locally

```bash
./start.sh docker
```

Zero configuration — compose ships development defaults so the stack comes up as-is. That is
fine on a laptop and **not** fine on a server: read the next section before exposing it.

## Docker Compose

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # → SECRET_KEY
# set FIRST_SUPERUSER_PASSWORD and CORS_ORIGINS too, then:
ENVIRONMENT=production docker compose up -d --build
```

With `ENVIRONMENT=production` the application validates its own configuration at startup and
**refuses to boot** on the cached development key, the documented default password, or a
wildcard CORS origin. A misconfigured deployment fails loudly at start rather than running
quietly with laptop defaults.

Brings up PostgreSQL 16, Redis 7, the API (Gunicorn + Uvicorn workers) and nginx. The entrypoint
waits for the database, applies migrations, then execs the server.

Console at `http://localhost:8080`, API at `http://localhost:8000`.

```bash
make logs          # tail everything
make ps            # status
make down          # stop
make clean-volumes # stop and delete data
```

## Required configuration

| Variable | Notes |
|---|---|
| `SECRET_KEY` | **Required.** ≥32 chars. Rotating it invalidates every issued token. |
| `FIRST_SUPERUSER_PASSWORD` | **Required in compose.** Change from the default. |
| `POSTGRES_HOST` / `DATABASE_URL` | Omit both to fall back to SQLite (development only). |
| `ENVIRONMENT` | `production` disables `/docs`, `/redoc` and `/openapi.json`. |
| `LOG_FORMAT` | `json` in production. |
| `CORS_ORIGINS` | Comma-separated. Never `*` in production. |
| `TRUSTED_HOSTS` | Set to your real hostnames to enable host validation. |
| `AUTO_SEED` | `false` for a real deployment — you do not want 24 synthetic employees. |
| `REDIS_URL` | Optional. Required for the live feed to fan out across replicas. |
| `WORKERS` | Gunicorn workers. Start at `2 × cores + 1`. |
| `RETENTION_DAYS` | Telemetry pruning window, default 90. |

Full list in [`.env.example`](../.env.example).

## Production checklist

- [ ] `SECRET_KEY` generated fresh and stored in a secret manager, not in the image
- [ ] `FIRST_SUPERUSER_PASSWORD` changed; rotate it after first sign-in
- [ ] `ENVIRONMENT=production` and `LOG_FORMAT=json`
- [ ] `AUTO_SEED=false`
- [ ] `CORS_ORIGINS` and `TRUSTED_HOSTS` restricted to real hostnames
- [ ] TLS terminated at the edge; HSTS enabled (automatic in production)
- [ ] PostgreSQL with automated backups and PITR
- [ ] Prometheus scraping `/metrics`; alerts on error rate and scoring duration
- [ ] Log shipping configured; correlation IDs preserved end to end
- [ ] `/metrics` not exposed publicly (the shipped nginx config restricts it to RFC-1918)
- [ ] Container image scanned; CI runs Trivy and CodeQL

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: silentshift
spec:
  replicas: 3
  selector:
    matchLabels: { app: silentshift }
  template:
    metadata:
      labels: { app: silentshift }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
      containers:
        - name: api
          image: ghcr.io/your-org/silentshift:2.0.0
          ports: [{ containerPort: 8000 }]
          env:
            - name: SECRET_KEY
              valueFrom: { secretKeyRef: { name: silentshift, key: secret-key } }
            - name: POSTGRES_PASSWORD
              valueFrom: { secretKeyRef: { name: silentshift, key: postgres-password } }
            - name: POSTGRES_HOST
              value: postgres.data.svc.cluster.local
            - name: REDIS_URL
              value: redis://redis.data.svc.cluster.local:6379/0
            - name: ENVIRONMENT
              value: production
            - name: LOG_FORMAT
              value: json
            - name: AUTO_SEED
              value: "false"
          # Liveness deliberately hits the dependency-free probe: a database blip
          # must not cause Kubernetes to restart an otherwise healthy pod.
          livenessProbe:
            httpGet: { path: /health/live, port: 8000 }
            initialDelaySeconds: 20
            periodSeconds: 15
          readinessProbe:
            httpGet: { path: /health/ready, port: 8000 }
            initialDelaySeconds: 10
            periodSeconds: 10
          resources:
            requests: { cpu: 300m, memory: 512Mi }
            limits:   { cpu: "2",  memory: 2Gi }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
```

Run migrations as a `Job` or an init container before rollout:

```yaml
command: ["./docker-entrypoint.sh", "migrate"]
```

## Scaling

**Replicas.** The API is stateless apart from two in-process caches: the peer cohort cache (120s
TTL, cheap to recompute per replica) and the rate-limit window (per-replica by design — nginx
handles the fleet-wide budget).

**Redis is required above one replica** if you want the live feed to work correctly. Without it each
replica only broadcasts to its own WebSocket clients.

**The background scheduler runs in every replica.** At three replicas the fleet is scored three
times per interval — wasteful but harmless, since scoring is idempotent. Above that, set
`RECOMPUTE_INTERVAL_SECONDS` high and run a dedicated scheduler deployment with the API replicas'
scheduler disabled.

**Database.** `security_events` is the growth table. It is indexed on `(identity_id, occurred_at)`,
`(resource, occurred_at)` and `anomaly_score`. Beyond a few hundred million rows, partition it by
month and lower `RETENTION_DAYS`.

### Rough capacity

| Estate | Shape |
|---|---|
| < 500 identities | 1 replica, 2 workers, small Postgres |
| 500–5,000 | 3 replicas, 4 workers, dedicated scheduler, Redis |
| > 5,000 | Partition events by month, separate read replica for analytics, batch ingestion |

## Backups

```bash
docker compose exec postgres pg_dump -U silentshift -Fc silentshift > backup-$(date +%F).dump
docker compose exec -T postgres pg_restore -U silentshift -d silentshift --clean < backup.dump
```

Back up the database only. The image is reproducible from the repository, and no state lives on the
container filesystem.

## Observability

**Prometheus**

```yaml
scrape_configs:
  - job_name: silentshift
    metrics_path: /metrics
    static_configs:
      - targets: ['silentshift:8000']
```

| Metric | Use |
|---|---|
| `silentshift_http_request_duration_seconds` | Latency SLO |
| `silentshift_http_requests_total` | Error rate by status |
| `silentshift_events_ingested_total` | Ingestion throughput |
| `silentshift_alerts_raised_total` | Alert volume by severity |
| `silentshift_identity_scoring_seconds` | Detection pipeline cost |
| `silentshift_identities_by_state` | Fleet posture |
| `silentshift_fleet_mean_risk` | Aggregate risk trend |
| `silentshift_websocket_clients` | Console connections |

Alerts worth having: p99 latency above 2s, 5xx rate above 1%, scoring duration above 1s, ingestion
dropping to zero (a silent forwarder looks exactly like a quiet fleet).

**Logs.** JSON to stdout with `request_id` on every line and `X-Request-ID` echoed to clients, so a
user-reported problem traces straight to its log lines.

## Migrations

```bash
make migrate                          # apply to head
make migration m="add widgets table"  # autogenerate
make migrate-down                     # roll back one
make db-check                         # verify models and migrations agree
```

`make db-check` runs in CI. Custom column types render as plain DDL in generated revisions, so
frozen migration history never couples to live enum definitions.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `SECRET_KEY must be set` | Compose requires it explicitly; there is no insecure default in production |
| Container unhealthy at boot | `/health/ready` needs the database; check `docker compose logs postgres` |
| Console loads but shows no data | Token expired or CORS — check the browser console and `CORS_ORIGINS` |
| Live badge shows Offline | WebSocket blocked by a proxy; ensure `Upgrade`/`Connection` headers pass through |
| Everything scores STABLE | Baselines have not been learned; `AUTO_SEED=false` and no ingested history |
| Everything scores CRITICAL | Baselines learned from anomalous data — re-baseline from a clean window |
