# Security

## Threat model

Aegis Drift holds behavioural telemetry about employees and the classification of an organisation's
most sensitive assets. A compromise of this system would hand an attacker both a map of what is
worth stealing and the ability to hide their own drift.

Three consequences shape the design:

1. **The blast-radius model is a target.** An attacker reading `/catalog/assets` learns exactly which
   systems hold crown jewels. Read access is authenticated; there is no anonymous surface.
2. **Detection suppression is the highest-value attack.** Anyone able to create a context record can
   quiet an alert. Damping is therefore bounded, never total, always attributed, and structurally
   unable to cover evidence destruction.
3. **The audit log is the last line.** Everything state-changing is recorded, credentials are
   scrubbed before write, and audit-log destruction is the one action that bypasses every
   suppression path in the system.

## Controls

### Authentication
- Argon2id password hashing (`passlib`), unique salt per hash
- Password policy: ≥12 chars, mixed case, digit, symbol — validated at the schema, not the handler
- Account lockout for 15 minutes after 6 consecutive failures
- Uniform failure responses, so login does not leak which addresses are registered
- JWT access (60 min) and refresh (14 days), issuer-validated, with `jti`, `nbf` and `exp`
- **Token type confusion rejected**: a refresh token cannot authenticate a request

### Authorisation
Four tiers — `viewer` < `analyst` < `responder` < `admin` — enforced by a dependency factory rather
than per-handler checks, so a new endpoint cannot accidentally ship unguarded. Enforcing actions
(quarantine, disable, revoke) require `responder`; engine tuning and estate reset require `admin`.

### Machine credentials
API keys are `ad_live_` + 256 bits of entropy, stored only as SHA-256, compared with
`hmac.compare_digest`, returned to the operator exactly once. They carry scopes, optional expiry,
and usage counters, and can be revoked immediately.

### Transport and headers
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
strict-origin-when-cross-origin`, `Permissions-Policy` denying geolocation/microphone/camera,
`Cross-Origin-Opener-Policy: same-origin`, and HSTS in production.

### Input handling
Every request body is a Pydantic model — bounded strings, ranged numerics, enum membership. The ORM
is used exclusively through the expression language, so there is no string-built SQL anywhere in the
codebase.

The rule DSL is the one place accepting user-authored logic. It is a whitelisted operator set over a
fixed fact namespace with a depth limit of 8 — not `eval`, not a query language. Regex is confined to
the `matches` operator on short event fields.

### Rate limiting
Fixed window per IP plus API-key prefix, with a separate higher budget for ingestion. nginx applies
a coarser limit at the edge: the application limiter protects one replica, the edge protects the
fleet.

### Audit
Append-only, capturing actor, action, target, outcome, IP, user agent, correlation ID and payload.
A redaction list scrubs `password`, `token`, `key` and `secret` before write — with a
[regression test](../backend/tests/integration/test_api.py) asserting a created user's password
never appears in the audit trail.

### Container
Non-root (uid 1001), no build toolchain in the runtime layer, dependencies installed into a
virtualenv copied from a builder stage, health check on the dependency-free probe. CI runs Trivy
and CodeQL on every push.

## The anti-tamper guarantee

The one property worth stating plainly:

> **No context record, of any breadth, created by anyone, can suppress an action that destroys or
> disables audit evidence.**

Enforced in [`engine/context.py`](../backend/app/engine/context.py) as the first branch of the
damping evaluator — before contexts are loaded at all — covering `delete_audit_logs`,
`disable_logging`, `dump_credentials`, `disable_mfa`, `exfiltrate`, `create_backdoor_user` and
`rotate_root_key`.

It is a code path, not a policy setting, precisely so that it cannot be misconfigured. The test
suite asserts it against a blanket approval with a maximally permissive damping factor, parametrised
over every listed action.

## Known limitations

- **Refresh tokens are not revocable before expiry.** There is no server-side token denylist; a
  stolen refresh token is valid for up to 14 days. Shorten `REFRESH_TOKEN_EXPIRE_DAYS` if that is
  unacceptable in your environment.
- **The WebSocket token appears in the URL.** Browsers cannot set headers on a WebSocket handshake.
  It is a short-lived access token granting read-only streaming, but it will appear in proxy access
  logs.
- **Rate limiting is per-replica.** Deliberate — see above — but it means the application limit
  alone does not bound fleet-wide traffic.
- **No MFA on console sign-in.** Front the deployment with an SSO provider that enforces it.
- **No field-level encryption at rest.** Rely on database-level encryption.

## Reporting a vulnerability

Please do not open a public issue. Email the maintainers with reproduction steps and impact. We aim
to acknowledge within 48 hours.
