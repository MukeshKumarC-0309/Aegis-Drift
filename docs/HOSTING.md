# Hosting on a free tier

What it actually costs, what breaks, and how to deploy.

---

## The honest summary

You can run Aegis Drift publicly for **£0**, at `https://aegisdrift.onrender.com`.

Three things you should know before you do:

1. **It sleeps.** Free web services shut down after ~15 minutes of no traffic. The next
   visitor waits **30–60 seconds** for a cold start. For a link you send someone, that first
   impression is a blank loading screen.
2. **The database is temporary.** Render's free PostgreSQL is deleted when its trial period
   ends. On most applications that is a catastrophe. Here it is survivable *only* because
   `AUTO_SEED` regenerates the whole synthetic estate on boot — you lose any cases and
   dispositions you created, and the demo comes back.
3. **A free `.com` does not exist.** `aegisdrift.com` is unregistered and costs roughly
   £10–15/year. The free address is the `onrender.com` subdomain.

If the sleeping is unacceptable, the cheapest fix is about **$7/month** for a paid instance
that stays warm. Nothing else about the deployment changes.

## Deploying

1. Push this repository to GitHub (already done).
2. Go to [render.com](https://render.com) and sign in with GitHub.
3. **New → Blueprint**, select the repository. Render reads `render.yaml` and creates both
   the web service and the database.
4. It prompts for `FIRST_SUPERUSER_PASSWORD`. Use a strong one — the application refuses to
   start on the documented default.
5. First build takes 5–10 minutes: it compiles the console and installs Python dependencies.

Then sign in at `https://aegisdrift.onrender.com` as `admin@aegisdrift.com`.

### The demo logins are off in production

`analyst@`, `responder@` and `viewer@` are **not created** on a production deployment. Their
passwords are published in this repository, and the responder role can quarantine identities
and execute containment playbooks. Handing that to anyone who reads the README is not a
demonstration, it is an open door.

If you want them for a public demo, set all four:

```
SEED_DEMO_ACCOUNTS=true
DEMO_ANALYST_PASSWORD=<something strong>
DEMO_RESPONDER_PASSWORD=<something strong>
DEMO_VIEWER_PASSWORD=<something strong>
```

Leave any of the three at its published value and the application refuses to boot. That is
deliberate.

## Shipping changes

`autoDeploy: true` and `branch: main` are set, so **pushing to `main` redeploys automatically**.

```bash
git add -A
git commit -m "..."
git push          # Render starts building within seconds
```

What happens, in order:

1. Render detects the push and rebuilds the Docker image — **5–10 minutes**, because it
   recompiles the console and reinstalls Python dependencies.
2. The new container waits for the database, runs `alembic upgrade head`, then starts.
3. Render swaps traffic over only once the health check passes.

### Your data survives

The database is a separate service, so a redeploy does not touch it. Seeding is skipped when
identities already exist — cases, alerts, dispositions and injected telemetry all persist
across deploys. Verified: an estate with an open case came back identical after a restart,
with `seed.identities_present` in the log instead of a re-seed.

### Things that will catch you out

| Situation | What happens |
|---|---|
| Build fails | The previous version keeps serving. Render does not swap to a broken image. |
| You changed a model but did not generate a migration | `alembic upgrade head` succeeds with nothing to do, then the app errors at runtime against a stale schema. Run `make db-check` before pushing — CI runs it too. |
| A migration fails | The container exits before serving, so the old one stays up. Check the deploy log. |
| You edited `render.yaml` | Blueprint changes are **not** picked up automatically. Trigger a manual sync from the Render dashboard. |
| You changed an environment variable in the dashboard | That alone triggers a redeploy. |
| Free tier, single instance | Expect a few seconds of downtime during the swap. |

### Skipping a deploy

Add `[skip render]` to the commit message for documentation-only changes, or turn off
auto-deploy in the dashboard and deploy manually.

## Adding a real domain later

Buy the domain (Cloudflare and Namecheap are both around £10/yr), then:

1. Render → your service → **Settings → Custom Domain** → add `aegisdrift.com`
2. Create the DNS records Render shows you
3. TLS is issued automatically via Let's Encrypt
4. Update two environment variables, or the browser will block your own frontend:

```
CORS_ORIGINS=https://aegisdrift.com
TRUSTED_HOSTS=aegisdrift.com
```

Custom domains work on Render's free plan.

## Why not the others

| Host | Verdict |
|---|---|
| **Render** | Best free fit. Docker, PostgreSQL, WebSockets, custom domains. Sleeps. |
| **Fly.io** | No general free tier any more; pay-as-you-go. Excellent, but not free. |
| **Railway** | Trial credit, then a paid minimum. |
| **Vercel / Netlify** | Wrong shape. Serverless functions cannot hold a WebSocket open or run the background scheduler. |
| **Oracle Cloud Always Free** | Genuinely free and far more capable (ARM VM, lots of RAM). Signup is notoriously difficult and you maintain the server yourself. |

## What breaks on the free tier, precisely

| Feature | Effect |
|---|---|
| Background scheduler | Stops while asleep. Risk scores are recomputed on the next request instead of every 45s. |
| Live WebSocket feed | Works while awake. Disconnects on sleep; the console reconnects with backoff. |
| Redis | Not provisioned. The event bus falls back to in-process, which is correct for one instance. |
| Telemetry retention | Cut to 30 days to stay inside the small free database. |
| Cold start | 30–60 seconds after idle. |
| Seeded estate | 30 days of history rather than 40, so startup stays inside the health-check window on 0.1 CPU. 21 of 24 baselines still reach maturity. |

None of these affect the detection engine's correctness — only its liveness.

## Keeping it awake (and why you probably should not)

An uptime pinger every 10 minutes will stop it sleeping. It also consumes your monthly free
instance hours, and Render's terms discourage it. If uptime matters, pay the $7.
