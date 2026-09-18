#!/usr/bin/env bash
# Container entrypoint: wait for the database, migrate, then exec the server.
set -euo pipefail

cd /app/backend

wait_for_database() {
  [[ -z "${POSTGRES_HOST:-}" && -z "${DATABASE_URL:-}" ]] && return 0

  echo "[entrypoint] waiting for the database…"
  for attempt in $(seq 1 60); do
    if python - <<'PY' 2>/dev/null
import asyncio, sys
from sqlalchemy import text
from app.db.session import engine

async def probe():
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))

try:
    asyncio.run(probe())
except Exception:
    sys.exit(1)
PY
    then
      echo "[entrypoint] database is ready (attempt ${attempt})"
      return 0
    fi
    sleep 2
  done

  echo "[entrypoint] database did not become ready in time" >&2
  exit 1
}

migrate() {
  echo "[entrypoint] applying migrations…"
  alembic upgrade head
}

case "${1:-serve}" in
  serve)
    wait_for_database
    migrate
    echo "[entrypoint] starting SilentShift on ${HOST:-0.0.0.0}:${PORT:-8000}"
    # Uvicorn workers under Gunicorn: process supervision plus an async worker class.
    exec gunicorn app.main:app \
      --worker-class uvicorn.workers.UvicornWorker \
      --workers "${WORKERS:-2}" \
      --bind "${HOST:-0.0.0.0}:${PORT:-8000}" \
      --timeout 120 \
      --graceful-timeout 30 \
      --keep-alive 5 \
      --access-logfile - \
      --error-logfile - \
      --log-level "${GUNICORN_LOG_LEVEL:-info}"
    ;;
  migrate)
    wait_for_database
    migrate
    ;;
  shell)
    exec python
    ;;
  *)
    exec "$@"
    ;;
esac
