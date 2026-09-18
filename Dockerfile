# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# SilentShift — single production image.
#
# Stage 1 builds the React console, stage 2 installs Python dependencies into a
# virtualenv, and the runtime stage copies only those artefacts. The result runs
# as a non-root user and contains no build toolchain.
# ---------------------------------------------------------------------------

# ----------------------------------------------------------- stage 1: console
FROM node:22-alpine AS console

WORKDIR /build

# Copy manifests first so dependency installation is cached independently of source.
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund

COPY frontend/ ./
RUN npm run build


# ------------------------------------------------------- stage 2: python deps
FROM python:3.12-slim AS deps

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY backend/pyproject.toml backend/README.md ./

# Resolve dependencies against a stub package so this layer caches independently of
# application source. The stub distribution is then uninstalled — pip leaves the
# dependencies in place — so nothing shadows the real code copied in at runtime.
RUN mkdir -p app && touch app/__init__.py \
 && pip install --upgrade pip setuptools wheel \
 && pip install . \
 && pip uninstall -y silentshift


# ----------------------------------------------------------- stage 3: runtime
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/backend \
    PATH="/opt/venv/bin:$PATH" \
    HOST=0.0.0.0 \
    PORT=8000 \
    ENVIRONMENT=production \
    LOG_FORMAT=json \
    FRONTEND_DIST_DIR=/app/frontend/dist

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl libpq5 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1001 silentshift \
 && useradd --system --uid 1001 --gid silentshift --create-home silentshift

COPY --from=deps /opt/venv /opt/venv

WORKDIR /app
COPY --chown=silentshift:silentshift backend/ ./backend/
COPY --from=console --chown=silentshift:silentshift /build/dist ./frontend/dist
COPY --chown=silentshift:silentshift docker-entrypoint.sh ./

RUN chmod +x docker-entrypoint.sh

USER silentshift
EXPOSE 8000

# The container is unhealthy only when the database is unreachable, so a transient
# dependency blip does not cause an orchestrator to cycle a serving pod.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT}/health/ready || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["serve"]
