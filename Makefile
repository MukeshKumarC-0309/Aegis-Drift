# Aegis Drift — developer entrypoints.
.DEFAULT_GOAL := help
SHELL := /bin/bash

VENV        := .venv
PY          := $(VENV)/bin/python
PIP         := $(VENV)/bin/pip
BACKEND     := backend
FRONTEND    := frontend
COMPOSE     := docker compose

.PHONY: start
start: ## Start everything — installs what is missing (the easy path)
	@./start.sh

.PHONY: stop
stop: ## Stop whatever is running
	@./start.sh stop

.PHONY: reset
reset: ## Wipe local data and start fresh
	@./start.sh reset

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------- setup
.PHONY: setup
setup: setup-backend setup-frontend ## Install everything for local development
	@echo "Ready. Run 'make dev' to start the API and console."

$(VENV):
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip setuptools wheel

.PHONY: setup-backend
setup-backend: $(VENV) ## Install Python dependencies
	$(PIP) install --quiet -e "$(BACKEND)[dev]"

# `start.sh` installs runtime dependencies only, which is right for running the
# app but leaves pytest and ruff absent. Developer targets ensure them first so
# `make test` after `./start.sh` does not fail with a confusing ImportError.
.PHONY: dev-deps
dev-deps: $(VENV)
	@$(PY) -c "import pytest, ruff" 2>/dev/null || \
	  (echo "  Installing development tools…" && $(PIP) install --quiet -e "$(BACKEND)[dev]")

.PHONY: setup-frontend
setup-frontend: ## Install Node dependencies
	cd $(FRONTEND) && npm install

.PHONY: env
env: ## Create .env from the example if it does not exist
	@test -f .env || (cp .env.example .env && \
	  $(PY) -c "import secrets,pathlib; p=pathlib.Path('.env'); \
	    p.write_text(p.read_text().replace('change-me-to-a-random-48-byte-urlsafe-string-before-deploying', secrets.token_urlsafe(48)))" && \
	  echo "Created .env with a freshly generated SECRET_KEY")

# --------------------------------------------------------------------- run
.PHONY: dev
dev: ## Run the API and the Vite dev server together
	@trap 'kill 0' EXIT; \
	 ($(MAKE) dev-api) & ($(MAKE) dev-web) & wait

.PHONY: dev-api
dev-api: ## Run the API with hot reload
	cd $(BACKEND) && PYTHONPATH=. ../$(VENV)/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

.PHONY: dev-web
dev-web: ## Run the console dev server
	cd $(FRONTEND) && npm run dev

.PHONY: serve
serve: build-web ## Serve the built console from the API (production shape)
	cd $(BACKEND) && PYTHONPATH=. ../$(VENV)/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000

# ------------------------------------------------------------------ quality
.PHONY: test
test: dev-deps ## Run the full backend test suite
	$(PY) -m pytest $(BACKEND)/tests -q

.PHONY: test-cov
test-cov: dev-deps ## Run tests with a coverage report
	$(PY) -m pytest $(BACKEND)/tests --cov=app --cov-report=term-missing --cov-report=html

.PHONY: lint
lint: dev-deps ## Lint and type-check everything
	$(VENV)/bin/ruff check $(BACKEND)
	$(VENV)/bin/ruff format --check $(BACKEND)
	cd $(FRONTEND) && npm run lint && npm run typecheck

.PHONY: format
format: dev-deps ## Auto-format and fix what can be fixed
	$(VENV)/bin/ruff check --fix $(BACKEND)
	$(VENV)/bin/ruff format $(BACKEND)

.PHONY: typecheck
typecheck: dev-deps ## Type-check the backend
	$(VENV)/bin/mypy $(BACKEND)/app

.PHONY: check
check: lint test ## Everything CI runs

# ---------------------------------------------------------------- database
.PHONY: migrate
migrate: ## Apply migrations to head
	cd $(BACKEND) && PYTHONPATH=. ../$(VENV)/bin/alembic upgrade head

.PHONY: migration
migration: ## Autogenerate a migration: make migration m="add widgets"
	@test -n "$(m)" || (echo "Usage: make migration m=\"describe the change\"" && exit 1)
	cd $(BACKEND) && PYTHONPATH=. ../$(VENV)/bin/alembic revision --autogenerate -m "$(m)"

.PHONY: migrate-down
migrate-down: ## Roll back one migration
	cd $(BACKEND) && PYTHONPATH=. ../$(VENV)/bin/alembic downgrade -1

.PHONY: db-check
db-check: ## Verify the models and migrations agree
	cd $(BACKEND) && PYTHONPATH=. ../$(VENV)/bin/alembic check

.PHONY: db-reset
db-reset: ## Delete the local SQLite database
	rm -f $(BACKEND)/aegisdrift.db
	@echo "Local database removed. It will be recreated and seeded on next start."

# ------------------------------------------------------------------- build
.PHONY: build-web
build-web: ## Build the console for production
	cd $(FRONTEND) && npm run build

.PHONY: docker-build
docker-build: ## Build the production image
	docker build -t aegisdrift:latest .

# ------------------------------------------------------------------ compose
.PHONY: up
up: env ## Start the full stack (Postgres, Redis, API, nginx)
	$(COMPOSE) up -d --build
	@echo "Console: http://localhost:8080   API docs: http://localhost:8000/docs"

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: clean-volumes
clean-volumes: ## Stop the stack and delete its data volumes
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail stack logs
	$(COMPOSE) logs -f --tail=100

.PHONY: ps
ps: ## Show stack status
	$(COMPOSE) ps

# ------------------------------------------------------------------- misc
.PHONY: smoke
smoke: ## Run the end-to-end smoke test against a running API
	$(PY) scripts/smoke_test.py

.PHONY: clean
clean: ## Remove build artefacts and caches
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	rm -rf $(FRONTEND)/dist $(FRONTEND)/node_modules/.vite
