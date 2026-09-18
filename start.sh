#!/usr/bin/env bash
#
# Aegis Drift — one command to run the whole thing.
#
#   ./start.sh            install what is missing, then start
#   ./start.sh dev        same, but with hot reload for the console
#   ./start.sh docker     run the full stack in containers
#   ./start.sh stop       stop whatever is running
#   ./start.sh reset      wipe local data and start fresh
#
# No configuration required. No .env to write. Everything it needs, it creates.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv"
PY="$VENV/bin/python"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
STATE="$ROOT/.aegisdrift"
PIDFILE="$STATE/api.pid"
PORTFILE="$STATE/api.port"
LOGFILE="$STATE/api.log"

# Remember the port a running instance was started on, so a later `./start.sh`
# reports the right URL instead of assuming the default.
if [[ -n "${PORT:-}" ]]; then
  PORT="$PORT"
elif [[ -f "$PORTFILE" ]]; then
  PORT="$(cat "$PORTFILE" 2>/dev/null || echo 8000)"
else
  PORT=8000
fi

MIN_PY_MINOR=11
MIN_NODE_MAJOR=20

# Local HTTPS. The hostname resolves via /etc/hosts and the certificate is issued
# by a locally-trusted mkcert CA, so the browser shows a real padlock with no
# warning. Nothing here is reachable from outside this machine.
SITE_HOST="${SITE_HOST:-aegisdrift.local}"
CERT_DIR="$STATE/certs"
CERT_FILE="$CERT_DIR/$SITE_HOST.pem"
KEY_FILE="$CERT_DIR/$SITE_HOST-key.pem"
HTTPS_PORT="${HTTPS_PORT:-8443}"

# ----------------------------------------------------------------------- output
if [[ -t 1 ]]; then
  B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
  GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; CYAN=$'\033[36m'
else
  B=''; DIM=''; R=''; GREEN=''; YELLOW=''; RED=''; CYAN=''
fi

step() { printf "  ${CYAN}›${R} %s\n" "$1"; }
ok()   { printf "  ${GREEN}✓${R} %s\n" "$1"; }
warn() { printf "  ${YELLOW}!${R} %s\n" "$1"; }
die()  { printf "\n  ${RED}✗ %s${R}\n\n" "$1" >&2; exit 1; }

banner() {
  printf "\n${B}  Aegis Drift${R} ${DIM}— identity threat detection & response${R}\n\n"
}

# ------------------------------------------------------------------ preflight
find_python() {
  # Prefer a modern interpreter; the project needs 3.11+ for the typing it uses.
  local candidate
  for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, $MIN_PY_MINOR) else 1)" 2>/dev/null; then
        echo "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

check_node() {
  command -v node >/dev/null 2>&1 || return 1
  local major
  major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [[ "$major" -ge "$MIN_NODE_MAJOR" ]]
}

# -------------------------------------------------------------------- install
ensure_backend() {
  local python_bin
  if ! python_bin="$(find_python)"; then
    die "Python ${MIN_PY_MINOR}+ is required but was not found.
    macOS:  brew install python@3.12
    Ubuntu: sudo apt install python3.12 python3.12-venv
    Or download from https://www.python.org/downloads/"
  fi

  if [[ ! -x "$PY" ]]; then
    step "Creating the Python environment ($($python_bin -V 2>&1))…"
    "$python_bin" -m venv "$VENV"
    "$PY" -m pip install --quiet --upgrade pip setuptools wheel
  fi

  # A marker keeps repeat runs fast; it is refreshed whenever deps change.
  local stamp="$STATE/.deps-backend"
  if [[ ! -f "$stamp" || "$BACKEND/pyproject.toml" -nt "$stamp" ]]; then
    step "Installing Python dependencies (about a minute the first time)…"
    "$PY" -m pip install --quiet -e "$BACKEND" || die "Could not install Python dependencies."
    mkdir -p "$STATE" && touch "$stamp"
  fi
  ok "Backend ready"
}

ensure_frontend() {
  if ! check_node; then
    warn "Node ${MIN_NODE_MAJOR}+ not found — starting in API-only mode."
    warn "Install Node to get the console: https://nodejs.org"
    return 1
  fi

  local stamp="$STATE/.deps-frontend"
  if [[ ! -d "$FRONTEND/node_modules" || "$FRONTEND/package.json" -nt "$stamp" ]]; then
    step "Installing console dependencies (about a minute the first time)…"
    (cd "$FRONTEND" && npm install --no-audit --no-fund --silent) || die "Could not install console dependencies."
    mkdir -p "$STATE" && touch "$stamp"
  fi

  # Rebuild when any source file is newer than the last build.
  if [[ ! -f "$FRONTEND/dist/index.html" ]] \
     || [[ -n "$(find "$FRONTEND/src" "$FRONTEND/index.html" -newer "$FRONTEND/dist/index.html" -print -quit 2>/dev/null)" ]]; then
    step "Building the console…"
    (cd "$FRONTEND" && npm run build --silent >/dev/null) || die "Console build failed."
  fi
  ok "Console ready"
  return 0
}

# ------------------------------------------------------------ local https
ensure_mkcert() {
  if command -v mkcert >/dev/null 2>&1; then return 0; fi

  printf "\n  mkcert is needed to issue a locally-trusted certificate.\n"
  if ! command -v brew >/dev/null 2>&1; then
    die "mkcert is not installed and Homebrew was not found.
    Install it manually: https://github.com/FiloSottile/mkcert#installation
    Then re-run: ./start.sh secure"
  fi

  step "Installing mkcert via Homebrew…"
  brew install mkcert nss >/dev/null 2>&1 || brew install mkcert >/dev/null 2>&1 \
    || die "brew install mkcert failed. Install it manually and re-run."
  ok "mkcert installed"
}

ensure_local_ca() {
  # -install adds a development root certificate to the system trust store.
  # It is what removes the browser warning, and it only ever signs certificates
  # you generate locally. Remove it later with: mkcert -uninstall
  if mkcert -CAROOT >/dev/null 2>&1 && [[ -f "$(mkcert -CAROOT)/rootCA.pem" ]]; then
    ok "Local certificate authority present"
    return 0
  fi
  warn "Installing a local development certificate authority."
  warn "macOS will ask for your password to add it to the system trust store."
  mkcert -install || die "Could not install the local CA."
  ok "Local certificate authority installed"
}

ensure_certificate() {
  if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
    ok "Certificate for $SITE_HOST present"
    return 0
  fi
  mkdir -p "$CERT_DIR"
  step "Issuing a certificate for $SITE_HOST…"
  ( cd "$CERT_DIR" && mkcert "$SITE_HOST" "*.$SITE_HOST" localhost 127.0.0.1 ::1 >/dev/null 2>&1 ) \
    || die "mkcert could not issue a certificate."

  # mkcert names files after the first host; normalise so the paths are predictable.
  local produced produced_key
  produced="$(find "$CERT_DIR" -name "$SITE_HOST*.pem" ! -name '*-key.pem' | head -1)"
  produced_key="$(find "$CERT_DIR" -name "$SITE_HOST*-key.pem" | head -1)"
  [[ -f "$produced" && -f "$produced_key" ]] || die "Certificate files were not produced as expected."
  [[ "$produced" != "$CERT_FILE" ]] && mv "$produced" "$CERT_FILE"
  [[ "$produced_key" != "$KEY_FILE" ]] && mv "$produced_key" "$KEY_FILE"
  chmod 600 "$KEY_FILE"
  ok "Certificate issued"
}

ensure_hosts_entry() {
  if grep -qE "^[^#]*[[:space:]]$SITE_HOST([[:space:]]|\$)" /etc/hosts 2>/dev/null; then
    ok "$SITE_HOST resolves to this machine"
    return 0
  fi
  warn "Adding '$SITE_HOST' to /etc/hosts — this needs your password."
  printf "  ${DIM}The single line added is:  127.0.0.1 %s${R}\n" "$SITE_HOST"
  printf "127.0.0.1 %s\n::1 %s\n" "$SITE_HOST" "$SITE_HOST" \
    | sudo tee -a /etc/hosts >/dev/null \
    || die "Could not update /etc/hosts. Add this line yourself:  127.0.0.1 $SITE_HOST"
  ok "$SITE_HOST now resolves to this machine"
}

https_running() {
  curl -fsS --max-time 2 "https://$SITE_HOST:$HTTPS_PORT/health/live" >/dev/null 2>&1
}

print_secure_ready() {
  local url="https://$SITE_HOST"
  [[ "$HTTPS_PORT" != "443" ]] && url="$url:$HTTPS_PORT"
  printf "\n"
  printf "  ${B}Console${R}    ${GREEN}%s${R}\n" "$url"
  printf "  ${B}API docs${R}   ${DIM}%s/docs${R}\n" "$url"
  printf "\n"
  printf "  ${DIM}Trusted certificate — the browser shows a padlock, no warning.${R}\n"
  printf "  ${DIM}Resolves only on this machine. Nothing is exposed to the internet.${R}\n"
  printf "\n"
  printf "  ${B}Sign in${R}\n"
  printf "    ${DIM}admin@aegisdrift.com${R}      ChangeMe_Aeg1sDrift!   ${DIM}full access${R}\n"
  printf "    ${DIM}analyst@aegisdrift.com${R}    AnalystDemo_2026!       ${DIM}triage and cases${R}\n"
  printf "    ${DIM}viewer@aegisdrift.com${R}     ViewerDemo_2026!        ${DIM}read only${R}\n"
  printf "\n"
  printf "  ${DIM}Stop:${R}   ./start.sh stop\n\n"
}

start_secure() {
  mkdir -p "$STATE"
  ensure_mkcert
  ensure_local_ca
  ensure_certificate
  ensure_hosts_entry

  if already_running; then
    warn "Stopping the plain-HTTP server first…"
    stop_server >/dev/null 2>&1 || true
  fi

  local sudo_prefix=()
  if [[ "$HTTPS_PORT" == "443" ]]; then
    warn "Port 443 requires root, so the server will run under sudo."
    sudo_prefix=(sudo -E)
  fi

  echo "$HTTPS_PORT" >"$PORTFILE"
  (
    cd "$BACKEND" || exit 1
    PYTHONPATH=. nohup "${sudo_prefix[@]}" "$VENV/bin/uvicorn" app.main:app \
      --host 0.0.0.0 --port "$HTTPS_PORT" \
      --ssl-certfile "$CERT_FILE" --ssl-keyfile "$KEY_FILE" \
      >"$LOGFILE" 2>&1 </dev/null &
    echo $! >"$PIDFILE"
    disown 2>/dev/null || true
  )

  local waited=0
  printf "  ${CYAN}›${R} Starting over HTTPS"
  while (( waited < 180 )); do
    if https_running; then
      printf "\r  ${GREEN}✓${R} Running%*s\n" 40 ""
      print_secure_ready
      [[ "${NO_OPEN:-}" == "1" ]] || {
        local open_url="https://$SITE_HOST"
        [[ "$HTTPS_PORT" != "443" ]] && open_url="$open_url:$HTTPS_PORT"
        command -v open >/dev/null 2>&1 && open "$open_url" >/dev/null 2>&1 || true
      }
      return 0
    fi
    printf "."; sleep 2; waited=$((waited + 2))
  done
  printf "\n"
  printf "${DIM}%s${R}\n" "$(tail -n 20 "$LOGFILE" 2>/dev/null)"
  die "The HTTPS server did not come up. Log: $LOGFILE"
}

unsecure() {
  step "Removing local HTTPS setup…"
  rm -rf "$CERT_DIR"
  if grep -qE "^[^#]*[[:space:]]$SITE_HOST([[:space:]]|\$)" /etc/hosts 2>/dev/null; then
    warn "Removing '$SITE_HOST' from /etc/hosts — needs your password."
    sudo sed -i '' "/[[:space:]]$SITE_HOST\$/d" /etc/hosts 2>/dev/null \
      || sudo sed -i "/[[:space:]]$SITE_HOST\$/d" /etc/hosts 2>/dev/null \
      || warn "Could not edit /etc/hosts; remove the '$SITE_HOST' line yourself."
  fi
  ok "Certificates and hosts entry removed"
  printf "  ${DIM}The mkcert root CA is still trusted. Remove it with: mkcert -uninstall${R}\n\n"
}

# ----------------------------------------------------------------- lifecycle
already_running() {
  [[ -f "$PIDFILE" ]] || return 1
  is_our_server "$(cat "$PIDFILE" 2>/dev/null || true)"
}

port_busy() {
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1
}

wait_for_health() {
  local waited=0
  printf "  ${CYAN}›${R} Starting (first run seeds the demo estate, ~30s)"
  while (( waited < 180 )); do
    if curl -fsS "http://127.0.0.1:${PORT}/health/live" >/dev/null 2>&1; then
      printf "\r  ${GREEN}✓${R} Running%*s\n" 40 ""
      return 0
    fi
    if [[ -f "$PIDFILE" ]] && ! kill -0 "$(cat "$PIDFILE" 2>/dev/null || echo 0)" 2>/dev/null; then
      printf "\n"
      printf "${DIM}%s${R}\n" "$(tail -n 25 "$LOGFILE" 2>/dev/null)"
      die "The server exited during startup. Log: $LOGFILE"
    fi
    printf "."
    sleep 2
    waited=$((waited + 2))
  done
  printf "\n"
  die "Timed out waiting for the server. Log: $LOGFILE"
}

print_ready() {
  local url="http://localhost:${PORT}"
  printf "\n"
  printf "  ${B}Console${R}    ${CYAN}%s${R}\n" "$url"
  printf "  ${B}API docs${R}   ${DIM}%s/docs${R}\n" "$url"
  printf "\n"
  printf "  ${B}Sign in${R}\n"
  printf "    ${DIM}admin@aegisdrift.com${R}      ChangeMe_Aeg1sDrift!   ${DIM}full access${R}\n"
  printf "    ${DIM}analyst@aegisdrift.com${R}    AnalystDemo_2026!       ${DIM}triage and cases${R}\n"
  printf "    ${DIM}viewer@aegisdrift.com${R}     ViewerDemo_2026!        ${DIM}read only${R}\n"
  printf "\n"
  printf "  ${DIM}Try it:${R} open ${B}Threat Simulator${R} and press ${B}Run all scenarios${R}.\n"
  printf "  ${DIM}Logs:${R}   %s\n" "${LOGFILE/#$ROOT\//}"
  printf "  ${DIM}Stop:${R}   ./start.sh stop\n\n"
}

open_browser() {
  local url="http://localhost:${PORT}"
  [[ "${NO_OPEN:-}" == "1" ]] && return 0
  if command -v open >/dev/null 2>&1; then open "$url" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$url" >/dev/null 2>&1 || true
  fi
}

start_server() {
  mkdir -p "$STATE"
  if already_running; then
    ok "Already running on port $PORT"
    print_ready
    open_browser
    return 0
  fi
  if port_busy; then
    die "Port $PORT is already in use by another process.
    Use a different port:  PORT=8010 ./start.sh
    Or stop the other process first."
  fi

  echo "$PORT" >"$PORTFILE"

  # Detach properly: stdin from /dev/null and both streams to the log, so the
  # server never holds this script's terminal open. Without that, `./start.sh`
  # piped into anything hangs forever waiting on a pipe the child still owns.
  (
    cd "$BACKEND" || exit 1
    PYTHONPATH=. nohup "$VENV/bin/uvicorn" app.main:app \
      --host 0.0.0.0 --port "$PORT" >"$LOGFILE" 2>&1 </dev/null &
    echo $! >"$PIDFILE"
    disown 2>/dev/null || true
  )

  wait_for_health
  print_ready
  open_browser
}

start_dev() {
  check_node || die "Hot-reload mode needs Node ${MIN_NODE_MAJOR}+. Use ./start.sh instead."
  mkdir -p "$STATE"
  printf "\n  ${DIM}API on :%s with reload, console on :5173 with HMR. Ctrl-C stops both.${R}\n\n" "$PORT"
  trap 'kill 0' EXIT INT TERM
  ( cd "$BACKEND" && PYTHONPATH=. "$VENV/bin/uvicorn" app.main:app --reload --port "$PORT" ) &
  ( cd "$FRONTEND" && VITE_API_TARGET="http://127.0.0.1:${PORT}" npm run dev ) &
  wait
}

# A recorded PID is only trustworthy if it still belongs to our server; PIDs get
# recycled, and killing a stranger's process would be a genuinely bad outcome.
is_our_server() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || return 1
  ps -o command= -p "$pid" 2>/dev/null | grep -q "uvicorn app.main:app"
}

stop_server() {
  local stopped=0

  if [[ -f "$PIDFILE" ]]; then
    local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if is_our_server "$pid"; then
      kill "$pid" 2>/dev/null || true
      for _ in 1 2 3 4 5; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.4
      done
      kill -9 "$pid" 2>/dev/null || true
      stopped=1
    fi
    rm -f "$PIDFILE" "$PORTFILE"
  fi

  # Catch a server started some other way (directly via uvicorn, say).
  local stray
  for stray in $(pgrep -f "bin/uvicorn app.main:app" 2>/dev/null || true); do
    kill "$stray" 2>/dev/null && stopped=1
  done

  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if [[ -n "$(docker compose ps -q 2>/dev/null)" ]]; then
      docker compose down >/dev/null 2>&1 && stopped=1
    fi
  fi

  [[ "$stopped" == "1" ]] && ok "Stopped" || warn "Nothing was running"
}

start_docker() {
  command -v docker >/dev/null 2>&1 || die "Docker is not installed. See https://docs.docker.com/get-docker/"
  docker info >/dev/null 2>&1 || die "Docker is installed but the daemon is not running. Start Docker Desktop and try again."

  step "Building and starting containers (several minutes the first time)…"
  docker compose up -d --build || die "docker compose failed. See the output above."

  local waited=0
  printf "  ${CYAN}›${R} Waiting for the stack"
  while (( waited < 240 )); do
    if curl -fsS "http://127.0.0.1:8080/health/live" >/dev/null 2>&1; then
      printf "\r  ${GREEN}✓${R} Stack running%*s\n" 30 ""
      printf "\n  ${B}Console${R}  ${CYAN}http://localhost:8080${R}\n"
      printf "  ${B}API${R}      ${DIM}http://localhost:8000/docs${R}\n\n"
      printf "  ${DIM}Logs:${R} docker compose logs -f\n"
      printf "  ${DIM}Stop:${R} ./start.sh stop\n\n"
      return 0
    fi
    printf "."; sleep 3; waited=$((waited + 3))
  done
  printf "\n"
  die "The stack did not become healthy. Check: docker compose logs"
}

reset_data() {
  stop_server
  step "Removing local data…"
  rm -f "$BACKEND/aegisdrift.db" "$LOGFILE"
  ok "Local data cleared — the estate will be regenerated on next start"
}

# ---------------------------------------------------------------------- main
case "${1:-start}" in
  start|"")
    banner
    ensure_backend
    ensure_frontend || true
    start_server
    ;;
  dev)
    banner
    ensure_backend
    ensure_frontend || true
    start_dev
    ;;
  secure|https)
    banner
    ensure_backend
    ensure_frontend || true
    start_secure
    ;;
  unsecure)
    banner
    stop_server >/dev/null 2>&1 || true
    unsecure
    ;;
  docker)
    banner
    start_docker
    ;;
  stop)
    banner
    stop_server
    ;;
  reset)
    banner
    ensure_backend
    reset_data
    start_server
    ;;
  logs)
    tail -f "$LOGFILE"
    ;;
  -h|--help|help)
    banner
    printf "  ${B}./start.sh${R}          install what is missing, then start\n"
    printf "  ${B}./start.sh dev${R}      hot reload for backend and console\n"
    printf "  ${B}./start.sh secure${R}   serve over HTTPS at https://%s\n" "$SITE_HOST"
    printf "  ${B}./start.sh unsecure${R} undo the HTTPS setup\n"
    printf "  ${B}./start.sh docker${R}   full stack in containers\n"
    printf "  ${B}./start.sh stop${R}     stop everything\n"
    printf "  ${B}./start.sh reset${R}    wipe local data and start fresh\n"
    printf "  ${B}./start.sh logs${R}     follow the server log\n\n"
    printf "  ${DIM}PORT=8010 ./start.sh${R}   use a different port\n"
    printf "  ${DIM}NO_OPEN=1 ./start.sh${R}   do not open a browser\n"
    printf "  ${DIM}SITE_HOST=my.site ./start.sh secure${R}   use a different hostname\n"
    printf "  ${DIM}HTTPS_PORT=443 ./start.sh secure${R}      drop the port from the URL (runs under sudo)\n\n"
    ;;
  *)
    die "Unknown command '${1}'. Try: ./start.sh help"
    ;;
esac
