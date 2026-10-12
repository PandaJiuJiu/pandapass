#!/usr/bin/env bash
#
# PandaPass local development launcher.
#
# Manages the Rust server (port 18233) and the Vite web dev server (port
# 15173) in the background, bound to 0.0.0.0 so a browser on another
# machine on the LAN can reach them. State lives under .run/ (pid files,
# logs, data dir).
#
# Usage:
#   ./run.sh start    — start server + vite (initialises data on first run)
#   ./run.sh stop     — stop both
#   ./run.sh restart  — stop, then start
#   ./run.sh status   — print whether each is up and the pid
#   ./run.sh logs     — tail both logs (Ctrl-C to exit)
#   ./run.sh health   — probe /api/v1/health
#   ./run.sh init     — generate server age identity + empty db, then exit
#   ./run.sh clean    — remove .run/ entirely (deletes server identity + db)
#
# Both processes log to .run/{server,vite}.log. Pids live in .run/{server,vite}.pid.
#
# Environment overrides:
#   PANDAPASS_PORT=NNNN         server listen port (default 18233)
#   PANDAPASS_VITE_PORT=NNNN    vite dev port (default 15173)
#   PANDAPASS_BIND=127.0.0.1    bind loopback only (default 0.0.0.0)
#
# Note: ports must be <= 65535 (TCP u16 limit). The server's health-check
# uses u16::from_str on the configured port, so values like 88233 (>65535)
# are rejected at startup.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$ROOT/.run"
DATA_DIR="$RUN_DIR/data"
SERVER_PID="$RUN_DIR/server.pid"
VITE_PID="$RUN_DIR/vite.pid"
SERVER_LOG="$RUN_DIR/server.log"
VITE_LOG="$RUN_DIR/vite.log"
SERVER_BIN="$ROOT/target/debug/pandapass-server"
SERVER_AGE_FILE="$DATA_DIR/server.age"
SERVER_PORT="${PANDAPASS_PORT:-18233}"
VITE_PORT="${PANDAPASS_VITE_PORT:-15173}"
# Bind address. 0.0.0.0 makes the services reachable from the LAN. Override
# with PANDAPASS_BIND=127.0.0.1 to keep things loopback-only.
BIND_ADDR="${PANDAPASS_BIND:-0.0.0.0}"

# Colours for status output (disabled when not a tty).
if [ -t 1 ]; then
  C_OK='\033[0;32m'; C_ERR='\033[0;31m'; C_DIM='\033[2m'; C_OFF='\033[0m'
else
  C_OK=''; C_ERR=''; C_DIM=''; C_OFF=''
fi

log() { printf "${C_DIM}[run.sh]${C_OFF} %s\n" "$*"; }
err() { printf "${C_ERR}[run.sh]${C_OFF} %s\n" "$*" >&2; }

# ── helpers ─────────────────────────────────────────────────────────────────

alive() {
  # $1 = pid file path. Returns 0 if the recorded pid is a running process
  # owned by us and matching our binary / node command.
  local f="$1"
  [ -f "$f" ] || return 1
  local pid; pid="$(cat "$f")"
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  return 0
}

stop_pidfile() {
  local name="$1" f="$2" sig="${3:-TERM}"
  if alive "$f"; then
    local pid; pid="$(cat "$f")"
    log "stopping $name (pid=$pid, signal=$sig)"
    kill "-$sig" "$pid" 2>/dev/null || true
    # Give it a moment, then force-kill if still up.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.2
    done
    if kill -0 "$pid" 2>/dev/null; then
      log "$name still alive after SIGTERM, sending SIGKILL"
      kill -9 "$pid" 2>/dev/null || true
    fi
  else
    log "$name not running (stale pid file removed)"
  fi
  rm -f "$f"
}

# ── init ─────────────────────────────────────────────────────────────────────

ensure_run_dir() {
  mkdir -p "$RUN_DIR" "$DATA_DIR"
}

init_storage() {
  ensure_run_dir
  if [ -f "$SERVER_AGE_FILE" ]; then
    log "server age identity already present"
    chmod 600 "$SERVER_AGE_FILE" 2>/dev/null || true
    return 0
  fi

  # Clean up any orphan processes on the server port first.
  cleanup_port "$SERVER_PORT"

  # `--init-only` generates the age identity and exits immediately (unlike
  # `--init`, which falls through into normal server startup for the Docker
  # image). We run it synchronously and wait for the file to appear.
  log "generating server age identity at $SERVER_AGE_FILE"
  PANDAPASS_LISTEN="127.0.0.1:$SERVER_PORT" \
  PANDAPASS_DB_URL="sqlite://$DATA_DIR/pandapass.db?mode=rwc" \
  PANDAPASS_SERVER_AGE_IDENTITY_FILE="$SERVER_AGE_FILE" \
  PANDAPASS_PUBLIC_URL="http://localhost:$VITE_PORT" \
  "$SERVER_BIN" --init-only >>"$SERVER_LOG" 2>&1

  if [ ! -f "$SERVER_AGE_FILE" ]; then
    err "server age identity was not written; check server logs"
    return 1
  fi
  chmod 600 "$SERVER_AGE_FILE" 2>/dev/null || true
}

ensure_built() {
  if [ ! -x "$SERVER_BIN" ]; then
    err "binary missing: $SERVER_BIN"
    err "run: cargo build -p pandapass-server"
    exit 1
  fi
}

ensure_web_deps() {
  if [ ! -d "$ROOT/web/node_modules" ]; then
    log "installing web deps (npm install)"
    (cd "$ROOT/web" && npm install) >/dev/null
  fi
}

# Pick the first non-loopback IPv4 we can find. Used to set PUBLIC_URL so that
# cookies / redirects behave when the browser connects from another machine on
# the LAN rather than localhost.
detect_lan_ip() {
  ip -4 -o addr show scope global 2>/dev/null \
    | awk '{print $4}' | cut -d/ -f1 \
    | grep -v '^127\.' | grep -v '^10\.' | grep -v '^172\.' \
    | head -n1
}

# Check if the server port is free (no LISTEN on BIND_ADDR:PORT or 0.0.0.0:PORT).
# Returns 0 if free, 1 if occupied.
port_free() {
  local port="$1"
  local addr="${2:-$BIND_ADDR}"
  # Check both the specific bind address and 0.0.0.0 (since a process on
  # 127.0.0.1:PORT blocks 0.0.0.0:PORT and vice versa on Linux).
  if ss -ltn 2>/dev/null | grep -qE "[:.]${port} "; then
    # Filter to only our bind address or 0.0.0.0
    local listeners
    listeners=$(ss -ltn 2>/dev/null | grep -E "[:.]${port} ")
    if echo "$listeners" | grep -qE "(^| )(${addr}|0\.0\.0\.0|127\.0\.0\.1):${port} "; then
      return 1
    fi
  fi
  return 0
}

# Kill any process listening on the server port that isn't ours.
# This cleans up orphaned --init-only processes from previous runs.
cleanup_port() {
  local port="$1"
  local pids
  # fuser -k would be simpler but not always available; use lsof + kill.
  pids=$(lsof -ti :"$port" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    log "cleaning up orphan processes on port $port: $pids"
    kill -TERM $pids 2>/dev/null || true
    sleep 0.5
    pids=$(lsof -ti :"$port" 2>/dev/null || true)
    if [ -n "$pids" ]; then
      kill -KILL $pids 2>/dev/null || true
    fi
  fi
}

# ── commands ─────────────────────────────────────────────────────────────────

cmd_start() {
  ensure_built
  ensure_web_deps
  ensure_run_dir
  init_storage

  # Clean up any orphan processes on the server port before starting.
  cleanup_port "$SERVER_PORT"

  # Verify the port is free; if not, fail fast with a clear message.
  if ! port_free "$SERVER_PORT"; then
    err "port $SERVER_PORT is still in use after cleanup; cannot start server"
    err "run 'lsof -i :$SERVER_PORT' to investigate, or stop conflicting services"
    return 1
  fi

  local lan_ip
  lan_ip="$(detect_lan_ip)"
  local public_url="http://localhost:$VITE_PORT"
  if [ -n "$lan_ip" ] && [ "$BIND_ADDR" != "127.0.0.1" ]; then
    public_url="http://$lan_ip:$VITE_PORT"
  fi

  # Server.
  if alive "$SERVER_PID"; then
    log "server already running (pid=$(cat "$SERVER_PID"))"
  else
    log "starting server on ${BIND_ADDR}:${SERVER_PORT} (public=${public_url}, log → $SERVER_LOG)"
    : > "$SERVER_LOG"
    (
      cd "$ROOT"
      PANDAPASS_LISTEN="${BIND_ADDR}:${SERVER_PORT}" \
      PANDAPASS_DB_URL="sqlite://$DATA_DIR/pandapass.db?mode=rwc" \
      PANDAPASS_SERVER_AGE_IDENTITY_FILE="$SERVER_AGE_FILE" \
      PANDAPASS_PUBLIC_URL="$public_url" \
      RUST_LOG="${RUST_LOG:-pandapass_server=info,tower_http=info}" \
      nohup "$SERVER_BIN" >>"$SERVER_LOG" 2>&1 &
      echo $! > "$SERVER_PID"
    )
  fi

  # Vite dev server.
  if alive "$VITE_PID"; then
    log "vite already running (pid=$(cat "$VITE_PID"))"
  else
    log "starting vite dev server on ${BIND_ADDR}:${VITE_PORT} (log → $VITE_LOG)"
    : > "$VITE_LOG"
    (
      cd "$ROOT/web"
      nohup npm run dev -- --port "$VITE_PORT" --strictPort \
        --host "$BIND_ADDR" >>"$VITE_LOG" 2>&1 &
      echo $! > "$VITE_PID"
    )
  fi

  # Wait briefly for the server to bind so callers know when to hit it.
  log "waiting for server health on :$SERVER_PORT…"
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if curl -sf "http://127.0.0.1:$SERVER_PORT/api/v1/health" >/dev/null 2>&1; then
      printf "${C_OK}ready${C_OFF}\n"
      cmd_status
      return 0
    fi
    sleep 0.5
  done
  err "server did not become healthy within 7.5s; tail $SERVER_LOG"
  return 1
}

cmd_stop() {
  stop_pidfile vite    "$VITE_PID"
  stop_pidfile server  "$SERVER_PID"
  log "stopped"
}

cmd_restart() {
  cmd_stop || true
  cmd_start
}

cmd_status() {
  local any=0
  for entry in "server:$SERVER_PID:http://127.0.0.1:$SERVER_PORT/api/v1/health" \
               "vite:$VITE_PID:http://127.0.0.1:$VITE_PORT/"; do
    IFS=: read -r name pidfile health <<<"$entry"
    if alive "$pidfile"; then
      printf "${C_OK}●${C_OFF} %-7s up   pid=%-6s health=%s\n" \
        "$name" "$(cat "$pidfile")" "$health"
      any=1
    else
      printf "${C_DIM}○${C_OFF} %-7s down (no live pid at %s)\n" "$name" "$pidfile"
    fi
  done
  # Exit 0 only if both are up; otherwise exit 1 so callers can branch.
  [ "$any" -eq 1 ] || exit 1
}

cmd_logs() {
  if [ ! -f "$SERVER_LOG" ] && [ ! -f "$VITE_LOG" ]; then
    err "no logs yet; run start first"
    exit 1
  fi
  # Tail both. exit code reflects the first to die.
  tail -n +1 -F "$SERVER_LOG" "$VITE_LOG"
}

cmd_health() {
  local url="http://127.0.0.1:$SERVER_PORT/api/v1/health"
  log "GET $url"
  if curl -fsS "$url"; then
    log "${C_OK}healthy${C_OFF}"
  else
    err "${C_ERR}unhealthy${C_OFF}"
    return 1
  fi
}

cmd_init() {
  ensure_built
  ensure_run_dir
  init_storage
  log "data dir: $DATA_DIR"
}

cmd_clean() {
  while true; do
    err "this will delete $RUN_DIR (server identity + db)."
    read -rp "type 'y' or 'yes' to confirm, or ctrl-c to cancel: " confirm
    case "${confirm,,}" in
      y|yes)
        break
        ;;
      *)
        log "confirmation required: please type 'y' or 'yes'"
        ;;
    esac
  done
  cmd_stop || true
  rm -rf "$RUN_DIR"
  log "cleaned $RUN_DIR"
}

cmd_help() {
  sed -n '2,17p' "$0"
}

# ── entry ────────────────────────────────────────────────────────────────────

cmd="${1:-help}"
shift || true

case "$cmd" in
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  restart) cmd_restart ;;
  status)  cmd_status ;;
  logs)    cmd_logs ;;
  health)  cmd_health ;;
  init)    cmd_init ;;
  clean)   cmd_clean ;;
  help|-h|--help) cmd_help ;;
  *) err "unknown command: $cmd"; cmd_help; exit 2 ;;
esac