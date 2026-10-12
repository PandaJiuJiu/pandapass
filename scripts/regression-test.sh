#!/usr/bin/env bash
#
# PandaPass pre-push regression test suite.
#
# Runs the full local verification gauntlet before pushing:
#   1. cargo fmt --all --check        (formatting)
#   2. cargo clippy --workspace --all-targets -- -D warnings   (lints)
#   3. cargo test --workspace         (Rust unit + integration tests)
#   4. cd web && npm run build        (Vue type-check + Vite production build)
#   5. Optional: integration e2e — CLI Rust tests (integration/cli) +
#      Playwright browser tests (integration/web)
#
# Usage:
#   ./scripts/regression-test.sh           # run steps 1-4
#   ./scripts/regression-test.sh --e2e      # also run Playwright e2e
#   ./scripts/regression-test.sh --skip-web  # skip web build (Rust only)
#   ./scripts/regression-test.sh --help
#
# Exit codes:
#   0  — everything passed
#   1  — a step failed (the script stops at the first failure)
#   2  — a required tool (cargo/node/npm/playwright) is missing

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_E2E=0
SKIP_WEB=0

for arg in "$@"; do
  case "$arg" in
    --e2e) RUN_E2E=1 ;;
    --skip-web) SKIP_WEB=1 ;;
    --help|-h)
      sed -n '2,24p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--e2e] [--skip-web]" >&2
      exit 2
      ;;
  esac
done

# ── helpers ─────────────────────────────────────────────────────────────────

C_OK=''; C_ERR=''; C_DIM=''; C_OFF=''
if [ -t 1 ]; then
  C_OK='\033[0;32m'; C_ERR='\033[0;31m'; C_DIM='\033[2m'; C_OFF='\033[0m'
fi

step() {
  printf "${C_DIM}==>${C_OFF} %s\n" "$*"
}

pass() {
  printf "${C_OK}✔${C_OFF} %s\n" "$*"
}

fail() {
  printf "${C_ERR}✘${C_OFF} %s\n" "$*"
}

require_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "Required tool '$name' not found in PATH." >&2
    exit 2
  fi
}

# ── 1. formatting ────────────────────────────────────────────────────────────

step "1/4 cargo fmt --all --check"
require_cmd cargo
if cargo fmt --all --check; then
  pass "cargo fmt"
else
  fail "cargo fmt: run 'cargo fmt --all' to fix formatting"
  exit 1
fi

# ── 2. clippy ────────────────────────────────────────────────────────────────

# These lints are pre-existing debt in core signatures (functions taking 8-9
# arguments, inherent `from_str` methods, a complex policy-engine type).
# Refactoring them is tracked separately; exempting them keeps `-D warnings`
# strict for everything else without failing the gate on unrelated refactors.
CLIPPY_ALLOWS=(
  -A clippy::too_many_arguments
  -A clippy::should_implement_trait
  -A clippy::type_complexity
)

step "2/4 cargo clippy --workspace --all-targets -- -D warnings ${CLIPPY_ALLOWS[*]}"
if cargo clippy --workspace --all-targets -- -D warnings "${CLIPPY_ALLOWS[@]}"; then
  pass "cargo clippy"
else
  fail "cargo clippy found warnings (treated as errors)"
  exit 1
fi

# ── 3. Rust tests ───────────────────────────��────────────────────────────────

step "3/4 cargo test --workspace"
if cargo test --workspace; then
  pass "cargo test --workspace"
else
  fail "cargo test --workspace failed"
  exit 1
fi

# ── 4. web build ─────────────────────────────────────────────────────────────

if [ "$SKIP_WEB" -eq 1 ]; then
  step "4/4 web build skipped (--skip-web)"
else
  step "4/4 web type-check + build"
  require_cmd npm
  if [ ! -d web/node_modules ]; then
    step "  installing web dependencies (npm install)"
    (cd web && npm install)
  fi
  if (cd web && npm run build); then
    pass "web build"
  else
    fail "web build failed (vue-tsc or vite)"
    exit 1
  fi
fi

# ── 5. optional Playwright e2e ──────────────────────────────────────────────

if [ "$RUN_E2E" -eq 1 ]; then
  echo
  step "5 (optional) integration e2e"

  # 5a. CLI Rust E2E (boots a real server per test).
  require_cmd cargo
  if cargo test --manifest-path integration/cli/Cargo.toml; then
    pass "cli integration tests"
  else
    fail "cli integration tests failed"
    exit 1
  fi

  # 5b. Web Playwright e2e.
  require_cmd npx
  if [ ! -d integration/web/node_modules ]; then
    step "  installing integration/web dependencies (npm install)"
    (cd integration/web && npm install)
  fi
  if (cd integration/web && npx playwright install chromium >/dev/null 2>&1); then
    :
  else
    echo "  (playwright browser already installed or install skipped)" >&2
  fi
  if (cd integration/web && npm run e2e); then
    pass "playwright e2e"
  else
    fail "playwright e2e failed"
    exit 1
  fi
fi

echo
printf "${C_OK}All regression checks passed.${C_OFF}\n"