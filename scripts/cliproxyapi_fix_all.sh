#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
AUTH_DIR="${CLIPROXYAPI_DIR:-$HOME/.cli-proxy-api}"
DEDUPE="$ROOT/scripts/cliproxyapi_dedupe_codex_subscriptions.py"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: cliproxyapi_fix_all.sh [--dry-run]

Safely deduplicate CLIProxyAPI Codex credentials, quarantine explicitly
disabled credentials outside auth-dir, optionally reconcile Codex aliases,
and restart the Homebrew service.

Options:
  --dry-run  Preview file and alias changes without restarting CLIProxyAPI.
  -h, --help Show this help.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

resolve_executable() {
  local label="$1"
  local requested="$2"
  shift 2
  local resolved=""
  local fallback=""

  if [[ "$requested" == */* ]]; then
    if [[ -x "$requested" ]]; then
      printf '%s\n' "$requested"
      return 0
    fi
  else
    resolved="$(command -v "$requested" 2>/dev/null || true)"
    if [[ -n "$resolved" && -x "$resolved" ]]; then
      printf '%s\n' "$resolved"
      return 0
    fi
  fi

  for fallback in "$@"; do
    if [[ -x "$fallback" ]]; then
      printf '%s\n' "$fallback"
      return 0
    fi
  done

  echo "ERROR: $label executable not found: $requested" >&2
  return 1
}

PY_REQUESTED="${CLIPROXYAPI_PYTHON_BIN:-${QLAB_PYTHON_BIN:-}}"
if [[ -n "$PY_REQUESTED" ]]; then
  PY="$(resolve_executable "Python" "$PY_REQUESTED")" || exit 2
else
  PY="$(resolve_executable "Python" "python3" /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3)" || exit 2
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
  if [[ -n "${CLIPROXYAPI_BREW_BIN:-}" ]]; then
    BREW="$(resolve_executable "Homebrew" "$CLIPROXYAPI_BREW_BIN")" || exit 2
  else
    BREW="$(resolve_executable "Homebrew" "brew" /opt/homebrew/bin/brew /usr/local/bin/brew)" || exit 2
  fi
else
  BREW="${CLIPROXYAPI_BREW_BIN:-brew}"
fi

if [[ ! -f "$DEDUPE" ]]; then
  echo "ERROR: dedupe helper not found: $DEDUPE" >&2
  exit 2
fi

run_dedupe() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    "$PY" "$DEDUPE" --dir "$AUTH_DIR" --dry-run
  else
    "$PY" "$DEDUPE" --dir "$AUTH_DIR"
  fi
}

guard_reconciliation() {
  local phase="$1"
  local guard_rc=0

  set +e
  "$PY" "$DEDUPE" --dir "$AUTH_DIR" --check-single-failures
  guard_rc=$?
  set -e

  if [[ "$guard_rc" -eq 10 ]]; then
    cat >&2 <<EOF
SAFETY STOP ($phase): an unusable lone credential remains in $AUTH_DIR.
Safe duplicate cleanup completed, but Codex auth/alias reconciliation and the
CLIProxyAPI restart were skipped. Re-login or move/delete the unusable file
outside auth-dir, then run cliproxyapi-fix-all again.
EOF
    exit 10
  elif [[ "$guard_rc" -ne 0 ]]; then
    echo "ERROR: credential safety check failed with exit code $guard_rc" >&2
    exit "$guard_rc"
  fi
}

echo "[1/4] Cleaning duplicate and disabled CLIProxyAPI credentials..."
run_dedupe
guard_reconciliation "before auth reconciliation"

AUTH_FIX="${CLIPROXYAPI_AUTH_FIX_SCRIPT:-}"
if [[ -z "$AUTH_FIX" ]]; then
  echo "[2/4] Skipping optional Codex auth reconciliation (set CLIPROXYAPI_AUTH_FIX_SCRIPT to enable)."
elif [[ ! -x "$AUTH_FIX" ]]; then
  echo "[2/4] WARN: configured Codex auth helper not found; skipping: $AUTH_FIX" >&2
elif [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[2/4] Previewing Codex auth/alias reconciliation..."
  "$AUTH_FIX" --dry-run --reconcile
else
  echo "[2/4] Reconciling Codex auth/aliases..."
  "$AUTH_FIX" --reconcile --status
fi

echo "[3/4] Rechecking credentials after reconciliation..."
run_dedupe
guard_reconciliation "after auth reconciliation"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[4/4] DRY-RUN: would run: $BREW services restart cliproxyapi"
  echo "Preview complete; no service restart was performed."
else
  echo "[4/4] Restarting CLIProxyAPI..."
  "$BREW" services restart cliproxyapi
  echo "CLIProxyAPI repair completed successfully."
fi
