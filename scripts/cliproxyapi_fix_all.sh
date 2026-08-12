#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${QLAB_PYTHON_BIN:-python3}"
AUTH_DIR="${CLIPROXYAPI_DIR:-$HOME/.cli-proxy-api}"
DEDUPE="$ROOT/scripts/cliproxyapi_dedupe_codex_subscriptions.py"

if [[ ! -x "$PY" ]]; then
  echo "ERROR: fixed Python not found: $PY" >&2
  exit 2
fi

# First resolve true duplicates.  This operation never removes a lone failed
# file; it only deletes/archives a failed file when a same-email peer exists.
"$PY" "$DEDUPE" --dir "$AUTH_DIR"

# A lone failed record is the operator's re-login handle.  Stop before the
# legacy Codex-home reconciler can compact aliases or overwrite that mapping.
set +e
"$PY" "$DEDUPE" --dir "$AUTH_DIR" --check-single-failures
guard_rc=$?
set -e
if [[ "$guard_rc" -eq 10 ]]; then
  echo "Skipping Codex auth reconciliation: lone failed subscription preserved."
  brew services restart cliproxyapi
  exit 0
elif [[ "$guard_rc" -ne 0 ]]; then
  exit "$guard_rc"
fi

# Optional Codex-home compatibility synchronizer.  It is intentionally opt-in:
# this public helper must never assume or reveal a maintainer's local path.
AUTH_FIX="${CLIPROXYAPI_AUTH_FIX_SCRIPT:-}"
if [[ -z "$AUTH_FIX" ]]; then
  echo "Skipping optional Codex auth reconciliation (set CLIPROXYAPI_AUTH_FIX_SCRIPT to enable)."
elif [[ ! -x "$AUTH_FIX" ]]; then
  echo "WARN: configured Codex auth helper not found; skipping: $AUTH_FIX" >&2
else
  "$AUTH_FIX" --reconcile --status
fi

# The compatibility helper may observe a login-created duplicate while it is
# running.  Re-run the guarded cleanup before the final service reload.
"$PY" "$DEDUPE" --dir "$AUTH_DIR"
brew services restart cliproxyapi
