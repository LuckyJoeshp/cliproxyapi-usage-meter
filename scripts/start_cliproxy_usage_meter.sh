#!/usr/bin/env bash
set -euo pipefail

WORK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${QLAB_PYTHON_BIN:-python3}"
METER_PORT="${PORT:-8327}"
METER_UPSTREAM="${UPSTREAM:-http://127.0.0.1:8317}"
METER_DB="${CLIPROXY_USAGE_DB:-${WORK_ROOT}/datas/cliproxy_usage.sqlite}"
METER_HOST="${CLIPROXY_USAGE_HOST:-127.0.0.1}"

exec "${PYTHON_BIN}" "${WORK_ROOT}/scripts/cliproxy_usage_meter.py" \
  --serve \
  --host "${METER_HOST}" \
  --port "${METER_PORT}" \
  --upstream "${METER_UPSTREAM}" \
  --db "${METER_DB}"
