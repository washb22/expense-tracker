#!/usr/bin/env bash
set -euo pipefail

python scripts/run_scheduler.py &
scheduler_pid=$!
gunicorn --bind "0.0.0.0:${PORT}" --timeout 120 app:app &
web_pid=$!

cleanup() {
  kill "$scheduler_pid" 2>/dev/null || true
  kill "$web_pid" 2>/dev/null || true
  wait "$scheduler_pid" 2>/dev/null || true
  wait "$web_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait -n "$scheduler_pid" "$web_pid"
