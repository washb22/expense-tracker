#!/usr/bin/env bash
set -euo pipefail

test_root="$(mktemp -d)"
stack_pid=""
child_pids=()

cleanup() {
  if [[ -n "$stack_pid" ]] && kill -0 "$stack_pid" 2>/dev/null; then
    kill -TERM "$stack_pid" 2>/dev/null || true
    wait "$stack_pid" 2>/dev/null || true
  fi
  rm -rf "$test_root"
}
trap cleanup EXIT

export DATABASE_URL="sqlite:///$test_root/moneylog-fixture.db"
export PORT=18765

start_stack() {
  bash scripts/start_production.sh >"$test_root/stack.log" 2>&1 &
  stack_pid=$!
  for _ in $(seq 1 60); do
    if curl --fail --silent "http://127.0.0.1:$PORT/login" >/dev/null; then
      break
    fi
    if ! kill -0 "$stack_pid" 2>/dev/null; then
      cat "$test_root/stack.log"
      return 1
    fi
    sleep 0.25
  done
  curl --fail --silent "http://127.0.0.1:$PORT/login" >/dev/null

  mapfile -t child_pids < <(pgrep -P "$stack_pid")
  [[ "${#child_pids[@]}" -eq 2 ]]
  [[ "$(pgrep -P "$stack_pid" -af 'scripts/run_scheduler.py' | wc -l)" -eq 1 ]]
  [[ "$(pgrep -P "$stack_pid" -af 'gunicorn.*app:app' | wc -l)" -eq 1 ]]
}

stop_stack() {
  local pid
  kill -TERM "$stack_pid"
  wait "$stack_pid" || true
  for pid in "${child_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      echo "orphan child remained after SIGTERM: $pid" >&2
      return 1
    fi
  done
  stack_pid=""
  child_pids=()
}

# First start validates HTTP, one scheduler and graceful SIGTERM.
start_stack
stop_stack

# A full restart must still produce exactly one scheduler and no stale child.
start_stack
stop_stack

echo "LINUX_START_TEST_PASS"
