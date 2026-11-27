#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
mkdir -p logs state
# Locks live inside each process; a duplicate launcher exits without competing.
nohup setsid "$PYTHON" -u scripts/tunnel_guard.py </dev/null >>logs/tunnel_guard.log 2>&1 &
nohup setsid "$PYTHON" -u scripts/wait_gpu_window.py </dev/null >>logs/gpu_window.log 2>&1 &
echo 'CPU audit/time/resource-gated waiter requested; GPU not enabled by this script.'
