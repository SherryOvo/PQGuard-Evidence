#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "${SSH_ORIGINAL_COMMAND:-status}" in
 status) cat "$ROOT/state/CPU_STATUS.json" "$ROOT/state/GPU_STATUS.json" 2>/dev/null || true ;;
 start_gpu) source "$ROOT/scripts/env.sh"; python "$ROOT/scripts/gpu_time_gate.py"; mkdir -p "$ROOT/logs"; nohup setsid python -u "$ROOT/scripts/run_gpu_joint.py" </dev/null >>"$ROOT/logs/gpu_controller.log" 2>&1 & echo "LAUNCH_REQUESTED" ;;
 *) echo 'Unsupported experiment-only command'; exit 64 ;;
esac
