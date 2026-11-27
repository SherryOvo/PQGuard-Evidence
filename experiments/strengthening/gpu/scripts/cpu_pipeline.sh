#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/env.sh
"$PYTHON" -u scripts/run_cpu_suite.py
"$PYTHON" -u scripts/audit_cpu.py
