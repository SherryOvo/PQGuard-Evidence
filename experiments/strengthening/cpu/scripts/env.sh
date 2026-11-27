#!/usr/bin/env bash
export ROOT="$HOME/pqguard_review_strengthening_20261124"
export OQS_INSTALL_PATH="$HOME/pqguard_cpu_followup_20261012_run1/oqs_install"
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib:${LD_LIBRARY_PATH:-}"
export PYTHONPATH="$ROOT/vendor:$ROOT/scripts"
export PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
export PYTHON="$HOME/pqguard_cpu_followup_20261012_run1/venv/bin/python"
