#!/bin/bash
# Environment setup for the PQGuard GPU experiments.
#
# The preserved runs used Python 3.12.3, PyTorch 2.5.1+cu124 and
# Transformers 4.57.6. Pin the same versions so the new numbers are comparable
# with the existing ones; record anything that differs.
set -euo pipefail

PY=${PY:-python3}
VENV=${VENV:-$HOME/pqguard-gpu-venv}

echo "=== python ==="
$PY --version

echo "=== creating venv at $VENV ==="
$PY -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --upgrade pip wheel

# Torch first; the index URL matters for the CUDA build.
echo "=== installing torch (cu124 pin, matching the preserved runs) ==="
pip install "torch==2.5.1" --index-url https://download.pytorch.org/whl/cu124

echo "=== installing transformers and helpers ==="
pip install "transformers==4.57.6" "accelerate" "huggingface_hub" "safetensors"

echo "=== verifying ==="
python - <<'PY'
import torch, transformers
print(f"torch {torch.__version__}  transformers {transformers.__version__}")
print(f"cuda available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"device: {torch.cuda.get_device_name(0)}")
    print(f"capability: {torch.cuda.get_device_capability(0)}")
    print(f"memory: {torch.cuda.get_device_properties(0).total_memory/1e9:.1f} GB")
PY

echo
echo "=== note on the audit signature backend ==="
echo "The GPU serving measurement counts audit work; it does not itself sign with"
echo "SPHINCS+. If you also want the signing cost on this host, install liboqs:"
echo "    pip install liboqs-python"
echo "(liboqs-python builds liboqs on first use; that takes several minutes)"
echo
echo "done. activate with: source $VENV/bin/activate"
