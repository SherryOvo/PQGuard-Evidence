#!/usr/bin/env bash
set -euo pipefail

EXP=${EXP:-"$PWD/pqguard_tifs_a800"}
OQS_PREFIX=${OQS_PREFIX:-/usr/local}
export EXP
MODEL="$EXP/models/Qwen2.5-14B-Instruct"
RESULTS="$EXP/results"
LOGS="$EXP/logs"
SRC="$EXP/src"
VENV="$EXP/venv"
STATUS="$LOGS/suite_status.log"

mkdir -p "$RESULTS" "$LOGS"
source "$VENV/bin/activate"
export LD_LIBRARY_PATH="$OQS_PREFIX/lib:${LD_LIBRARY_PATH:-}"
export TOKENIZERS_PARALLELISM=false
export PYTHONUNBUFFERED=1

note() {
  printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$STATUS"
}

wait_for_pid_file() {
  local pid_file=$1
  local label=$2
  local pid
  pid=$(cat "$pid_file")
  while kill -0 "$pid" 2>/dev/null; do
    note "$label still running pid=$pid"
    sleep 60
  done
  note "$label process exited pid=$pid"
}

note "suite monitor started"
wait_for_pid_file "$EXP/model_download.pid" "model download"
wait_for_pid_file "$EXP/cpu_batch.pid" "CPU batch matrix"

weight_count=$(find "$MODEL" -maxdepth 1 -name 'model-*.safetensors' | wc -l | tr -d ' ')
model_bytes=$(du -sb "$MODEL" | awk '{print $1}')
if [[ "$weight_count" -ne 8 || "$model_bytes" -lt 25000000000 ]]; then
  note "model validation failed: weights=$weight_count bytes=$model_bytes"
  exit 20
fi
for batch in 10 50 100; do
  if [[ ! -s "$RESULTS/cpu_batch_${batch}.json" ]]; then
    note "missing CPU batch result for batch_size=$batch"
    exit 21
  fi
done
note "prerequisite artifacts validated"

note "starting admission read/digest decomposition"
python "$SRC/gpu_admission_benchmark.py" \
  --artifacts "$MODEL" --trials 3 --availability-trials 0 \
  --out "$RESULTS/admission" > "$LOGS/admission.log" 2>&1
note "admission decomposition complete"

note "starting integrated GPU smoke run"
python "$SRC/a800_integrated_pqguard_benchmark.py" \
  --model "$MODEL" --blocks 10 --warmup 1 --max-new-tokens 8 \
  --batch-size 10 --output "$RESULTS/gpu_smoke" \
  > "$LOGS/gpu_smoke.log" 2>&1
note "integrated GPU smoke run complete"

python - <<'PY'
import json
import os
from pathlib import Path
p = Path(os.environ['EXP']) / 'results/gpu_smoke/integrated_results.json'
x = json.loads(p.read_text())
assert all(v is True for k, v in x['validation'].items() if isinstance(v, bool)), x['validation']
print(x['validation'])
PY

note "starting 100-block Qwen2.5-14B BF16 integrated run"
python "$SRC/a800_integrated_pqguard_benchmark.py" \
  --model "$MODEL" --blocks 100 --warmup 5 --max-new-tokens 64 \
  --batch-size 10 --bootstrap-resamples 10000 \
  --seed 20261005 --output "$RESULTS/gpu_full" \
  > "$LOGS/gpu_full.log" 2>&1
note "integrated GPU run complete"

python - <<'PY'
import json
import os
from pathlib import Path
p = Path(os.environ['EXP']) / 'results/gpu_full/integrated_results.json'
x = json.loads(p.read_text())
assert all(v is True for k, v in x['validation'].items() if isinstance(v, bool)), x['validation']
assert x['audit']['counters']['entry_signatures'] == 100
assert x['audit']['counters']['checkpoint_signatures'] == 10
print(json.dumps({'paired': x['paired'], 'validation': x['validation']}, indent=2))
PY

note "building evidence manifest"
(
  cd "$EXP"
  find src results logs env -type f -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS.txt
  tar -czf pqguard_a800_tifs_evidence_20261005.tar.gz \
    src results logs env SHA256SUMS.txt
)
touch "$EXP/SUITE_COMPLETE"
note "suite complete"
