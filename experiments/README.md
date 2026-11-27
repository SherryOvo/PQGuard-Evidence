# Experiment and verification scripts

This directory contains scripts exported from the current journal reproducibility-code bundle. The recorded campaign implementations are retained without changing their measurement logic. It contains no model weights, raw evidence archives, manuscript sources, credentials, or generated signing keys.

## Layout

- `current/cpu/`: feature-matched CPU experiment and verification.
- `current/gpu/`: continuous-batching GPU runner, lifecycle stores, scheduler logging and artifact verification.
- `current/remote_witness/`: two-host witness experiment, worker and verification.
- `current/derive_results.py`, `current/plot_results.py`: primary evidence reanalysis and plotting.
- `strengthening/cpu/`: signed-object controls and CPU state/failure extensions.
- `strengthening/gpu/`: joint GPU/local-or-remote-witness campaign, preparation, bounded controllers and independent audits.
- `strengthening/analysis/`: joint-campaign public analysis.
- `component_sources/`: historical component benchmarks. These use campaign-specific software and are not interchangeable with the current implementations.
- `analysis_source/`: security-evidence figure analysis.

## Dependencies and execution boundaries

The retained environment/package manifests identify the recorded campaign versions. Current campaigns use Python 3.12 and liboqs/liboqs-python 0.16; historical scripts can require older algorithm identifiers and versions. GPU campaigns additionally require a CUDA-compatible PyTorch/Transformers/vLLM environment and the separately acquired Qwen model snapshot. Plotting requires NumPy and Matplotlib. Install upstream liboqs-python separately: the bundled third-party `vendor/deps/oqs` copy is deliberately not redistributed here.

These are recorded research scripts, not a one-command deployment package. Some launchers retain the original local `/root/autodl-tmp/...` workspace paths and expect preparation/status/hash manifests from their evidence archive. Configure local paths, native-library locations, model files, working directories and CPU affinity for your host before execution. Remote-witness launchers expect a locally supplied `private/link.json`, SSH key and pinned known-hosts file; these are not published. Do not remove their source-hash/preflight checks merely to bypass a missing preparation artifact. Analyze evidence on working copies, since SQLite verification can checkpoint WALs.

## Reanalyze the primary campaigns

After separately extracting the relevant CPU, GPU and formal evidence archives, replace the paths below with their absolute locations:

```bash
python experiments/current/derive_results.py \
  --cpu /absolute/PQGuard_CPU_Evidence/strong_baseline \
  --witness /absolute/PQGuard_CPU_Evidence/two_host_witness \
  --gpu /absolute/PQGuard_GPU_Evidence/continuous_batching \
  --formal /absolute/PQGuard_Formal_Artifacts/current \
  --output /absolute/analysisOutput
python experiments/current/plot_results.py \
  --analysis-output /absolute/analysisOutput \
  --figure-output /absolute/figureOutput
```

The scripts require their matching retained data; source publication does not imply that fresh experiments were rerun. Verification here covered Python parsing, shell syntax, publish-safety patterns and source checksums, not a fresh CPU/GPU/prover execution.

## Source integrity

```bash
cd experiments
shasum -a 256 -c SHA256SUMS
```

The root `SHA256SUMS.txt` remains the checksum list for the separately released evidence ZIPs. `experiments/SHA256SUMS` covers this script tree. The two lists serve different artifacts.
