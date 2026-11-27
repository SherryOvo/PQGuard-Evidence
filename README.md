# PQGuard raw evidence

Raw evidence archives for the PQGuard post-quantum continuous-batching auditable-serving study.

These archives are released **as supporting evidence**, not as an upload package. They are the same files
prepared for the journal supplementary material, hosted here because each exceeds the submission system's
per-file upload limit (~450 MB observed).

## Contents

| Archive | Bytes | SHA-256 |
|---|---|---|
| `pqGuardEsm4CpuEvidence.zip` | 808,255,378 | `e4312861d6ec2527d4829de06d9193f294dd3cf05680ed06cfde60e2e1bcb0de` |
| `pqGuardEsm6GpuEndToEndEvidence.zip` | 790,967,908 | `2bf98f5b3b2d6b4120c817af175863dac92c61c815fbba665848d59444b2cd82` |

Download both from the [release assets](../../releases).

## Verification

```bash
unzip -tq pqGuardEsm4CpuEvidence.zip
unzip -tq pqGuardEsm6GpuEndToEndEvidence.zip
cd PQGuard_CPU_Evidence   # after extraction
shasum -a 256 -c SHA256SUMS
cd ../PQGuard_GPU_Evidence
shasum -a 256 -c SHA256SUMS
```

Each archive contains its own `SHA256SUMS`, `README.txt` and verifier scripts.

## Experiment scripts

CPU, GPU, remote-witness, component and verification scripts are available in [`experiments/`](experiments/README.md). See that directory for campaign boundaries, dependency manifests, evidence requirements and source checksums. The existing release archives and their checksums are unchanged.
