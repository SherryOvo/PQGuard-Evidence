# PQGuard reproducibility code

This archive contains the protocol, replay-state, audit-chain, Merkle, GPU measurement, network-stress, statistical-recomputation, synchronization, and figure-generation programs submitted with the manuscript. Environment records and machine-readable results are in PQGuard_Source_Data_Supplement.zip; the Tamarin models and outputs are in PQGuard_Formal_Artifacts.zip. Generated secret keys and large model weights are intentionally excluded.

## R11 security-repair harness

`r7_cpu_formal/` now contains the repaired executable profile used for the R11 correctness checks:

- `r7_crypto_profiles.py` implements an authenticated ephemeral X25519/ML-KEM-768 hybrid transcript, a separately signed policy descriptor, and per-record AES-GCM material derived from `(sid, direction, sequence)`.
- `r11_durable_lifecycle.py` atomically persists completion evidence and a signed witness-outbox item before publication is attempted.
- `r7_matched_baseline.py` establishes one session per cell and uses a distinct sequence for every record. It reports session setup separately from steady-state request timing.
- `r7_validate.py` independently checks public-key signatures, database integrity, persistent-session sequence shape, outbox drainage, and witness-head agreement.
- `test_r11_security_contract.py` tests record-material uniqueness, AAD rejection, outage retention, restart publication, and duplicate admission.

The R11 result workspace contains a replacement 80-cell, 5,120-record matrix generated after the repair. Every cell establishes one authenticated session and assigns distinct record sequences. Independent validation verifies all 5,120 admission/completion signatures, all lifecycle databases, every drained outbox, and all local/witness head pairs. The earlier fresh-session matrix is not performance evidence for this profile.

Example correctness run (use a Python environment with liboqs support for the post-quantum profile):

```bash
python test_r11_security_contract.py
python r7_matched_baseline.py --out /new/result/path --repetitions 1 --concurrency 4 --minimum-requests 8 --requests-factor 2 --payload-bytes 1024
python r7_validate.py /new/result/path
```
