#!/usr/bin/env python3
"""Bridge the Merkle batch logger to PQGuard's existing SAL and AuditLogger.

This is the piece that makes the R5 comparison runnable on a host that has
liboqs. It provides

  * ``SALSigner`` - adapts ``PQSecurityAbstractionLayer.sign_audit_log`` /
    ``verify_audit_log`` (bytes in, bytes out, SPHINCS+-SHA2-128f-simple) to the
    ``Signer`` interface of ``merkle_audit``;
  * ``compare_policies`` - runs the per-record policy and the batched policy over
    the same entry stream and reports signing counts, throughput and retained
    bytes, so the two are measured under one code path.

The per-record policy is reproduced faithfully: one SAL audit signature per
entry, which is what ``pqguard/audit_log.py`` does in ``sign_entry`` and
``log``. The batched policy signs one Merkle root per batch.

Nothing here changes the evaluated logger. To measure on the target host, put
this directory on ``PYTHONPATH`` next to ``pqguard`` and run the CLI:

    python3 tools/merkle_integration.py --entries 1000 --batch-size 1000 \
        --repeats 10 --json-out merkle_vs_perrecord.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from merkle_audit import MerkleAuditLogger, Signer, hash_entry

SPHINCS_SIGNATURE_BYTES = 17088


class SALSigner(Signer):
    """Signer backed by PQGuard's security abstraction layer.

    ``sal`` must expose sign_audit_log(log_data, secret_key) -> bytes and
    verify_audit_log(log_data, signature, public_key) -> bool.
    """

    def __init__(self, sal, public_key: bytes, secret_key: bytes) -> None:
        self._sal = sal
        self._public_key = public_key
        self._secret_key = secret_key
        self.name = f"SAL audit signature ({getattr(sal, 'AUDIT_SIG_ALGORITHM', 'unknown')})"
        # Determine the signature size from the backend rather than assuming.
        probe = self._sal.sign_audit_log(b"pqguard-signature-size-probe", self._secret_key)
        self.signature_bytes = len(probe)

    def sign(self, message: bytes) -> bytes:
        return self._sal.sign_audit_log(message, self._secret_key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return bool(self._sal.verify_audit_log(message, signature, self._public_key))


def make_sal_signer(sal_class_path: Optional[str] = None) -> SALSigner:
    """Build a SALSigner using the evaluated PQGuard SAL.

    ``sal_class_path`` defaults to importing ``pqguard.sal``, which requires the
    experiment source tree on ``PYTHONPATH``.
    """

    if sal_class_path:
        sys.path.insert(0, sal_class_path)
    from pqguard.sal import PQSecurityAbstractionLayer  # type: ignore

    sal = PQSecurityAbstractionLayer()
    public_key, secret_key = sal.generate_audit_keypair()
    return SALSigner(sal, public_key, secret_key)


def entry_stream(n: int) -> List[Dict[str, Any]]:
    """Deterministic synthetic entries shaped like the evaluated audit records."""

    return [
        {
            "timestamp": 1_700_000_000.0 + i,
            "session_id": f"sid-{i % 64}",
            "model_id": "qwen2.5-14b-instruct",
            "model_version_hash": "a" * 64,
            "request_hash": f"{i:064x}",
            "response_hash": f"{(i * 7) % (1 << 256):064x}",
            "user_id": f"u{i % 1024}",
            "metadata": {"policy_version": 3, "policy_digest": "b" * 64},
        }
        for i in range(n)
    ]


def measure_per_record(signer: Signer, entries: Sequence[Dict[str, Any]],
                       repeats: int) -> Dict[str, Any]:
    """Per-record policy: one signature per entry, as the evaluated logger does."""

    import hashlib

    samples: List[float] = []
    for _ in range(repeats):
        total_sig_bytes = 0
        previous_hash = "0" * 64
        t0 = time.perf_counter()
        for sequence, e in enumerate(entries):
            payload = dict(e)
            payload["stream_id"] = "stream-0"
            payload["sequence"] = sequence
            payload["previous_hash"] = previous_hash
            leaf = hash_entry(payload)
            sig = signer.sign(leaf)
            total_sig_bytes += len(sig)
            previous_hash = leaf.hex()
        samples.append((time.perf_counter() - t0) * 1e3)

    s = sorted(samples)
    n = len(entries)
    return {
        "policy": "per-record signature",
        "signatures": n * repeats,          # per repetition
        "signatures_per_entry": 1.0,
        "batch_ms": {
            "median": statistics.median(s),
            "p25": s[max(0, int(0.25 * (len(s) - 1)))],
            "p75": s[min(len(s) - 1, int(0.75 * (len(s) - 1)))],
            "n": len(s),
        },
        "ms_per_entry": statistics.median(s) / n,
        "entries_per_second": n / (statistics.median(s) / 1e3),
        "signature_bytes_per_entry": signer.signature_bytes,
        "retained_signature_bytes": signer.signature_bytes * n,
    }


def measure_batched(signer: Signer, entries: Sequence[Dict[str, Any]],
                    batch_size: int, repeats: int) -> Dict[str, Any]:
    """Batched policy: one signed Merkle root per batch of ``batch_size``."""

    samples: List[float] = []
    sig_count = 0
    proof_hashes = 0
    for _ in range(repeats):
        t0 = time.perf_counter()
        logger = MerkleAuditLogger(signer, batch_size=batch_size)
        for e in entries:
            logger.append(e)
        if logger.pending_count:
            logger.flush()
        samples.append((time.perf_counter() - t0) * 1e3)
        sig_count = logger.signature_count
        proof_hashes = sum(len(p) for p in logger._proofs.values())

    s = sorted(samples)
    n = len(entries)
    retained = sig_count * signer.signature_bytes + proof_hashes * 32
    return {
        "policy": "merkle batch, one signature per batch",
        "batch_size": batch_size,
        "signatures": sig_count,
        "signatures_per_entry": sig_count / n,
        "batch_ms": {
            "median": statistics.median(s),
            "p25": s[max(0, int(0.25 * (len(s) - 1)))],
            "p75": s[min(len(s) - 1, int(0.75 * (len(s) - 1)))],
            "n": len(s),
        },
        "ms_per_entry": statistics.median(s) / n,
        "entries_per_second": n / (statistics.median(s) / 1e3),
        "signature_bytes_per_entry": retained / n,
        "retained_signature_bytes": retained,
        "inclusion_proof_hashes": proof_hashes,
    }


def compare_policies(signer: Signer, entries: Sequence[Dict[str, Any]],
                     batch_size: int, repeats: int) -> Dict[str, Any]:
    per_record = measure_per_record(signer, entries, repeats)
    batched = measure_batched(signer, entries, batch_size, repeats)
    return {
        "entries": len(entries),
        "repeats": repeats,
        "signer": signer.name,
        "signature_bytes": signer.signature_bytes,
        "per_record": per_record,
        "batched": batched,
        "speedup": {
            "throughput_ratio": batched["entries_per_second"] / per_record["entries_per_second"],
            "ms_per_entry_ratio": per_record["ms_per_entry"] / batched["ms_per_entry"],
            "signature_bytes_ratio": per_record["retained_signature_bytes"] / batched["retained_signature_bytes"],
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--entries", type=int, default=1000)
    ap.add_argument("--batch-size", type=int, default=1000)
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--sal-path", type=str, default=None,
                    help="directory containing the pqguard package")
    ap.add_argument("--json-out", type=str, default=None)
    args = ap.parse_args()

    signer = make_sal_signer(args.sal_path)
    print(f"signer: {signer.name}  ({signer.signature_bytes} B signatures)")

    entries = entry_stream(args.entries)
    results = compare_policies(signer, entries, args.batch_size, args.repeats)

    print(json.dumps(results, indent=2, sort_keys=True))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"\nwritten to {args.json_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
