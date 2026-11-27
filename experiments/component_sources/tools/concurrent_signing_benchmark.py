#!/usr/bin/env python3
"""Does batching remove the audit lock as the concurrency bottleneck?

The evaluated logger signs every record inside a lock. At concurrency 64 the
paper measures request p50 rising from ~20 ms to 946--1,025 ms with mean lock
wait 802 ms, i.e. the lock, not the signature, sets the ceiling. This harness
asks whether the batched schedule changes that.

Design
------
For each concurrency level c in {1, 8, 32, 64} and each schedule:

  * c worker threads generate entries at a barrier so that they contend;
  * the per-record schedule signature-signs every entry while holding one lock
    (reproducing the evaluated behaviour);
  * the batched schedule buffers entries under the lock and signs one Merkle
    root per batch, also under the lock;
  * every concurrency level processes the same fixed total number of entries;
    workers receive strided subsets of that common workload;
  * full batches seal as soon as ``batch_size`` is reached, and the final partial
    batch is included in the measured interval.

Reported per level: wall time, entries/s, and the mean time a worker spends
inside the critical section, which is the quantity the paper attributes the
bottleneck to.

Run on a host with liboqs:
    python3 concurrent_signing_benchmark.py --levels 1,8,32,64 --total-entries 3200 \
        --batch-size 1000 --json-out concurrent_signing.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from merkle_audit import GENESIS_HASH, MerkleAuditLogger, Signer, hash_entry, resolve_real_signer

try:  # host without liboqs
    from merkle_audit import StubSigner
except ImportError:  # pragma: no cover
    StubSigner = None  # type: ignore


def entry(i: int) -> Dict[str, Any]:
    return {
        "timestamp": 1_700_000_000.0 + i,
        "session_id": f"sid-{i % 64}",
        "model_id": "qwen2.5-14b-instruct",
        "model_version_hash": "a" * 64,
        "request_hash": f"{i:064x}",
        "response_hash": f"{(i * 7) % (1 << 256):064x}",
        "user_id": f"u{i % 1024}",
        "metadata": {"policy_version": 3, "policy_digest": "b" * 64},
    }


def run_per_record(signer: Signer, threads: int, total: int) -> Dict[str, Any]:
    """One lock, one signature per entry (the evaluated schedule)."""

    lock = threading.Lock()
    barrier = threading.Barrier(threads)
    critical: List[float] = []
    lock_times: List[float] = []
    state = {"previous_hash": GENESIS_HASH, "sequence": 0}

    def worker(wid: int) -> None:
        barrier.wait()
        for idx in range(wid, total, threads):
            t0 = time.perf_counter()
            with lock:
                t1 = time.perf_counter()
                payload = entry(idx)
                payload["stream_id"] = "stream-0"
                payload["sequence"] = state["sequence"]
                payload["previous_hash"] = state["previous_hash"]
                leaf = hash_entry(payload)
                signer.sign(leaf)
                state["previous_hash"] = leaf.hex()
                state["sequence"] += 1
                t2 = time.perf_counter()
            critical.append(t2 - t1)
            lock_times.append(t1 - t0)

    ts = [threading.Thread(target=worker, args=(w,)) for w in range(threads)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    wall = time.perf_counter() - t0
    return {
        "schedule": "per-record",
        "entries": total,
        "wall_s": wall,
        "entries_per_s": total / wall,
        "ms_per_entry": wall / total * 1e3,
        "mean_sign_hold_ms": statistics.fmean(critical) * 1e3,
        "mean_lock_wait_ms": statistics.fmean(lock_times) * 1e3,
        "signatures": total,
    }


def run_batched(signer: Signer, threads: int, total: int,
                batch_size: int) -> Dict[str, Any]:
    """One lock around buffering, and one signature per batch."""

    lock = threading.Lock()
    barrier = threading.Barrier(threads)
    logger = MerkleAuditLogger(signer, batch_size=batch_size)
    lock_times: List[float] = []
    hold_times: List[float] = []
    seq = {"n": 0}

    def worker(wid: int) -> None:
        barrier.wait()
        for _ in range(wid, total, threads):
            t0 = time.perf_counter()
            with lock:
                t1 = time.perf_counter()
                idx = seq["n"]
                seq["n"] = idx + 1
                logger.append(entry(idx))
                t2 = time.perf_counter()
            lock_times.append(t1 - t0)
            hold_times.append(t2 - t1)

    ts = [threading.Thread(target=worker, args=(w,)) for w in range(threads)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    # Flush the remainder on the main thread so the batch work is counted.
    if logger.pending_count:
        with lock:
            logger.flush()
    wall = time.perf_counter() - t0
    return {
        "schedule": "batched",
        "batch_size": batch_size,
        "entries": total,
        "wall_s": wall,
        "entries_per_s": total / wall,
        "ms_per_entry": wall / total * 1e3,
        "mean_sign_hold_ms": None,   # root signature happens at flush
        "mean_lock_wait_ms": statistics.fmean(lock_times) * 1e3,
        "mean_buffer_hold_ms": statistics.fmean(hold_times) * 1e3,
        "signatures": logger.signature_count,
        "batch_leaf_counts": [batch.leaf_count for batch in logger.batches],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", type=str, default="1,8,32,64")
    ap.add_argument("--total-entries", type=int, default=3200)
    ap.add_argument("--batch-size", type=int, default=1000)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--backend", choices=["real", "stub"], default="real")
    ap.add_argument("--json-out", type=str, default=None)
    args = ap.parse_args()

    signer = resolve_real_signer() if args.backend == "real" else StubSigner()
    levels = [int(x) for x in args.levels.split(",") if x.strip()]
    print(f"backend: {signer.name}  signature {signer.signature_bytes} B")
    print(f"fixed total entries: {args.total_entries}  repeats: {args.repeats}  "
          f"batch size: {args.batch_size}\n")

    out: Dict[str, Any] = {
        "backend": signer.name,
        "signature_bytes": signer.signature_bytes,
        "total_entries": args.total_entries,
        "repeats": args.repeats,
        "batch_size": args.batch_size,
        "levels": {},
    }

    hdr = (f"{'c':>4} {'schedule':>11} {'entries/s':>10} {'ms/entry':>9} "
           f"{'lock wait ms':>13} {'hold ms':>9} {'sigs':>6}")
    print(hdr)
    print("-" * len(hdr))

    for c in levels:
        cell: Dict[str, Any] = {}
        for name, fn in (("per-record", lambda: run_per_record(signer, c, args.total_entries)),
                         ("batched", lambda: run_batched(signer, c, args.total_entries, args.batch_size))):
            runs = [fn() for _ in range(args.repeats)]
            med = {
                k: statistics.median([r[k] for r in runs])
                for k in ("entries_per_s", "ms_per_entry", "mean_lock_wait_ms", "signatures")
                if runs[0].get(k) is not None
            }
            hold_key = "mean_sign_hold_ms" if name == "per-record" else "mean_buffer_hold_ms"
            med[hold_key] = statistics.median([r[hold_key] for r in runs])
            med["schedule"] = name
            med["entries"] = args.total_entries
            med["runs"] = runs
            cell[name] = med
            print(f"{c:>4} {name:>11} {med['entries_per_s']:>10.1f} {med['ms_per_entry']:>9.3f} "
                  f"{med['mean_lock_wait_ms']:>13.3f} {med[hold_key]:>9.3f} {med['signatures']:>6.0f}")
        cell["throughput_ratio"] = (
            cell["batched"]["entries_per_s"] / cell["per-record"]["entries_per_s"]
        )
        print(f"{'':>4} {'ratio':>11} {cell['throughput_ratio']:>10.1f}x")
        out["levels"][str(c)] = cell
        print()

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"written to {args.json_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
