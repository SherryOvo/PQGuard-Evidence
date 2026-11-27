#!/usr/bin/env python3
"""Functional and timing tests for the Merkle-batched audit logger.

Every check named as missing in the internal audit of the earlier prototype is
implemented here:

  * complete leaf coverage, including odd trailing nodes at every level;
  * a verified inclusion proof for *every* leaf, not just the batch root;
  * tamper rejection for payload change, interior deletion, reorder, insertion
    and truncation;
  * per-batch verification (leaf count, tree shape, root, signature);
  * repeated timing rather than a single measurement per batch size.

Run:  python3 tools/test_merkle_audit.py
      python3 tools/test_merkle_audit.py --timing --repeats 20 --json-out timing.json
      python3 tools/test_merkle_audit.py --timing --backend real
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import statistics
import sys
import time
from typing import Any, Dict, List, Sequence

from merkle_audit import (
    LibOQSPhincsSigner,
    MerkleAuditLogger,
    MerkleTree,
    StubSigner,
    hash_entry,
    verify_inclusion,
)

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def payload(i: int) -> Dict[str, Any]:
    """A raw audit payload, as a caller would supply it."""

    return {
        "timestamp": 1_700_000_000.0 + i,
        "session_id": f"sid-{i % 7}",
        "model_id": "qwen2.5-14b-instruct",
        "model_version_hash": "a" * 64,
        "request_hash": f"{i:064x}",
        "response_hash": f"{i * 7:064x}",
        "user_id": f"u{i % 13}",
        "metadata": {"policy_version": 3, "policy_digest": "b" * 64},
    }


def buffer_entries(logger: MerkleAuditLogger, n: int) -> List[Dict[str, Any]]:
    """Append n payloads and return them as the logger stored them."""

    return [logger.append(payload(i)) for i in range(n)]


def build(logger: MerkleAuditLogger, n: int):
    """Append n entries and return the batch that covers them."""

    before = len(logger.batches)
    entries = buffer_entries(logger, n)
    if logger.pending_count:
        logger.flush()
    created = logger.batches[before:]
    if len(created) != 1:
        raise AssertionError(f"expected one batch, created {len(created)}")
    batch = created[0]
    return entries, batch


def filler_entry(i: int) -> Dict[str, Any]:
    """A filled entry shaped like the logger's output, for insertion tests."""

    return {
        "timestamp": 1.0, "session_id": "sid-x", "model_id": "m",
        "model_version_hash": "a" * 64, "request_hash": f"{i:064x}",
        "response_hash": f"{i:064x}", "user_id": "u", "metadata": {},
        "stream_id": "stream-0", "sequence": i, "previous_hash": "0" * 64,
    }


def test_leaf_coverage() -> None:
    print("\n1. Leaf coverage (odd trailing nodes must be promoted, not dropped)")
    sizes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 63, 64, 65, 100, 127,
             128, 129, 999, 1000, 1001, 1024, 1025]
    for n in sizes:
        tree = MerkleTree([hash_entry({"i": i}) for i in range(n)])
        covered = tree.covered_leaf_count()
        check(f"n={n:5d}: all {n} leaves covered", covered == n, f"(covered {covered})")


def test_inclusion_proofs() -> None:
    print("\n2. Inclusion proof verified for every leaf")
    for n in [1, 2, 3, 5, 7, 10, 100, 1000, 1001]:
        leaves = [hash_entry({"i": i}) for i in range(n)]
        tree = MerkleTree(leaves)
        ok = all(verify_inclusion(leaves[i], tree.proof(i), tree.root) for i in range(n))
        check(f"n={n:5d}: {n}/{n} inclusion proofs verify", ok)

        alien = MerkleTree([hash_entry({"i": i}) for i in range(n + 1)]).root
        check(
            f"n={n:5d}: proof rejected against a different root",
            not verify_inclusion(leaves[0], tree.proof(0), alien),
        )

        depth = max(len(tree.proof(i)) for i in range(n))
        bound = 1 if n == 1 else math.ceil(math.log2(n))
        check(f"n={n:5d}: proof depth {depth} <= ceil(log2 n) = {bound}", depth <= bound)

        if n >= 2:
            check(
                f"n={n:5d}: proof for leaf 0 does not verify leaf 1",
                not verify_inclusion(leaves[1], tree.proof(0), tree.root),
            )


def test_tamper_rejection() -> None:
    print("\n3. Tamper rejection")
    n = 100
    signer = StubSigner()
    logger = MerkleAuditLogger(signer, batch_size=n)
    entries, batch = build(logger, n)

    check("baseline batch verifies", logger.verify_batch(batch, entries))
    check("baseline entry 50 verifies", logger.verify_entry(entries[50]))

    for idx in [0, 1, 49, 50, 98, 99]:
        tampered = [dict(e) for e in entries]
        tampered[idx]["response_hash"] = "f" * 64
        check(
            f"payload modification at index {idx} rejected",
            not logger.verify_batch(batch, tampered),
        )
        check(
            f"modified entry {idx} rejected individually",
            not logger.verify_entry(tampered[idx]),
        )

    for idx in [0, 1, 50, 98]:
        deleted = entries[:idx] + entries[idx + 1:]
        check(
            f"interior deletion at index {idx} rejected",
            not logger.verify_batch(batch, deleted),
        )

    swapped = list(entries)
    swapped[10], swapped[11] = swapped[11], swapped[10]
    check("adjacent reorder rejected", not logger.verify_batch(batch, swapped))
    distant = list(entries)
    distant[3], distant[77] = distant[77], distant[3]
    check("distant reorder rejected", not logger.verify_batch(batch, distant))

    inserted = entries[:50] + [filler_entry(999)] + entries[50:]
    check("insertion rejected", not logger.verify_batch(batch, inserted))

    check("tail truncation rejected", not logger.verify_batch(batch, entries[:-1]))
    check("heavy truncation rejected", not logger.verify_batch(batch, entries[:10]))

    forged = copy.deepcopy(batch)
    forged.signature = bytes(len(batch.signature))
    check("forged batch signature rejected", not logger.verify_batch(forged, entries))

    forged_root = copy.deepcopy(batch)
    forged_root.root = b"\x00" * 32
    check("substituted batch root rejected", not logger.verify_batch(forged_root, entries))

    leaves = [hash_entry(e) for e in entries]
    tree = MerkleTree(leaves)
    check(
        "proof for leaf 5 does not verify leaf 6",
        not verify_inclusion(leaves[6], tree.proof(5), tree.root),
    )


def test_batch_shapes() -> None:
    print("\n4. Batch verification across tree shapes and batch sizes")
    for batch_size in [1, 2, 3, 7, 10, 100, 1000]:
        signer = StubSigner()
        logger = MerkleAuditLogger(signer, batch_size=batch_size)
        entries, batch = build(logger, batch_size)
        check(
            f"batch_size={batch_size:5d}: tree shape, root and signature verify",
            logger.verify_batch(batch, entries),
        )
        cov = logger.coverage()
        check(
            f"batch_size={batch_size:5d}: covered == leaves == {batch_size}",
            cov["covered"] == cov["leaves"] == batch_size,
        )
        check(
            f"batch_size={batch_size:5d}: exactly one signature for the batch",
            logger.signature_count == 1,
        )

    print("\n   multi-batch chain")
    signer = StubSigner()
    logger = MerkleAuditLogger(signer, batch_size=100)
    all_entries: List[Dict[str, Any]] = []
    for start in range(0, 1000, 100):
        chunk = [logger.append(payload(i)) for i in range(start, start + 100)]
        batch = logger.batches[-1]
        check(
            f"chunk {start:4d}-{start + 99:4d}: batch verifies",
            logger.verify_batch(batch, chunk),
        )
        all_entries.extend(chunk)
    check("1000 entries in 10 batches -> 10 signatures", logger.signature_count == 10)
    cov = logger.coverage()
    check("all 1000 entries covered by a proof", cov["covered"] == cov["leaves"] == 1000)
    check("every entry verifies individually", all(logger.verify_entry(e) for e in all_entries))

    linked = all(
        nxt.previous_batch_hash == prev.batch_hash()
        for prev, nxt in zip(logger.batches, logger.batches[1:])
    )
    check("batch chain linkage holds for all batches", linked)

    print("\n   configured batch size is enforced")
    signer = StubSigner()
    logger = MerkleAuditLogger(signer, batch_size=3)
    ten = [logger.append(payload(i)) for i in range(10)]
    check("three full batches sealed while appending", [b.leaf_count for b in logger.batches] == [3, 3, 3])
    check("one entry remains before final flush", logger.pending_count == 1)
    logger.flush()
    check("10 entries at batch_size=3 produce 3,3,3,1", [b.leaf_count for b in logger.batches] == [3, 3, 3, 1])
    check("all four roots are signed", logger.signature_count == 4)
    check("all ten entries verify", all(logger.verify_entry(e) for e in ten))


def test_edge_cases() -> None:
    print("\n5. Edge cases")
    try:
        MerkleTree([])
        check("empty tree rejected", False)
    except ValueError:
        check("empty tree rejected", True)

    signer = StubSigner()
    logger = MerkleAuditLogger(signer)
    try:
        logger.flush()
        check("flush with no pending entries rejected", False)
    except ValueError:
        check("flush with no pending entries rejected", True)

    filled = logger.append(payload(0))
    batch = logger.flush() if logger.pending_count else logger.batches[-1]
    check("single-entry batch verifies", logger.verify_batch(batch, [filled]))
    check("single-entry root equals the leaf hash", batch.root == hash_entry(filled))
    check("single-entry tree has height 0", MerkleTree([hash_entry(filled)]).height == 0)


def stats(xs: Sequence[float]) -> Dict[str, float]:
    s = sorted(xs)
    n = len(s)
    return {
        "median_ms": statistics.median(s),
        "p25_ms": s[max(0, int(0.25 * (n - 1)))],
        "p75_ms": s[min(n - 1, int(0.75 * (n - 1)))],
        "min_ms": s[0],
        "max_ms": s[-1],
        "n": n,
    }


def timing(repeats: int, sizes: List[int], backend: str) -> Dict[str, Any]:
    signer = LibOQSPhincsSigner() if backend == "real" else StubSigner()
    print(f"\n6. Timing with backend: {signer.name}  (repeats={repeats} per size)")
    results: Dict[str, Any] = {
        "backend": signer.name,
        "signature_bytes": signer.signature_bytes,
        "repeats": repeats,
        "sizes": {},
    }
    for n in sizes:
        build_ms: List[float] = []
        prove_ms: List[float] = []
        verify_ms: List[float] = []
        flush_ms: List[float] = []
        proof_hashes = 0
        for _ in range(repeats):
            leaves = [hash_entry({"i": i}) for i in range(n)]

            t0 = time.perf_counter()
            tree = MerkleTree(leaves)
            t1 = time.perf_counter()
            proofs = [tree.proof(i) for i in range(n)]
            t2 = time.perf_counter()
            assert all(verify_inclusion(leaves[i], proofs[i], tree.root) for i in range(n))
            t3 = time.perf_counter()
            build_ms.append((t1 - t0) * 1e3)
            prove_ms.append((t2 - t1) * 1e3)
            verify_ms.append((t3 - t2) * 1e3)
            proof_hashes = sum(len(p) for p in proofs)

            logger = MerkleAuditLogger(signer, batch_size=n)
            t0 = time.perf_counter()
            buffer_entries(logger, n)
            if logger.pending_count:
                logger.flush()
            flush_ms.append((time.perf_counter() - t0) * 1e3)

        per_record = signer.signature_bytes * n
        batch_policy = signer.signature_bytes + proof_hashes * 32
        results["sizes"][str(n)] = {
            "tree_build": stats(build_ms),
            "proof_generation": stats(prove_ms),
            "proof_verification": stats(verify_ms),
            "flush_including_one_signature": stats(flush_ms),
            "retained_bytes": {
                "entries": n,
                "signatures_per_batch": 1,
                "per_record_policy": per_record,
                "batch_policy": batch_policy,
                "saving_ratio": 1.0 - batch_policy / per_record,
                "proof_hashes": proof_hashes,
            },
        }
        r = results["sizes"][str(n)]
        print(
            f"  n={n:6d}  tree {r['tree_build']['median_ms']:8.3f} ms | "
            f"prove {r['proof_generation']['median_ms']:8.3f} ms | "
            f"verify {r['proof_verification']['median_ms']:8.3f} ms | "
            f"flush+1sig {r['flush_including_one_signature']['median_ms']:9.3f} ms | "
            f"retained saving {r['retained_bytes']['saving_ratio'] * 100:6.2f}%"
        )
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timing", action="store_true", help="also run timing")
    ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--sizes", type=str, default="10,100,1000,10000")
    ap.add_argument("--backend", choices=["stub", "real"], default="stub")
    ap.add_argument("--json-out", type=str, default=None)
    args = ap.parse_args()

    test_leaf_coverage()
    test_inclusion_proofs()
    test_tamper_rejection()
    test_batch_shapes()
    test_edge_cases()

    if args.timing:
        sizes = [int(x) for x in args.sizes.split(",") if x.strip()]
        payload_json = timing(args.repeats, sizes, args.backend)
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(payload_json, fh, indent=2, sort_keys=True)
            print(f"\n  timing written to {args.json_out}")

    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
