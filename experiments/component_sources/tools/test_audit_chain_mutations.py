#!/usr/bin/env python3
"""Audit-chain and checkpoint mutation coverage, at 1,000 trials per class.

Motivation
----------
Supplementary Table S3 reports the "complete suffix truncation" test with a
single trial and Supplementary Table S29 reports one instance per mutation, both
labelled as negative controls. Those are existence demonstrations, not detection
rates. This harness measures the same classes over 1,000 independent trials each
so the supplementary tables can report a rate rather than a single outcome.

Independence note: the chain and checkpoint semantics here are re-implemented
from the description in Section 4.4 and checked against the record shape in the
local evidence database (`results/concurrent_replay/audit.sqlite3`, whose
signature column decodes to 17,088 bytes, matching the evaluated
SPHINCS+-SHA2-128f-simple size). The signatures use the same pluggable backend
as `merkle_audit`: functional coverage is backend-independent, but the detection
claim for the deployed configuration must be re-run with
``--backend real`` on a host with liboqs.

Run:
    python3 tools/test_audit_chain_mutations.py --trials 1000
    python3 tools/test_audit_chain_mutations.py --trials 1000 --backend real
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from merkle_audit import LibOQSPhincsSigner, Signer, StubSigner

GENESIS = "0" * 64
ENTRY_DOMAIN = b"PQGuard-Audit-Entry-v2\x00"
CHECKPOINT_DOMAIN = b"PQGuard-Audit-Checkpoint-v1\x00"
BATCH_SIZE = 10


def canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass
class Entry:
    sequence: int
    payload: Dict[str, Any]
    previous_hash: str
    entry_hash: str = ""
    signature: bytes = b""

    def body(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        }


@dataclass
class Checkpoint:
    start_sequence: int
    end_sequence: int
    count: int
    batch_hash: str
    last_entry_hash: str
    previous_checkpoint_hash: str
    signature: bytes = b""

    def body(self) -> Dict[str, Any]:
        return {
            "start_sequence": self.start_sequence,
            "end_sequence": self.end_sequence,
            "count": self.count,
            "batch_hash": self.batch_hash,
            "last_entry_hash": self.last_entry_hash,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
        }


@dataclass
class Stream:
    entries: List[Entry] = field(default_factory=list)
    checkpoints: List[Checkpoint] = field(default_factory=list)
    head: Optional[Dict[str, Any]] = None


def build_stream(signer: Signer, n: int, stream_id: str = "s0",
                 batch: int = BATCH_SIZE) -> Stream:
    st = Stream()
    prev = GENESIS
    prev_ckpt = GENESIS
    for i in range(n):
        e = Entry(sequence=i, payload={"i": i, "sid": stream_id,
                                       "req": f"{i:064x}", "resp": f"{i + 1:064x}"},
                  previous_hash=prev)
        e.entry_hash = hashlib.sha256(ENTRY_DOMAIN + canon(e.body())).hexdigest()
        e.signature = signer.sign(ENTRY_DOMAIN + canon(e.body()))
        st.entries.append(e)
        prev = e.entry_hash
        if (i + 1) % batch == 0:
            chunk = st.entries[-batch:]
            joined = "".join(x.entry_hash for x in chunk).encode("ascii")
            ck = Checkpoint(start_sequence=chunk[0].sequence,
                            end_sequence=chunk[-1].sequence, count=len(chunk),
                            batch_hash=hashlib.sha256(joined).hexdigest(),
                            last_entry_hash=chunk[-1].entry_hash,
                            previous_checkpoint_hash=prev_ckpt)
            ck.signature = signer.sign(CHECKPOINT_DOMAIN + canon(ck.body()))
            st.checkpoints.append(ck)
            prev_ckpt = hashlib.sha256(CHECKPOINT_DOMAIN + canon(ck.body())).hexdigest()
    st.head = {
        "log_hash": hashlib.sha256(canon([e.entry_hash for e in st.entries])).hexdigest(),
        "checkpoint_hash": prev_ckpt,
        "entry_count": len(st.entries),
    }
    return st


def verify_stream(st: Stream, signer: Signer, head: Optional[Dict[str, Any]] = None,
                  verify_signatures: bool = True) -> Tuple[bool, str]:
    """Recompute the whole chain; optional comparison against a separate head."""

    prev = GENESIS
    for e in st.entries:
        if e.previous_hash != prev:
            return False, f"predecessor link broken at {e.sequence}"
        if e.entry_hash != hashlib.sha256(ENTRY_DOMAIN + canon(e.body())).hexdigest():
            return False, f"entry hash mismatch at {e.sequence}"
        if verify_signatures and not signer.verify(ENTRY_DOMAIN + canon(e.body()), e.signature):
            return False, f"entry signature invalid at {e.sequence}"
        prev = e.entry_hash

    prev_ckpt = GENESIS
    for ck in st.checkpoints:
        if ck.previous_checkpoint_hash != prev_ckpt:
            return False, f"checkpoint link broken at {ck.start_sequence}"
        chunk = [e for e in st.entries
                 if ck.start_sequence <= e.sequence <= ck.end_sequence]
        if len(chunk) != ck.count:
            return False, "checkpoint covers records outside the retained prefix"
        joined = "".join(x.entry_hash for x in chunk).encode("ascii")
        if hashlib.sha256(joined).hexdigest() != ck.batch_hash:
            return False, "batch hash mismatch"
        if chunk and chunk[-1].entry_hash != ck.last_entry_hash:
            return False, "checkpoint terminal hash mismatch"
        if verify_signatures and not signer.verify(CHECKPOINT_DOMAIN + canon(ck.body()), ck.signature):
            return False, "checkpoint signature invalid"
        prev_ckpt = hashlib.sha256(CHECKPOINT_DOMAIN + canon(ck.body())).hexdigest()

    if head is not None:
        if head["entry_count"] != len(st.entries):
            return False, "head entry count differs (rollback detected)"
        if head["checkpoint_hash"] != prev_ckpt:
            return False, "head checkpoint hash differs (rollback detected)"
        if head["log_hash"] != hashlib.sha256(canon([e.entry_hash for e in st.entries])).hexdigest():
            return False, "head log hash differs"
    return True, "ok"


# --------------------------------------------------------------------------
def run_mutations(signer: Signer, trials: int, seed: int = 20260917) -> Dict[str, Any]:
    """Measure each class.

    ``expect_detected`` states the expected verification outcome:
      * attacks -> True  (verification must fail)
      * control and local-only consistent rollback -> False (verification must pass,
        which is precisely why a separately retained head is required)
    A trial is a mismatch when the observed outcome differs from the expectation.
    """

    rng = random.Random(seed)
    n = 100
    classes: Dict[str, int] = {}
    mismatches: Dict[str, int] = {}
    examples: Dict[str, List[str]] = {}

    def record(cls: str, observed_detected: bool, expected_detected: bool,
               detail: str = "") -> None:
        classes[cls] = classes.get(cls, 0) + 1
        if observed_detected != expected_detected:
            mismatches[cls] = mismatches.get(cls, 0) + 1
            if len(examples.setdefault(cls, [])) < 3:
                examples[cls].append(detail)

    for t in range(trials):
        st = build_stream(signer, n)
        ok, why = verify_stream(st, signer)
        record("control: unmodified stream verifies", not ok, False, why)

        m = _clone(st)
        idx = rng.randrange(len(m.entries))
        m.entries[idx].payload["resp"] = "f" * 64
        record("payload modification", not verify_stream(m, signer)[0], True)

        m = _clone(st)
        idx = rng.randrange(1, len(m.entries) - 1)
        del m.entries[idx]
        record("interior deletion", not verify_stream(m, signer)[0], True)

        m = _clone(st)
        i = rng.randrange(len(m.entries) - 1)
        m.entries[i], m.entries[i + 1] = m.entries[i + 1], m.entries[i]
        record("entry reordering", not verify_stream(m, signer)[0], True)

        m = _clone(st)
        drop = rng.randrange(1, 15)
        m.entries = m.entries[:-drop]
        record("unmatched tail truncation", not verify_stream(m, signer)[0], True)

        m = _clone(st)
        ck = m.checkpoints[rng.randrange(len(m.checkpoints))]
        ck.batch_hash = "0" * 64
        record("checkpoint modification", not verify_stream(m, signer)[0], True)

        # Consistent suffix rollback: remove the final entries together with the
        # checkpoints that cover them. drop_ck >= 2 guarantees at least one
        # checkpoint and therefore at least one entry is actually removed.
        m = _clone(st)
        drop_ck = rng.randrange(2, len(m.checkpoints) + 1)
        keep_upto = m.checkpoints[-drop_ck].end_sequence
        m.entries = [e for e in m.entries if e.sequence <= keep_upto]
        m.checkpoints = [c for c in m.checkpoints if c.end_sequence <= keep_upto]
        removed = n - len(m.entries)
        local_ok, local_why = verify_stream(m, signer)
        head_ok, _ = verify_stream(m, signer, head=st.head)
        record("suffix rollback, local-only: expected ACCEPT (negative control)",
               not local_ok, False, f"removed {removed} entries: {local_why}")
        record("suffix rollback vs separately retained head: expected REJECT",
               not head_ok, True, f"removed {removed} entries")

        m = _clone(st)
        idx = rng.randrange(len(m.entries))
        m.entries[idx].signature = bytes(len(m.entries[idx].signature))
        record("forged entry signature", not verify_stream(m, signer)[0], True)

    summary: Dict[str, Any] = {
        "trials": trials,
        "backend": signer.name,
        "stream_entries": n,
        "checkpoints": n // BATCH_SIZE,
        "classes": {},
    }
    for cls in classes:
        tot = classes[cls]
        mism = mismatches.get(cls, 0)
        summary["classes"][cls] = {
            "trials": tot,
            "matching_expectation": tot - mism,
            "match_rate": (tot - mism) / tot if tot else 0.0,
            "mismatches": mism,
            "examples": examples.get(cls, []),
        }
    return summary


def _clone(st: Stream) -> Stream:
    return Stream(
        entries=[Entry(e.sequence, dict(e.payload), e.previous_hash, e.entry_hash, e.signature)
                 for e in st.entries],
        checkpoints=[Checkpoint(c.start_sequence, c.end_sequence, c.count, c.batch_hash,
                                c.last_entry_hash, c.previous_checkpoint_hash, c.signature)
                     for c in st.checkpoints],
        head=dict(st.head) if st.head else None,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=1000)
    ap.add_argument("--backend", choices=["stub", "real"], default="stub")
    ap.add_argument("--json-out", type=str, default=None)
    args = ap.parse_args()

    signer: Signer = LibOQSPhincsSigner() if args.backend == "real" else StubSigner()
    print(f"backend: {signer.name}   trials per class: {args.trials}")
    s = run_mutations(signer, args.trials)

    print(f"\n{'class':62} {'trials':>7} {'match':>7} {'rate':>7} {'bad':>5}")
    for cls, v in sorted(s["classes"].items()):
        print(f"{cls:62} {v['trials']:>7} {v['matching_expectation']:>7} "
              f"{v['match_rate']:>7.4f} {v['mismatches']:>5}")
        for ex in v["examples"]:
            print(f"{'':64}-- {ex[:90]}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(s, fh, indent=2, sort_keys=True)
        print(f"\nwritten to {args.json_out}")

    bad = [c for c, v in s["classes"].items() if v["mismatches"]]
    print(f"\n=== {'PASS' if not bad else 'FAIL: ' + str(bad)} ===")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
