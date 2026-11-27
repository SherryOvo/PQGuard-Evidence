#!/usr/bin/env python3
"""Validation scaffold for a future instrumented PQGuard GPU benchmark.

This file validates the randomized complete-block design, counters, paired
statistics, and output schema. It is intentionally not an executable paper
benchmark: the repository does not contain the deployed PQGuard AEAD and audit
pipeline needed to replace the response-hash and counter-only placeholders.

Why the counters matter. The manuscript reports a small mean increment of the
full mode over transport-only serving, while one audit signature costs
17--20~ms. Those two facts can only be reconciled by knowing how many requests
actually signed inside the measured interval and whether the signature cost is
amortised across a batch. Without the counters the serving measurement cannot be
attributed, and Section 6.3 of the manuscript says exactly that.

Measurement boundaries, matching the paper:
  * T_start = [model load, admission complete] and is excluded from serving;
  * the serving timer starts when the already-decrypted prompt enters the
    generation function and ends when the response is ready;
  * the full mode additionally performs response encryption, the audit append,
    and any batch flush the measured request triggers.

Usage:
  python3 gpu_serving_benchmark.py --self-test

Do not use this scaffold to generate manuscript measurements. A runnable
version must call the actual AEAD, signer, checkpoint, and persistence code and
must retain the matched verification keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

MODES = ("plain", "transport", "full")

PROMPTS = [
    "Explain the difference between a hash chain and a Merkle tree.",
    "Summarize why replay protection requires atomic check-and-insert.",
    "Describe how a KEM differs from a key-agreement protocol.",
    "What does a signed manifest guarantee about a model snapshot?",
    "Why can a consistent log suffix rollback pass local verification?",
    "Explain the role of associated data in an AEAD construction.",
]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def import_torch():
    import torch  # noqa: F401 (validated here for a clear error)
    return torch


def load_model(model_id: str, dtype: str, device: str):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch_dtype = {"bf16": torch.bfloat16, "fp16": torch.float16,
                   "fp32": torch.float32}[dtype]
    tok = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(
        model_id, torch_dtype=torch_dtype, device_map=device
    )
    model.eval()
    return tok, model


class AuditInstrument:
    """Counts audit work inside the measured interval.

    In ``full`` mode every completed request appends a response-completion
    record; the logger signs per record in the evaluated schedule, or once per
    batch in a batched schedule. Either way the counters record what actually
    happened so the increment can be attributed.
    """

    def __init__(self, schedule: str = "per-record", batch_size: int = 10) -> None:
        self.schedule = schedule
        self.batch_size = batch_size
        self.signatures = 0
        self.flushes = 0
        self.checkpoints = 0
        self.pending = 0

    def append(self) -> Dict[str, Any]:
        """Record one response completion; returns the work it triggered."""

        work = {"signatures": 0, "flushes": 0, "checkpoints": 0}
        if self.schedule == "per-record":
            self.signatures += 1
            work["signatures"] = 1
            self.pending += 1
            if self.pending >= self.batch_size:
                self.flushes += 1
                self.checkpoints += 1
                work["flushes"] = 1
                work["checkpoints"] = 1
                self.pending = 0
        else:  # batched
            self.pending += 1
            if self.pending >= self.batch_size:
                self.signatures += 1
                self.flushes += 1
                self.checkpoints += 1
                work["signatures"] = 1
                work["flushes"] = 1
                work["checkpoints"] = 1
                self.pending = 0
        return work

    def snapshot(self) -> Dict[str, int]:
        return {
            "signatures": self.signatures,
            "flushes": self.flushes,
            "checkpoints": self.checkpoints,
            "pending": self.pending,
        }


def run_block(tok, model, mode: str, prompt: str, max_new_tokens: int,
              instrument: AuditInstrument, device: str) -> Dict[str, Any]:
    import torch

    inputs = tok(prompt, return_tensors="pt").to(device)

    # The serving timer starts when the decrypted prompt enters the pipeline.
    with torch.inference_mode():
        if device.startswith("cuda"):
            torch.cuda.synchronize()
        t0 = time.perf_counter()
        out = model.generate(
            **inputs, max_new_tokens=max_new_tokens, do_sample=False
        )
        if device.startswith("cuda"):
            torch.cuda.synchronize()
        t1 = time.perf_counter()

    text = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    latency_ms = (t1 - t0) * 1e3

    # Layers after inference, still inside the measured interval.
    post = {"response_encrypt_ms": 0.0, "audit_ms": 0.0}
    if mode in ("transport", "full"):
        t2 = time.perf_counter()
        _ = hashlib.sha256(text.encode()).hexdigest()  # response protection stand-in
        post["response_encrypt_ms"] = (time.perf_counter() - t2) * 1e3
    if mode == "full":
        t3 = time.perf_counter()
        work = instrument.append()
        post["audit_ms"] = (time.perf_counter() - t3) * 1e3
        post.update({f"audit_{k}": v for k, v in work.items()})

    return {
        "mode": mode,
        "latency_ms": latency_ms,
        "response_chars": len(text),
        "response_sha256": sha256_text(text),
        **post,
    }


def summarise(records: List[Dict[str, Any]], mode: str) -> Dict[str, Any]:
    lats = sorted(r["latency_ms"] for r in records if r["mode"] == mode)
    if not lats:
        return {}
    def q(p: float) -> float:
        return lats[min(len(lats) - 1, int(p * (len(lats) - 1)))]
    hashes = {r["response_sha256"] for r in records if r["mode"] == mode}
    chars = {r["response_chars"] for r in records if r["mode"] == mode}
    return {
        "scheme": {"plain": "baseline_plain", "transport": "baseline_pq_transport",
                   "full": "pqguard_steady"}[mode],
        "runs": len(lats),
        "p50_ms": q(0.5), "p95_ms": q(0.95), "p99_ms": q(0.99),
        "avg_ms": statistics.fmean(lats), "std_ms": statistics.pstdev(lats),
        "min_ms": lats[0], "max_ms": lats[-1],
        "response_hashes_identical": len(hashes) == 1,
        "response_lengths_identical": len(chars) == 1,
    }


def paired_difference(records: List[Dict[str, Any]], a: str, b: str,
                      resamples: int, seed: int) -> Optional[Dict[str, Any]]:
    by_block: Dict[int, Dict[str, float]] = {}
    for r in records:
        by_block.setdefault(r["block"], {})[r["mode"]] = r["latency_ms"]
    diffs = [v[b] - v[a] for v in by_block.values() if a in v and b in v]
    if not diffs:
        return None
    rng = random.Random(seed)
    boots = sorted(
        statistics.fmean(rng.choices(diffs, k=len(diffs))) for _ in range(resamples)
    )
    return {
        "n_blocks": len(diffs),
        "mean_ms": statistics.fmean(diffs),
        "bootstrap95": [boots[int(0.025 * resamples)], boots[int(0.975 * resamples)]],
    }


def self_test() -> int:
    """Exercise everything except the model, so the harness is known good first."""

    failures = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  [{'OK' if cond else 'FAIL'}] {name}{(' ' + detail) if not cond else ''}")
        if not cond:
            failures += 1

    print("1. instrumentation: per-record schedule")
    a = AuditInstrument("per-record", batch_size=10)
    flush_at = [i + 1 for i in range(25) if a.append()["flushes"]]
    check("25 records produce 25 signatures", a.signatures == 25, f"got {a.signatures}")
    check("flushes at records 10 and 20", flush_at == [10, 20], f"got {flush_at}")
    check("checkpoints equal flushes", a.checkpoints == a.flushes)

    print("2. instrumentation: batched schedule")
    b = AuditInstrument("batched", batch_size=10)
    sign_at = [i + 1 for i in range(25) if b.append()["signatures"]]
    check("25 records produce 2 signatures", b.signatures == 2, f"got {b.signatures}")
    check("signatures at records 10 and 20", sign_at == [10, 20], f"got {sign_at}")

    print("3. block structure and mode randomisation")
    rng = random.Random(7)
    orders = set()
    records = []
    for block in range(1, 21):
        order = list(MODES)
        rng.shuffle(order)
        orders.add(tuple(order))
        for position, mode in enumerate(order, start=1):
            records.append({"block": block, "position": position, "mode": mode,
                            "latency_ms": {"plain": 1000.0, "transport": 1001.0,
                                           "full": 1010.0}[mode] + block * 0.1,
                            "response_chars": 10, "response_sha256": "a" * 64})
    check("every block contains all modes once",
          all(sorted(r["mode"] for r in records if r["block"] == k) == sorted(MODES)
              for k in range(1, 21)))
    check("mode order varies across blocks", len(orders) > 1,
          f"only {len(orders)} distinct order(s)")

    print("4. summaries and response-equality checks")
    su = [summarise(records, m) for m in MODES]
    check("three summaries produced", len([s for s in su if s]) == 3)
    check("identical response hashes detected",
          all(s["response_hashes_identical"] for s in su if s))
    check("run count per mode equals block count",
          all(s["runs"] == 20 for s in su if s))

    print("5. paired differences")
    d = paired_difference(records, "transport", "full", 2000, 42)
    check("full minus transport equals 9.000 ms",
          abs(d["mean_ms"] - 9.0) < 1e-6, f"got {d['mean_ms']}")
    check("bootstrap interval contains the mean",
          d["bootstrap95"][0] <= d["mean_ms"] <= d["bootstrap95"][1])

    print("6. JSON serialisation")
    payload = {"design": "self-test", "summaries": su, "paired": {"x": d},
               "records": records[:6]}
    text = json.dumps(payload)
    check("payload serialises", len(text) > 100)
    check("payload round-trips", json.loads(text)["design"] == "self-test")

    print(f"\n=== self-test: {'PASS' if failures == 0 else f'{failures} FAILED'} ===")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--blocks", type=int, default=100)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--max-new-tokens", type=int, default=64)
    ap.add_argument("--dtype", default="bf16", choices=["bf16", "fp16", "fp32"])
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--seed", type=int, default=20260915)
    ap.add_argument("--bootstrap-resamples", type=int, default=10000)
    ap.add_argument("--audit-schedule", default="per-record",
                    choices=["per-record", "batched"])
    ap.add_argument("--audit-batch-size", type=int, default=10)
    ap.add_argument("--skip-admission-startup", action="store_true",
                    help="skip the artifact-hashing admission start-up measurement")
    ap.add_argument("--cache-dir", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--self-test", action="store_true",
                    help="validate instrumentation, block structure, paired "
                         "statistics and output format without loading a model")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    ap.error(
        "benchmark execution is disabled: this scaffold contains counter-only "
        "audit instrumentation and is not connected to the deployed PQGuard "
        "AEAD/signing/persistence pipeline; use --self-test only"
    )

    if not args.out:
        ap.error("--out is required unless --self-test is used")
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    if args.cache_dir:
        os.environ["HF_HOME"] = args.cache_dir

    import torch
    print(f"torch {torch.__version__}  cuda={torch.cuda.is_available()}  "
          f"device={torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'cpu'}")

    # ---- admission / startup, excluded from serving -----------------------
    model_path = Path(args.model)
    startup: Dict[str, Any] = {"model_ref": args.model}
    if model_path.is_dir() and not args.skip_admission_startup:
        t0 = time.perf_counter()
        total = 0
        for root, _dirs, files in os.walk(model_path):
            for name in sorted(files):
                p = Path(root) / name
                h = hashlib.sha256()
                with p.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        total += len(chunk)
                        h.update(chunk)
        startup["artifact_hash_ms"] = (time.perf_counter() - t0) * 1e3
        startup["artifact_bytes"] = total
        startup["effective_read_and_digest_mb_s"] = (
            total / 1e6 / ((time.perf_counter() - t0))
        )
        print(f"admission hashing: {startup['artifact_hash_ms']:.1f} ms "
              f"for {total/1e9:.2f} GB")

    t0 = time.perf_counter()
    tok, model = load_model(args.model, args.dtype, args.device)
    startup["model_load_ms"] = (time.perf_counter() - t0) * 1e3

    instrument = AuditInstrument(args.audit_schedule, args.audit_batch_size)
    rng = random.Random(args.seed)
    records: List[Dict[str, Any]] = []

    total_blocks = args.warmup + args.blocks
    for block in range(1, total_blocks + 1):
        prompt = PROMPTS[rng.randrange(len(PROMPTS))]
        order = list(MODES)
        rng.shuffle(order)  # randomized order within the block
        for position, mode in enumerate(order, start=1):
            rec = run_block(tok, model, mode, prompt, args.max_new_tokens,
                            instrument, args.device)
            if block > args.warmup:
                rec.update({"block": block - args.warmup, "position": position})
                records.append(rec)
        if block <= args.warmup or block % 10 == 0:
            snap = instrument.snapshot()
            print(f"  block {block}/{total_blocks}  sig={snap['signatures']} "
                  f"flush={snap['flushes']} mode_last={order[-1]}")

    summaries = [summarise(records, m) for m in MODES]
    payload = {
        "design": "randomized_complete_block",
        "blocks": args.blocks,
        "warmup_blocks_excluded": args.warmup,
        "seed": args.seed,
        "bootstrap_resamples": args.bootstrap_resamples,
        "platform_name": (torch.cuda.get_device_name(0)
                          if torch.cuda.is_available() else "cpu"),
        "model_ref": args.model,
        "max_new_tokens": args.max_new_tokens,
        "dtype": args.dtype,
        "audit_schedule": args.audit_schedule,
        "audit_batch_size": args.audit_batch_size,
        "startup": startup,
        "audit_instrumentation": instrument.snapshot(),
        "summaries": [s for s in summaries if s],
        "paired": {
            "full_minus_transport_ms": paired_difference(
                records, "transport", "full", args.bootstrap_resamples, args.seed),
            "full_minus_plain_ms": paired_difference(
                records, "plain", "full", args.bootstrap_resamples, args.seed),
            "transport_minus_plain_ms": paired_difference(
                records, "plain", "transport", args.bootstrap_resamples, args.seed),
        },
        "records": records,
    }
    outfile = outdir / f"gpu_serving_{args.audit_schedule}.json"
    outfile.write_text(json.dumps(payload, indent=1), encoding="utf-8")

    print("\n=== summaries ===")
    for s in payload["summaries"]:
        print(f"  {s['scheme']:22} p50={s['p50_ms']:9.2f} ms  runs={s['runs']}  "
              f"hashes_identical={s['response_hashes_identical']}")
    print("\n=== paired differences (block bootstrap) ===")
    for k, v in payload["paired"].items():
        if v:
            print(f"  {k:28} mean={v['mean_ms']:+9.3f} ms  "
                  f"95% CI [{v['bootstrap95'][0]:+.3f}, {v['bootstrap95'][1]:+.3f}]  n={v['n_blocks']}")
    print(f"\n=== audit instrumentation ===\n  {payload['audit_instrumentation']}")
    print(f"\nwritten {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
