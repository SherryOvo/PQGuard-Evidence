#!/usr/bin/env python3
"""Instrumented A800 serving benchmark with real PQGuard post-processing.

The benchmark uses randomized complete blocks.  Each block runs the same prompt
in three modes: model generation only, generation plus AES-256-GCM response
protection, and generation plus response protection plus the evaluated audit
schedule.  The audit schedule signs every completion record and signs one
checkpoint after each ten-record batch.  Every stage and every operation count
is retained per request so the result can support attribution rather than only
a mode-level latency comparison.

The serving timer starts immediately before ``model.generate`` and ends after
the mode-specific post-processing.  Tokenization, model loading, key generation,
and result verification are outside that interval.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence


MODES = ("plain", "transport", "full")
ENTRY_DOMAIN = b"PQGuard-Audit-Entry-v2\x00"
CHECKPOINT_DOMAIN = b"PQGuard-Audit-Checkpoint-v2\x00"
GENESIS_HASH = "0" * 64
PROMPTS = (
    "Explain the difference between a hash chain and a Merkle tree.",
    "Summarize why replay protection requires atomic check-and-insert.",
    "Describe how a KEM differs from a key-agreement protocol.",
    "What does a signed manifest guarantee about a model snapshot?",
    "Why can a consistent log suffix rollback pass local verification?",
    "Explain the role of associated data in an AEAD construction.",
)


def canonical_bytes(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def percentile(values: Sequence[float], p: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile of empty values")
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * p
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


class Signer(Protocol):
    name: str
    public_key: bytes
    signature_bytes: int

    def sign(self, message: bytes) -> bytes: ...

    def verify(self, message: bytes, signature: bytes) -> bool: ...


class OQSAuditSigner:
    """Real liboqs hash-based signature backend."""

    CANDIDATES = (
        "SLH_DSA_PURE_SHA2_128F",
        "SPHINCS+-SHA2-128f-simple",
        "SLH_DSA_PURE_SHAKE_128F",
        "SPHINCS+-SHAKE-128f-simple",
    )

    def __init__(self, mechanism: Optional[str] = None) -> None:
        import oqs

        available = list(oqs.get_enabled_sig_mechanisms())
        if mechanism is None:
            mechanism = next((m for m in self.CANDIDATES if m in available), None)
        if not mechanism or mechanism not in available:
            raise RuntimeError(
                f"requested audit signature is unavailable; enabled={available}"
            )
        self._oqs = oqs
        self.mechanism = mechanism
        with oqs.Signature(mechanism) as signature:
            self.public_key = signature.generate_keypair()
            self._secret_key = signature.export_secret_key()
        probe = self.sign(b"PQGuard signature-size probe")
        if not self.verify(b"PQGuard signature-size probe", probe):
            raise RuntimeError("audit signature self-test failed")
        self.signature_bytes = len(probe)
        self.name = f"liboqs:{mechanism}"

    def sign(self, message: bytes) -> bytes:
        with self._oqs.Signature(
            self.mechanism, secret_key=self._secret_key
        ) as signature:
            return signature.sign(message)

    def verify(self, message: bytes, signature_bytes: bytes) -> bool:
        with self._oqs.Signature(self.mechanism) as signature:
            return bool(signature.verify(message, signature_bytes, self.public_key))


class HMACSelfTestSigner:
    """Functional self-test backend; never used for measurements."""

    name = "HMAC self-test only"
    public_key = b""
    signature_bytes = 32

    def __init__(self) -> None:
        self._key = b"PQGuard self-test key"

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(message), signature)


@dataclass
class AuditWork:
    hash_ms: float = 0.0
    entry_sign_ms: float = 0.0
    checkpoint_build_ms: float = 0.0
    checkpoint_sign_ms: float = 0.0
    persist_ms: float = 0.0
    entry_signatures: int = 0
    checkpoint_signatures: int = 0
    write_count: int = 0
    durable_write_count: int = 0
    bytes_written: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


class SignedBatchAuditLog:
    """Per-record signatures plus a signed checkpoint every ``batch_size``."""

    def __init__(
        self,
        signer: Signer,
        output: Path,
        batch_size: int = 10,
        fsync: bool = False,
    ) -> None:
        self.signer = signer
        self.output = output
        self.batch_size = batch_size
        self.fsync = fsync
        self.previous_hash = GENESIS_HASH
        self.previous_checkpoint_hash = GENESIS_HASH
        self.sequence = 0
        self.pending: List[Dict[str, Any]] = []
        self.entries: List[Dict[str, Any]] = []
        self.checkpoints: List[Dict[str, Any]] = []
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text("", encoding="utf-8")

    def append(
        self,
        session_id: str,
        policy_digest: str,
        prompt: str,
        response: str,
    ) -> AuditWork:
        work = AuditWork()
        t0 = time.perf_counter_ns()
        entry = {
            "session_id": session_id,
            "sequence": self.sequence,
            "policy_version": 1,
            "policy_digest": policy_digest,
            "prompt_hash": sha256_hex(prompt.encode("utf-8")),
            "response_hash": sha256_hex(response.encode("utf-8")),
            "previous_hash": self.previous_hash,
            "timestamp_ns": time.time_ns(),
        }
        message = ENTRY_DOMAIN + canonical_bytes(entry)
        entry_hash = sha256_hex(message)
        work.hash_ms = (time.perf_counter_ns() - t0) / 1e6

        t1 = time.perf_counter_ns()
        signature = self.signer.sign(message)
        work.entry_sign_ms = (time.perf_counter_ns() - t1) / 1e6
        work.entry_signatures = 1
        record = {
            "kind": "entry",
            "entry": entry,
            "entry_hash": entry_hash,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        self.entries.append(record)
        self.pending.append(record)
        self.previous_hash = entry_hash
        self.sequence += 1

        if len(self.pending) == self.batch_size:
            self._checkpoint_and_persist(work)
        return work

    def _checkpoint_and_persist(self, work: AuditWork) -> None:
        t0 = time.perf_counter_ns()
        first = self.pending[0]["entry"]["sequence"]
        last = self.pending[-1]["entry"]["sequence"]
        batch_digest = sha256_hex(
            b"".join(bytes.fromhex(item["entry_hash"]) for item in self.pending)
        )
        checkpoint = {
            "start_sequence": first,
            "end_sequence": last,
            "leaf_count": len(self.pending),
            "batch_digest": batch_digest,
            "terminal_entry_hash": self.pending[-1]["entry_hash"],
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
            "timestamp_ns": time.time_ns(),
        }
        checkpoint_message = CHECKPOINT_DOMAIN + canonical_bytes(checkpoint)
        checkpoint_hash = sha256_hex(checkpoint_message)
        work.checkpoint_build_ms = (time.perf_counter_ns() - t0) / 1e6

        t1 = time.perf_counter_ns()
        checkpoint_signature = self.signer.sign(checkpoint_message)
        work.checkpoint_sign_ms = (time.perf_counter_ns() - t1) / 1e6
        work.checkpoint_signatures = 1
        checkpoint_record = {
            "kind": "checkpoint",
            "checkpoint": checkpoint,
            "checkpoint_hash": checkpoint_hash,
            "signature_b64": base64.b64encode(checkpoint_signature).decode("ascii"),
        }
        self.checkpoints.append(checkpoint_record)

        t2 = time.perf_counter_ns()
        payload = "".join(
            json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
            for item in [*self.pending, checkpoint_record]
        ).encode("utf-8")
        with self.output.open("ab", buffering=0) as stream:
            stream.write(payload)
            work.write_count = 1
            if self.fsync:
                os.fsync(stream.fileno())
                work.durable_write_count = 1
        work.persist_ms = (time.perf_counter_ns() - t2) / 1e6
        work.bytes_written = len(payload)
        self.previous_checkpoint_hash = checkpoint_hash
        self.pending = []

    def verify_all(self) -> Dict[str, Any]:
        previous = GENESIS_HASH
        entries_valid = 0
        for record in self.entries:
            entry = record["entry"]
            message = ENTRY_DOMAIN + canonical_bytes(entry)
            signature = base64.b64decode(record["signature_b64"])
            valid = (
                entry["previous_hash"] == previous
                and sha256_hex(message) == record["entry_hash"]
                and self.signer.verify(message, signature)
            )
            if not valid:
                break
            previous = record["entry_hash"]
            entries_valid += 1

        previous_checkpoint = GENESIS_HASH
        checkpoints_valid = 0
        for record in self.checkpoints:
            checkpoint = record["checkpoint"]
            message = CHECKPOINT_DOMAIN + canonical_bytes(checkpoint)
            signature = base64.b64decode(record["signature_b64"])
            valid = (
                checkpoint["previous_checkpoint_hash"] == previous_checkpoint
                and sha256_hex(message) == record["checkpoint_hash"]
                and self.signer.verify(message, signature)
            )
            if not valid:
                break
            previous_checkpoint = record["checkpoint_hash"]
            checkpoints_valid += 1
        return {
            "entries": len(self.entries),
            "entries_valid": entries_valid,
            "checkpoints": len(self.checkpoints),
            "checkpoints_valid": checkpoints_valid,
            "pending_entries": len(self.pending),
            "all_valid": (
                entries_valid == len(self.entries)
                and checkpoints_valid == len(self.checkpoints)
                and not self.pending
            ),
        }


def bootstrap_mean_ci(
    values: Sequence[float], resamples: int, seed: int
) -> List[float]:
    rng = random.Random(seed)
    n = len(values)
    sampled = sorted(
        statistics.fmean(rng.choices(values, k=n)) for _ in range(resamples)
    )
    return [percentile(sampled, 0.025), percentile(sampled, 0.975)]


def summarise(records: Sequence[Dict[str, Any]], mode: str) -> Dict[str, Any]:
    selected = [r for r in records if r["mode"] == mode]
    values = [float(r["total_ms"]) for r in selected]
    return {
        "mode": mode,
        "n": len(values),
        "mean_ms": statistics.fmean(values),
        "std_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def paired_summary(
    records: Sequence[Dict[str, Any]],
    baseline: str,
    treatment: str,
    resamples: int,
    seed: int,
) -> Dict[str, Any]:
    blocks: Dict[int, Dict[str, float]] = {}
    for record in records:
        blocks.setdefault(int(record["block"]), {})[record["mode"]] = float(
            record["total_ms"]
        )
    diffs = [
        values[treatment] - values[baseline]
        for values in blocks.values()
        if baseline in values and treatment in values
    ]
    baseline_values = [
        values[baseline]
        for values in blocks.values()
        if baseline in values and treatment in values
    ]
    mean = statistics.fmean(diffs)
    return {
        "baseline": baseline,
        "treatment": treatment,
        "n_blocks": len(diffs),
        "mean_difference_ms": mean,
        "bootstrap95_ms": bootstrap_mean_ci(diffs, resamples, seed),
        "relative_to_baseline_mean_percent": (
            mean / statistics.fmean(baseline_values) * 100.0
        ),
        "fraction_treatment_faster": sum(x < 0 for x in diffs) / len(diffs),
    }


def command_output(command: Sequence[str]) -> str:
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)
    except Exception as exc:
        return f"unavailable: {exc!r}"


def environment() -> Dict[str, Any]:
    import torch
    import transformers

    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version,
        "platform": platform.platform(),
        "torch": torch.__version__,
        "torch_cuda": torch.version.cuda,
        "transformers": transformers.__version__,
        "gpu": torch.cuda.get_device_name(0),
        "gpu_memory_bytes": torch.cuda.get_device_properties(0).total_memory,
        "nvidia_smi": command_output(
            [
                "nvidia-smi",
                "--query-gpu=name,uuid,driver_version,memory.total",
                "--format=csv,noheader",
            ]
        ).strip(),
        "cpu_count": os.cpu_count(),
    }


def load_model(model_path: str):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch.bfloat16,
        device_map={"": 0},
        low_cpu_mem_usage=True,
        local_files_only=True,
    )
    model.eval()
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token_id = tokenizer.eos_token_id
    return tokenizer, model


def generate(model, inputs: Dict[str, Any], max_new_tokens: int) -> tuple[str, int, float]:
    import torch

    torch.cuda.synchronize()
    t0 = time.perf_counter_ns()
    with torch.inference_mode():
        output = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            use_cache=True,
            pad_token_id=model.config.eos_token_id,
        )
    torch.cuda.synchronize()
    elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
    prompt_tokens = inputs["input_ids"].shape[1]
    generated = output[0][prompt_tokens:]
    return generated, int(generated.shape[0]), elapsed_ms


def run_experiment(args: argparse.Namespace) -> Dict[str, Any]:
    import torch
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    env = environment()
    signer = OQSAuditSigner(args.audit_mechanism)
    tokenizer, model = load_model(args.model)
    session_key = hashlib.sha256(b"PQGuard measured session key").digest()
    policy_digest = sha256_hex(b"PQGuard measured policy v1")
    rng = random.Random(args.seed)

    warmup_logger = SignedBatchAuditLog(
        signer, output / "warmup_audit.jsonl", args.batch_size, args.fsync
    )
    measured_logger = SignedBatchAuditLog(
        signer, output / "measured_audit.jsonl", args.batch_size, args.fsync
    )
    records: List[Dict[str, Any]] = []
    run_counter = 0

    for physical_block in range(1, args.warmup + args.blocks + 1):
        measured = physical_block > args.warmup
        block = physical_block - args.warmup
        prompt_id = rng.randrange(len(PROMPTS))
        prompt = PROMPTS[prompt_id]
        tokens = tokenizer(prompt, return_tensors="pt")
        inputs = {key: value.to("cuda") for key, value in tokens.items()}
        order = list(MODES)
        rng.shuffle(order)
        logger = measured_logger if measured else warmup_logger

        for position, mode in enumerate(order, start=1):
            run_counter += 1
            total_start = time.perf_counter_ns()
            generated_tokens, output_tokens, generation_ms = generate(
                model, inputs, args.max_new_tokens
            )
            response = tokenizer.decode(generated_tokens, skip_special_tokens=True)

            encrypt_ms = 0.0
            ciphertext_bytes = 0
            work = AuditWork()
            if mode in ("transport", "full"):
                aad = canonical_bytes(
                    {
                        "session_id": "a800-measured-session",
                        "block": block if measured else -physical_block,
                        "mode": mode,
                    }
                )
                nonce = run_counter.to_bytes(12, "big")
                t0 = time.perf_counter_ns()
                ciphertext = AESGCM(session_key).encrypt(
                    nonce, response.encode("utf-8"), aad
                )
                encrypt_ms = (time.perf_counter_ns() - t0) / 1e6
                ciphertext_bytes = len(ciphertext) + len(nonce)

            if mode == "full":
                work = logger.append(
                    "a800-measured-session", policy_digest, prompt, response
                )
            total_ms = (time.perf_counter_ns() - total_start) / 1e6

            if measured:
                record = {
                    "block": block,
                    "position": position,
                    "mode": mode,
                    "prompt_id": prompt_id,
                    "prompt_sha256": sha256_hex(prompt.encode("utf-8")),
                    "response_sha256": sha256_hex(response.encode("utf-8")),
                    "response_chars": len(response),
                    "output_tokens": output_tokens,
                    "generation_ms": generation_ms,
                    "response_encrypt_ms": encrypt_ms,
                    "ciphertext_bytes": ciphertext_bytes,
                    **work.as_dict(),
                    "audit_total_ms": (
                        work.hash_ms
                        + work.entry_sign_ms
                        + work.checkpoint_build_ms
                        + work.checkpoint_sign_ms
                        + work.persist_ms
                    ),
                    "total_ms": total_ms,
                    "gpu_memory_allocated_bytes": torch.cuda.memory_allocated(),
                    "gpu_memory_reserved_bytes": torch.cuda.memory_reserved(),
                }
                records.append(record)

        if physical_block <= args.warmup or block % 10 == 0:
            print(
                f"block {physical_block}/{args.warmup + args.blocks} "
                f"measured={measured} order={','.join(order)}",
                flush=True,
            )

    if measured_logger.pending:
        raise RuntimeError(
            "measured full-mode count is not divisible by batch size; rerun with "
            "--blocks divisible by --batch-size so every persistence cost is assigned"
        )
    verification = measured_logger.verify_all()
    by_block: Dict[int, List[Dict[str, Any]]] = {}
    for record in records:
        by_block.setdefault(record["block"], []).append(record)
    response_match = all(
        len({record["response_sha256"] for record in values}) == 1
        and len({record["output_tokens"] for record in values}) == 1
        for values in by_block.values()
    )
    mode_complete = all(
        sorted(record["mode"] for record in values) == sorted(MODES)
        for values in by_block.values()
    )
    full_records = [record for record in records if record["mode"] == "full"]
    counters = {
        key: sum(int(record[key]) for record in full_records)
        for key in (
            "entry_signatures",
            "checkpoint_signatures",
            "write_count",
            "durable_write_count",
            "bytes_written",
        )
    }
    validation = {
        "record_count": len(records),
        "expected_record_count": args.blocks * len(MODES),
        "each_block_has_all_modes": mode_complete,
        "response_hash_and_length_match_within_block": response_match,
        "all_audit_signatures_and_links_verify": verification["all_valid"],
        "audit_verification": verification,
        "full_request_count": len(full_records),
        "entry_signature_count_matches_full_requests": (
            counters["entry_signatures"] == len(full_records)
        ),
        "checkpoint_count_matches_schedule": (
            counters["checkpoint_signatures"]
            == len(full_records) // args.batch_size
        ),
    }
    if not all(
        value
        for key, value in validation.items()
        if key not in {"record_count", "expected_record_count", "audit_verification", "full_request_count"}
    ):
        raise RuntimeError(f"validation failed: {validation}")

    result = {
        "schema": "pqguard-a800-integrated-v1",
        "design": "randomized complete block",
        "model": str(Path(args.model).resolve()),
        "dtype": "bfloat16",
        "blocks": args.blocks,
        "warmup_blocks_excluded": args.warmup,
        "max_new_tokens": args.max_new_tokens,
        "seed": args.seed,
        "bootstrap_resamples": args.bootstrap_resamples,
        "audit": {
            "algorithm": signer.name,
            "signature_bytes": signer.signature_bytes,
            "batch_size": args.batch_size,
            "fsync": args.fsync,
            "public_key_sha256": sha256_hex(signer.public_key),
            "counters": counters,
        },
        "environment": env,
        "summaries": {mode: summarise(records, mode) for mode in MODES},
        "paired": {
            "transport_minus_plain": paired_summary(
                records, "plain", "transport", args.bootstrap_resamples, args.seed
            ),
            "full_minus_transport": paired_summary(
                records, "transport", "full", args.bootstrap_resamples, args.seed + 1
            ),
            "full_minus_plain": paired_summary(
                records, "plain", "full", args.bootstrap_resamples, args.seed + 2
            ),
        },
        "validation": validation,
        "records": records,
    }
    (output / "integrated_results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "environment.json").write_text(
        json.dumps(env, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"paired": result["paired"], "validation": validation}, indent=2))
    return result


def self_test(output: Path) -> None:
    signer = HMACSelfTestSigner()
    logger = SignedBatchAuditLog(signer, output / "self_test.jsonl", batch_size=10)
    counters = []
    for i in range(20):
        counters.append(logger.append("sid", "a" * 64, f"p{i}", f"r{i}"))
    report = logger.verify_all()
    assert report["all_valid"], report
    assert sum(item.entry_signatures for item in counters) == 20
    assert sum(item.checkpoint_signatures for item in counters) == 2
    assert sum(item.write_count for item in counters) == 2
    synthetic = []
    for block in range(1, 21):
        for mode, value in (("plain", 100.0), ("transport", 101.0), ("full", 110.0)):
            synthetic.append({"block": block, "mode": mode, "total_ms": value + block / 100})
    paired = paired_summary(synthetic, "transport", "full", 1000, 7)
    assert abs(paired["mean_difference_ms"] - 9.0) < 1e-9
    print(json.dumps({"audit": report, "paired": paired}, indent=2))
    print("SELF-TEST PASS")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model")
    parser.add_argument("--output", required=True)
    parser.add_argument("--blocks", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--max-new-tokens", type=int, default=64)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20261005)
    parser.add_argument("--bootstrap-resamples", type=int, default=10000)
    parser.add_argument("--audit-mechanism", default=None)
    parser.add_argument("--fsync", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if args.self_test:
        self_test(output)
        return 0
    if not args.model:
        raise SystemExit("--model is required unless --self-test is used")
    run_experiment(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
