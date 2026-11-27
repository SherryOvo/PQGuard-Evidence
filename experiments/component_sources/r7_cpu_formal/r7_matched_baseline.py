#!/usr/bin/env python3
"""Run matched classical/PQ transport and CBAS lifecycle measurements."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import median
from typing import Any

import cryptography
import oqs
import psutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from r7_crypto_profiles import build_profile, canonical, sha256
from r7_witness import witness_message
from r11_durable_lifecycle import DurableLifecycleStore


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    position = (len(ordered) - 1) * p
    lo = int(position)
    hi = min(lo + 1, len(ordered) - 1)
    fraction = position - lo
    return ordered[lo] * (1 - fraction) + ordered[hi] * fraction


class WitnessClient:
    def __init__(self, host: str, port: int, timeout: float = 15.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def call(self, request: dict[str, Any]) -> dict[str, Any]:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as conn:
            conn.sendall(canonical(request) + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                raw += chunk
        return json.loads(raw)

    def publish(self, stream: str, counter: int, digest: str, signature: bytes) -> dict[str, Any]:
        return self.call(
            {
                "op": "publish",
                "stream": stream,
                "counter": counter,
                "digest": digest,
                "signature_hex": signature.hex(),
            }
        )

    def fetch(self, stream: str) -> dict[str, Any]:
        return self.call({"op": "fetch", "stream": stream})


def run_request(
    profile: Any,
    session: Any,
    full: bool,
    store: DurableLifecycleStore | None,
    policy_digest: str,
    request_index: int,
    payload_bytes: int,
) -> dict[str, Any]:
    prompt = (f"request-{request_index}:".encode() + b"x" * payload_bytes)[:payload_bytes]
    prompt_hash = sha256(prompt)
    total_start = time.perf_counter_ns()
    sid = session.sid
    request_key, request_nonce = profile.record_material(session, "request", request_index)
    request_aad = profile.associated_data(session, "request", request_index)
    request_ciphertext = AESGCM(request_key).encrypt(request_nonce, prompt, request_aad)
    decrypted_prompt = AESGCM(request_key).decrypt(request_nonce, request_ciphertext, request_aad)
    if decrypted_prompt != prompt:
        raise RuntimeError("request AEAD mismatch")
    admission_ns = 0
    if full:
        assert store is not None
        _, admission_ns = store.admit(sid, request_index, prompt_hash, policy_digest)
    response = hashlib.sha256(b"deterministic-cpu-response\0" + decrypted_prompt).digest()
    response_key, response_nonce = profile.record_material(session, "response", request_index)
    response_aad = profile.associated_data(session, "response", request_index)
    response_ciphertext = AESGCM(response_key).encrypt(response_nonce, response, response_aad)
    received_response = AESGCM(response_key).decrypt(response_nonce, response_ciphertext, response_aad)
    if received_response != response:
        raise RuntimeError("response AEAD mismatch")
    lifecycle = {
        "lifecycle_ns": 0,
        "entry_digest": None,
        "audit_verified": None,
        "witness_counter": None,
        "witness_digest": None,
        "witness_reason": None,
    }
    if full:
        lifecycle = store.complete(sid, request_index, sha256(response))
    total_ns = time.perf_counter_ns() - total_start
    return {
        "sid": sid,
        "request_index": request_index,
        "success": True,
        "setup_ns": 0,
        "admission_ns": admission_ns,
        "lifecycle_ns": lifecycle["lifecycle_ns"],
        "total_ns": total_ns,
        "wire_bytes": len(request_ciphertext) + len(response_ciphertext),
        "bundle_verified": session.bundle_verified,
        "policy_verified": session.policy_verified,
        **{key: lifecycle[key] for key in lifecycle if key != "lifecycle_ns"},
    }


def wait_for_witness(ready_path: Path, process: subprocess.Popen[str]) -> tuple[str, int]:
    for _ in range(200):
        if ready_path.exists():
            data = json.loads(ready_path.read_text(encoding="utf-8"))
            return data["host"], int(data["port"])
        if process.poll() is not None:
            raise RuntimeError("witness process exited before becoming ready")
        time.sleep(0.05)
    raise TimeoutError("witness readiness timeout")


def environment_record() -> dict[str, Any]:
    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "memory_bytes": psutil.virtual_memory().total,
        "cryptography": cryptography.__version__,
        "liboqs_version": oqs.oqs_version(),
        "liboqs_python_version": oqs.oqs_python_version(),
        "pid": os.getpid(),
    }


def run_witness_fault_tests(profiles: dict[str, Any], witness: WitnessClient) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for profile_name, profile in profiles.items():
        stream = f"{profile_name}-fault"

        def signed(counter: int, digest: str) -> bytes:
            return profile.sign_audit(witness_message(stream, counter, digest))

        d1, d2, conflict, d3, gap = [sha256(f"{profile_name}:{label}".encode()) for label in ("1", "2", "x", "3", "4")]
        cases = [
            ("initial", witness.publish(stream, 1, d1, signed(1, d1)), True, "accepted"),
            ("exact_replay", witness.publish(stream, 1, d1, signed(1, d1)), True, "idempotent"),
            ("advance", witness.publish(stream, 2, d2, signed(2, d2)), True, "accepted"),
            ("regression", witness.publish(stream, 1, d1, signed(1, d1)), False, "counter_regression"),
            (
                "same_counter_conflict",
                witness.publish(stream, 2, conflict, signed(2, conflict)),
                False,
                "same_counter_conflict",
            ),
            ("invalid_signature", witness.publish(stream, 3, d3, b"invalid"), False, "invalid_signature"),
            ("counter_gap", witness.publish(stream, 4, gap, signed(4, gap)), False, "counter_gap"),
            ("valid_recovery", witness.publish(stream, 3, d3, signed(3, d3)), True, "accepted"),
        ]
        for case, response, expected_ok, expected_reason in cases:
            results.append(
                {
                    "profile": profile_name,
                    "case": case,
                    "response": response,
                    "expected_ok": expected_ok,
                    "expected_reason": expected_reason,
                    "passed": response.get("ok") is expected_ok and response.get("reason") == expected_reason,
                }
            )
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8, 32, 64])
    parser.add_argument("--requests-factor", type=int, default=2)
    parser.add_argument("--minimum-requests", type=int, default=32)
    parser.add_argument("--payload-bytes", type=int, default=1024)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "raw").mkdir()
    (args.out / "state").mkdir()
    policy_digest = sha256(b"PQGuard R7 fixed CPU policy")
    profiles = {name: build_profile(name, policy_digest) for name in ("classical", "post_quantum")}
    streams = [f"{profile}-cbas-c{c}-r{r}" for profile in profiles for c in args.concurrency for r in range(args.repetitions)]
    streams.extend(f"{profile}-fault" for profile in profiles)
    registry = {}
    for stream in streams:
        profile_name = stream.split("-cbas-")[0] if "-cbas-" in stream else stream.removesuffix("-fault")
        registry[stream] = {
            "algorithm": profiles[profile_name].audit_algorithm,
            "public_key_hex": profiles[profile_name].audit_public.hex(),
        }
    registry_path = args.out / "witness_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
    ready_path = args.out / "witness_ready.json"
    witness_db = args.out / "state" / "witness.sqlite3"
    witness_log = (args.out / "witness_process.log").open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("r7_witness.py")),
            "--db",
            str(witness_db),
            "--registry",
            str(registry_path),
            "--ready",
            str(ready_path),
        ],
        stdout=witness_log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    host, port = wait_for_witness(ready_path, process)
    witness = WitnessClient(host, port)
    raw_path = args.out / "raw" / "requests.jsonl"
    cells: list[dict[str, Any]] = []
    fault_results: list[dict[str, Any]] = []
    try:
        with raw_path.open("w", encoding="utf-8") as raw_file:
            for profile_name, profile in profiles.items():
                for full in (False, True):
                    mode = f"{profile_name}_{'cbas' if full else 'transport'}"
                    for concurrency in args.concurrency:
                        request_count = max(args.minimum_requests, concurrency * args.requests_factor)
                        for repetition in range(args.repetitions):
                            stream = f"{profile_name}-cbas-c{concurrency}-r{repetition}"
                            session = profile.establish_session(
                                canonical(
                                    {
                                        "concurrency": concurrency,
                                        "mode": mode,
                                        "policy": policy_digest,
                                        "repetition": repetition,
                                        "request_count": request_count,
                                    }
                                )
                            )
                            store = None
                            if full:
                                store = DurableLifecycleStore(
                                    args.out / "state" / f"{stream}.sqlite3", profile, stream, witness
                                )
                            start = time.perf_counter_ns()
                            records: list[dict[str, Any]] = []
                            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                                futures = [
                                    executor.submit(
                                        run_request,
                                        profile,
                                        session,
                                        full,
                                        store,
                                        policy_digest,
                                        index,
                                        args.payload_bytes,
                                    )
                                    for index in range(request_count)
                                ]
                                for future in as_completed(futures):
                                    records.append(future.result())
                            wall_ns = time.perf_counter_ns() - start
                            for record in records:
                                record.update(
                                    {
                                        "mode": mode,
                                        "profile": profile_name,
                                        "full_cbas": full,
                                        "concurrency": concurrency,
                                        "repetition": repetition,
                                        "request_count": request_count,
                                        "payload_bytes": args.payload_bytes,
                                        "policy_digest": policy_digest,
                                    }
                                )
                                raw_file.write(json.dumps(record, sort_keys=True) + "\n")
                            integrity = store.integrity() if store else None
                            if store:
                                head = witness.fetch(stream)
                                if head.get("counter") != integrity["counter"] or head.get("digest") != integrity["head"]:
                                    raise RuntimeError("local and witness heads diverged")
                                if integrity["pending_witness_publications"] != 0:
                                    raise RuntimeError("witness outbox was not drained")
                                store.close()
                            totals_ms = [record["total_ns"] / 1e6 for record in records]
                            cells.append(
                                {
                                    "mode": mode,
                                    "profile": profile_name,
                                    "full_cbas": full,
                                    "concurrency": concurrency,
                                    "repetition": repetition,
                                    "requests": request_count,
                                    "successes": len(records),
                                    "session_setup_ms": session.setup_ns / 1e6,
                                    "session_wire_bytes": session.wire_bytes,
                                    "wall_ms": wall_ns / 1e6,
                                    "throughput_req_s": request_count / (wall_ns / 1e9),
                                    "median_ms": median(totals_ms),
                                    "p95_ms": percentile(totals_ms, 0.95),
                                    "integrity": integrity,
                                }
                            )
                            print(json.dumps(cells[-1], sort_keys=True), flush=True)
        fault_results = run_witness_fault_tests(profiles, witness)
        if not all(item["passed"] for item in fault_results):
            raise RuntimeError("one or more witness fault tests failed")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        witness_log.close()
    outage_rejected = False
    try:
        witness.call({"op": "health"})
    except OSError:
        outage_rejected = True
    ready_restart = args.out / "witness_ready_restart.json"
    restart_log = (args.out / "witness_restart.log").open("w", encoding="utf-8")
    restart = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("r7_witness.py")),
            "--db",
            str(witness_db),
            "--registry",
            str(registry_path),
            "--ready",
            str(ready_restart),
        ],
        stdout=restart_log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    restart_host, restart_port = wait_for_witness(ready_restart, restart)
    restart_client = WitnessClient(restart_host, restart_port)
    restart_heads = {name: restart_client.fetch(f"{name}-fault") for name in profiles}
    restart.terminate()
    restart.wait(timeout=5)
    restart_log.close()
    fault_report = {
        "cases": fault_results,
        "outage_fail_closed": outage_rejected,
        "restart_heads": restart_heads,
        "restart_persistence_passed": all(head.get("ok") and head.get("counter") == 3 for head in restart_heads.values()),
    }
    (args.out / "witness_fault_tests.json").write_text(json.dumps(fault_report, indent=2), encoding="utf-8")
    (args.out / "environment.json").write_text(json.dumps(environment_record(), indent=2), encoding="utf-8")
    (args.out / "public_material.json").write_text(
        json.dumps({name: profile.export_public() for name, profile in profiles.items()}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (args.out / "cells.json").write_text(json.dumps(cells, indent=2), encoding="utf-8")
    with (args.out / "cells.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = [key for key in cells[0] if key != "integrity"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in cells:
            writer.writerow({key: row[key] for key in fields})
    source_dir = args.out / "source"
    source_dir.mkdir()
    for name in (
        "r7_crypto_profiles.py",
        "r7_witness.py",
        "r11_durable_lifecycle.py",
        "r7_matched_baseline.py",
        "r7_validate.py",
        "test_r11_security_contract.py",
    ):
        source = Path(__file__).with_name(name)
        if source.exists():
            shutil.copy2(source, source_dir / name)


if __name__ == "__main__":
    main()
