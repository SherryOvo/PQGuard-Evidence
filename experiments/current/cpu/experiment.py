#!/usr/bin/env python3
"""Fresh-process CPU cells and real-store contract tests. No GPU or WAN claims."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from conventional_store import ConventionalStrongStore
from r7_crypto_profiles import build_profile, canonical, sha256
from r11_durable_lifecycle import DurableLifecycleStore


def atomic(path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def quantile(xs, p):
    ys = sorted(xs)
    if not ys:
        return None
    x = (len(ys) - 1) * p
    a = int(x)
    return ys[a] + (ys[min(a + 1, len(ys) - 1)] - ys[a]) * (x - a)


class WitnessClient:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.inject_transport_outage = False
        self.inject_lost_ack = False

    def call(self, data):
        if self.inject_transport_outage:
            raise ConnectionError("declared client-side pre-connect exception; NOT a routed outage")
        with socket.create_connection((self.host, self.port), timeout=8) as s:
            s.sendall(canonical(data) + b"\n")
            buf = bytearray()
            while not buf.endswith(b"\n"):
                part = s.recv(65536)
                if not part:
                    raise ConnectionError("witness connection closed")
                buf.extend(part)
                if len(buf) > 8_000_000:
                    raise ValueError("reply too large")
        answer = json.loads(buf)
        if self.inject_lost_ack and data.get("op") == "publish" and answer.get("ok"):
            self.inject_lost_ack = False
            raise ConnectionError("declared lost acknowledgement AFTER successful publication")
        return answer

    def publish(self, stream, counter, head, signature):
        return self.call(dict(op="publish", stream=stream, counter=counter,
                              digest=head, signature_hex=signature.hex()))

    def fetch(self, stream):
        return self.call(dict(op="fetch", stream=stream))


class Context:
    def __init__(self, out, implementation, profile_name):
        self.out = out
        out.mkdir(parents=True, exist_ok=False)
        self.policy = sha256(b"review-followup fixed 1024-byte CPU policy v1")
        self.profile = build_profile(profile_name, self.policy)
        self.session = self.profile.establish_session(canonical(dict(study="review-cpu", policy=self.policy)))
        self.stream = "review-cpu-stream"
        self.kind = implementation
        self.cls = DurableLifecycleStore if implementation == "submitted_cbas" else ConventionalStrongStore
        atomic(out / "public_material.json", self.profile.export_public())
        atomic(out / "registry.json", {self.stream: dict(algorithm=self.profile.audit_algorithm,
                                                        public_key_hex=self.profile.audit_public.hex())})
        self.start_witness()
        self.store = self.cls(out / "lifecycle.sqlite", self.profile, self.stream, self.witness)
        self.raw = (out / "requests.jsonl").open("a", buffering=1)
        self.raw_lock = threading.Lock()
        self.inflight = 0
        self.max_inflight = 0

    def start_witness(self):
        ready = self.out / "witness_ready.json"
        ready.unlink(missing_ok=True)
        self.wlog = (self.out / "witness.log").open("a")
        self.proc = subprocess.Popen([sys.executable, str(Path(__file__).with_name("r7_witness.py")),
                                      "--db", str(self.out / "witness.sqlite"),
                                      "--registry", str(self.out / "registry.json"),
                                      "--ready", str(ready)], stdout=self.wlog, stderr=subprocess.STDOUT)
        for _ in range(300):
            if ready.exists():
                value = json.loads(ready.read_text())
                self.witness = WitnessClient(value["host"], int(value["port"]))
                return
            if self.proc.poll() is not None:
                raise RuntimeError("witness failed at startup")
            time.sleep(.05)
        self.stop_witness()
        raise TimeoutError("witness readiness")

    def stop_witness(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.wlog.close()

    def close(self):
        self.raw.close()
        self.store.close()
        self.stop_witness()

    def request(self, seq, phase="measured", barrier=None):
        if barrier is not None:
            barrier.wait(timeout=120)
        start = time.perf_counter_ns()
        with self.raw_lock:
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
        prompt = (f"request-{seq}:".encode() + b"x" * 1024)[:1024]
        row = dict(seq=seq, sid=self.session.sid, phase=phase, prompt_hash=sha256(prompt),
                   policy=self.policy, success=False, pid=os.getpid(), start_ns=start,
                   response_released=False)
        try:
            key, nonce = self.profile.record_material(self.session, "request", seq)
            aad = self.profile.associated_data(self.session, "request", seq)
            ct = AESGCM(key).encrypt(nonce, prompt, aad)
            plain = AESGCM(key).decrypt(nonce, ct, aad)
            if plain != prompt:
                raise ValueError("request mismatch")
            _, admission_ns = self.store.admit(self.session.sid, seq, sha256(plain), self.policy)
            response = hashlib.sha256(b"deterministic-cpu-response\0" + plain).digest()
            key, nonce = self.profile.record_material(self.session, "response", seq)
            aad = self.profile.associated_data(self.session, "response", seq)
            encrypted = AESGCM(key).encrypt(nonce, response, aad)
            terminal = self.store.complete(self.session.sid, seq, sha256(response))
            # Response is released only AFTER witness acceptance.
            received = AESGCM(key).decrypt(nonce, encrypted, aad)
            if received != response:
                raise ValueError("response mismatch")
            row.update(success=True, response_released=True, response_hash=sha256(received),
                       admission_ns=admission_ns, lifecycle_ns=terminal["lifecycle_ns"],
                       witness_counter=terminal["witness_counter"],
                       witness_digest=terminal["witness_digest"],
                       application_ciphertext_bytes=len(ct) + len(encrypted))
        except Exception as e:
            row.update(error_type=type(e).__name__, error=str(e))
        finally:
            row["elapsed_ns"] = time.perf_counter_ns() - start
            with self.raw_lock:
                self.inflight -= 1
                self.raw.write(json.dumps(row, sort_keys=True) + "\n")
        return row


def run_cell(args):
    ctx = Context(args.out, args.implementation, args.profile)
    try:
        warmups = [ctx.request(seq, "warmup") for seq in range(args.warmup)]
        n = math.ceil(max(args.requests, args.workers * args.factor) / args.workers) * args.workers
        barrier = threading.Barrier(args.workers)
        start = time.perf_counter_ns()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            rows = list(pool.map(lambda i: ctx.request(1000 + i, barrier=barrier), range(n)))
        wall = time.perf_counter_ns() - start
        lat = [r["elapsed_ns"] / 1e6 for r in rows if r["success"]]
        integrity = ctx.store.integrity()
        head = ctx.witness.fetch(ctx.stream)
        result = dict(implementation=args.implementation, profile=args.profile,
                      repetition=args.repetition, workers=args.workers, requests=n,
                      successes=sum(r["success"] for r in rows), failures=sum(not r["success"] for r in rows),
                      warmups=args.warmup, warmup_successes=sum(r["success"] for r in warmups),
                      wall_ns=wall, throughput_success_s=len(lat) / (wall / 1e9),
                      median_ms=quantile(lat, .5), p95_ms=quantile(lat, .95),
                      max_in_flight=ctx.max_inflight, session_setup_ns=ctx.session.setup_ns,
                      pid=os.getpid(), integrity=integrity, witness_head=head,
                      scope="CPU; local encrypted record exchange; loopback witness; NO LLM",
                      timing="after start barrier to client response decoding after witness ack",
                      success_only_latency=True)
        result["passed"] = (all(r["success"] for r in warmups)
                            and result["failures"] == 0 and integrity["integrity"] == "ok"
                            and integrity["pending"] == integrity["pending_witness_publications"] == 0
                            and head.get("counter") == integrity["counter"]
                            and head.get("digest") == integrity["head"])
        atomic(args.out / "cell.json", result)
        print(json.dumps(result), flush=True)
        return 0 if result["passed"] else 1
    finally:
        ctx.close()


def run_contract(args):
    ctx = Context(args.out, args.implementation, args.profile)
    checks = []

    def check(name, ok, **detail):
        row = dict(case=name, passed=bool(ok), **detail)
        checks.append(row)
        atomic(args.out / "contract_progress.json", checks)

    try:
        rows = [ctx.request(x, "contract_out_of_order") for x in [9, 1, 100, 3]]
        check("out_of_order_and_gaps_allowed", all(x["success"] for x in rows))
        duplicate = ctx.request(9, "expected_replay_rejection")
        check("duplicate_rejected", not duplicate["success"], observed=duplicate)
        ctx.store.close()
        ctx.store = ctx.cls(args.out / "lifecycle.sqlite", ctx.profile, ctx.stream, ctx.witness)
        again = ctx.request(9, "expected_replay_rejection_after_reopen")
        check("duplicate_after_db_reopen_rejected", not again["success"], observed=again)
        # Synchronized duplicate requests exercise the actual unique constraint.
        with ThreadPoolExecutor(max_workers=32) as pool:
            b = threading.Barrier(32)
            dup = list(pool.map(lambda _: ctx.request(500, "concurrent_duplicate", b), range(32)))
        check("32_copy_replay_exactly_one", sum(x["success"] for x in dup) == 1,
              accepted=sum(x["success"] for x in dup))
        # Independent witness process dies, existing DB is retained.
        ctx.stop_witness()
        dead = ctx.request(600, "actual_witness_process_outage")
        pending = ctx.store.integrity()
        check("witness_outage_blocks_release", not dead["response_released"]
              and pending["pending_witness_publications"] == 1, state=pending)
        ctx.start_witness()
        ctx.store.witness = ctx.witness
        ctx.store.flush_witness_outbox()
        recovered = ctx.store.integrity()
        check("outbox_recovers_after_witness_restart", recovered["pending_witness_publications"] == 0
              and ctx.witness.fetch(ctx.stream).get("digest") == recovered["head"], state=recovered)
        ctx.witness.inject_lost_ack = True
        lost = ctx.request(700, "injected_ack_loss_after_acceptance")
        check("ack_loss_blocks_release", not lost["response_released"]
              and ctx.store.integrity()["pending_witness_publications"] == 1)
        before = ctx.witness.fetch(ctx.stream)
        ctx.store.flush_witness_outbox()
        after = ctx.witness.fetch(ctx.stream)
        check("ack_loss_retry_is_idempotent", before == after
              and ctx.store.integrity()["pending_witness_publications"] == 0)
        # Mutate copies of authentic rows. Validate that every component signature
        # still verifies but the shared-policy relation rejects the substitution.
        p = ctx.profile
        foreign = sha256(b"another authorized policy")
        admission = canonical(dict(kind="admission", sid=ctx.session.sid, seq=800,
                                   prompt_hash=sha256(b"prompt"), policy=ctx.policy))
        completion = canonical(dict(kind="completion", sid=ctx.session.sid, seq=800,
                                    prompt_hash=sha256(b"prompt"), response_hash=sha256(b"response"),
                                    policy=foreign, previous="genesis"))
        sa, sc = p.sign_identity(admission), p.sign_audit(completion)
        relation = all(json.loads(admission)[k] == json.loads(completion)[k]
                       for k in ("sid", "seq", "prompt_hash", "policy"))
        check("valid_components_policy_mismatch_rejected_by_relation",
              p.verify_identity(admission, sa) and p.verify_audit(completion, sc) and not relation,
              component_signatures_valid=True, relation_accepted=relation,
              fixture_scope="offline relation-checker test; NOT an admitted runtime attack")
        atomic(args.out / "relation_fixture.json", dict(admission_hex=admission.hex(),
               admission_signature_hex=sa.hex(), completion_hex=completion.hex(),
               completion_signature_hex=sc.hex()))
        final = ctx.store.integrity()
        check("final_integrity_and_drain", final["integrity"] == "ok"
              and final["pending_witness_publications"] == 0, state=final)
        report = dict(checks=checks, passed=all(x["passed"] for x in checks),
                      not_tested=["policy-version high-water across fresh key provisioning",
                                  "replay garbage collection", "routed network outage",
                                  "distributed consensus", "arbitrary filesystem failure"],
                      scope="real primitives and stores; process-isolated loopback witness")
        atomic(args.out / "contract.json", report)
        return 0 if report["passed"] else 1
    finally:
        ctx.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("task", choices=["cell", "contract"])
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--implementation", choices=["submitted_cbas", "conventional_strong"], required=True)
    p.add_argument("--profile", choices=["classical", "post_quantum"], required=True)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--requests", type=int, default=128)
    p.add_argument("--factor", type=int, default=8)
    p.add_argument("--warmup", type=int, default=5)
    p.add_argument("--repetition", type=int, default=0)
    a = p.parse_args()
    try:
        return run_cell(a) if a.task == "cell" else run_contract(a)
    except BaseException:
        a.out.mkdir(parents=True, exist_ok=True)
        (a.out / "EXCEPTION.txt").write_text(traceback.format_exc())
        raise


if __name__ == "__main__":
    sys.exit(main())
