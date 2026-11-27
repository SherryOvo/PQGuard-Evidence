#!/usr/bin/env python3
"""Real crypto/durability preflight. No model, Torch or GPU is loaded."""
import concurrent.futures
import copy
import json
import os
import signal
import sqlite3
import time
import traceback
from pathlib import Path

from conventional_store import ConventionalStrongStore
from merkle_store import MerkleStore, tree
from r11_durable_lifecycle import DurableLifecycleStore
from r7_crypto_profiles import build_profile, sha256, canonical
from runtime import WitnessProcess, atomic
from verify_artifacts import verify_case, membership, verify_sig

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence/cpu_preflight"
OUT.mkdir(parents=True, exist_ok=False)
results = []


def run_case(profile_name, implementation, batch_size=8):
    case = OUT / (profile_name + "_" + implementation + "_" + str(batch_size))
    case.mkdir()
    p = build_profile(profile_name, sha256(b"CPU preflight, no inference"))
    public = p.export_public()
    atomic(case / "public_material.json", public)
    witness = WitnessProcess(case, public, "preflight")
    cls = {"submitted": DurableLifecycleStore, "conventional": ConventionalStrongStore,
           "merkle": MerkleStore}[implementation]
    extra = dict(batch_size=batch_size, max_wait_ms=30) if implementation == "merkle" else {}
    store = cls(case / "lifecycle.sqlite", p, "preflight", witness, **extra)
    n = 17 if implementation == "merkle" else 3
    def one(i):
        store.admit("session", i, sha256(str(i).encode()), p.policy_digest)
        return store.complete("session", i, sha256(b"actual preflight response " + str(i).encode()))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(one, range(n)))
        try:
            store.admit("session", 0, sha256(b"0"), p.policy_digest)
        except sqlite3.IntegrityError:
            duplicate_rejected = True
        else:
            raise AssertionError("duplicate admitted")
        state = store.integrity()
        assert state["integrity"] == "ok" and state["pending_witness_publications"] == 0
    finally:
        store.close()
        witness.close()
    verified = verify_case(case)
    result = dict(case=case.name, passed=True, duplicate_rejected=duplicate_rejected,
                  state=state, independent_verification=verified)
    atomic(case / "COMPLETE.json", result)
    return result


def crash_case(point, profile_name):
    case = OUT / ("crash_" + profile_name + "_" + point)
    case.mkdir()
    p = build_profile(profile_name, sha256(b"crash test stable parent signer"))
    public = p.export_public()
    atomic(case / "public_material.json", public)
    witness = WitnessProcess(case, public, "crash")
    marker = case / "CRASH_POINT.json"
    released = case / "RESPONSE_RELEASED.json"
    pid = os.fork()
    if pid == 0:
        try:
            def hook(name):
                if name == point:
                    with marker.open("w") as f:
                        f.write(json.dumps(dict(point=name, pid=os.getpid())))
                        f.flush()
                        os.fsync(f.fileno())
                    time.sleep(120)
            s = MerkleStore(case / "lifecycle.sqlite", p, "crash", witness,
                            batch_size=1, max_wait_ms=1, failure_hook=hook)
            s.admit("s", 0, sha256(b"prompt"), p.policy_digest)
            s.complete("s", 0, sha256(b"response"))
            atomic(released, dict(released=True))
            s.close()
        except BaseException as e:
            atomic(case / "CHILD_EXCEPTION.json", dict(error_type=type(e).__name__, error=str(e), traceback=traceback.format_exc()))
            os._exit(1)
        os._exit(0)
    start = time.monotonic()
    while not marker.exists():
        done, status = os.waitpid(pid, os.WNOHANG)
        if done or time.monotonic() - start > 90:
            if not done:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            witness.close()
            raise RuntimeError("crash point not reached: " + point)
        time.sleep(.05)
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    assert not released.exists(), "unwitnessed response released"
    db = sqlite3.connect(case / "lifecycle.sqlite")
    before = dict(admissions=db.execute("SELECT COUNT(*) FROM admissions").fetchone()[0],
        staged=db.execute("SELECT COUNT(*) FROM staged").fetchone()[0],
        batches=db.execute("SELECT COUNT(*) FROM batches").fetchone()[0],
        integrity=db.execute("PRAGMA integrity_check").fetchone()[0])
    db.close()
    s = MerkleStore(case / "lifecycle.sqlite", p, "crash", witness, batch_size=1)
    state = s.integrity()
    s.close()
    witness.close()
    verified = verify_case(case)
    result = dict(case=case.name, passed=True, before_recovery=before, after_recovery=state,
        actual_signal="SIGKILL", response_released_before_recovery=False,
        independent_verification=verified,
        scope="audit worker process crash with stable trusted parent signer; not entire GPU-host reboot")
    atomic(case / "COMPLETE.json", result)
    return result


def negative_proofs():
    count = 0
    for n in (1, 3, 5, 8, 17, 32):
        entries = [canonical(dict(i=i, value="actual test")) for i in range(n)]
        root, proofs = tree(entries)
        for i, entry in enumerate(entries):
            membership(entry, i, n, proofs[i], root)
            tests = [(entry + b"!", proofs[i], root), (entry, proofs[i], "00" * 32)]
            if proofs[i]:
                bad = copy.deepcopy(proofs[i])
                bad[0] = {"side": "left", "digest": "00" * 32}
                tests.append((entry, bad, root))
            for payload, proof, expected in tests:
                try:
                    membership(payload, i, n, proof, expected)
                except (AssertionError, KeyError):
                    count += 1
                else:
                    raise AssertionError("modified inclusion proof accepted")
    return dict(case="merkle_odd_shapes_and_mutations", passed=True, rejected_mutations=count)


try:
    results.append(negative_proofs())
    for profile in ("classical", "post_quantum"):
        for mode in ("submitted", "conventional", "merkle"):
            results.append(run_case(profile, mode))
        for point in ("after_stage_commit", "after_seal_commit", "after_witness_ack_before_publish_commit"):
            results.append(crash_case(point, profile))
    report = dict(passed=True, checks=len(results), gpu_used=False, results=results)
    atomic(ROOT / "evidence/CPU_PREFLIGHT_PASS.json", report)
    print(json.dumps(dict(passed=True, checks=len(results), gpu_used=False)))
except BaseException as e:
    atomic(ROOT / "evidence/CPU_PREFLIGHT_FAIL.json", dict(passed=False,
        error_type=type(e).__name__, error=str(e), completed=results))
    raise
