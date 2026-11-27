#!/usr/bin/env python3
"""Deterministic contract tests for the R11 session and witness repairs.

This test uses the classical profile so it can run on a machine without
liboqs.  The same record-derivation and outbox logic is shared by the PQ
profile; the PQ suite must additionally run where liboqs 0.16 is installed.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from r11_durable_lifecycle import DurableLifecycleStore, WitnessUnavailable
from r7_crypto_profiles import ClassicalProfile, canonical, sha256
from r7_witness import witness_message


class RecordingWitness:
    def __init__(self, profile: ClassicalProfile, fail_first: bool = False) -> None:
        self.profile = profile
        self.fail_first = fail_first
        self.heads: dict[str, tuple[int, str]] = {}

    def publish(self, stream: str, counter: int, digest: str, signature: bytes) -> dict[str, object]:
        if self.fail_first:
            self.fail_first = False
            return {"ok": False, "reason": "simulated_outage"}
        if not self.profile.verify_audit(witness_message(stream, counter, digest), signature):
            return {"ok": False, "reason": "invalid_signature"}
        current = self.heads.get(stream)
        if current is None:
            if counter != 1:
                return {"ok": False, "reason": "counter_gap"}
        elif counter == current[0] and digest == current[1]:
            return {"ok": True, "reason": "idempotent"}
        elif counter != current[0] + 1:
            return {"ok": False, "reason": "counter_gap"}
        self.heads[stream] = (counter, digest)
        return {"ok": True, "reason": "accepted"}


def check_record_derivation(profile: ClassicalProfile) -> dict[str, object]:
    session = profile.establish_session(canonical({"purpose": "contract-test"}))
    seen: set[tuple[bytes, bytes]] = set()
    for sequence in range(64):
        for direction in ("request", "response"):
            key, nonce = profile.record_material(session, direction, sequence)
            assert (key, nonce) not in seen
            seen.add((key, nonce))
            aad = profile.associated_data(session, direction, sequence)
            message = f"{direction}:{sequence}".encode()
            ciphertext = AESGCM(key).encrypt(nonce, message, aad)
            assert AESGCM(key).decrypt(nonce, ciphertext, aad) == message
            try:
                AESGCM(key).decrypt(nonce, ciphertext, aad + b"tamper")
            except InvalidTag:
                pass
            else:
                raise AssertionError("AEAD accepted altered associated data")
    return {"sid": session.sid, "unique_record_material": len(seen)}


def check_durable_outbox(profile: ClassicalProfile) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="pqguard-r11-") as root:
        db_path = Path(root) / "state.sqlite3"
        stream = "contract-stream"
        witness = RecordingWitness(profile, fail_first=True)
        store = DurableLifecycleStore(db_path, profile, stream, witness)
        session = profile.establish_session(canonical({"purpose": "outbox-test"}))
        store.admit(session.sid, 0, sha256(b"prompt-0"), profile.policy_digest)
        try:
            store.complete(session.sid, 0, sha256(b"response-0"))
        except WitnessUnavailable:
            pass
        else:
            raise AssertionError("simulated witness outage did not fail closed")
        before = store.state()
        assert before["pending_witness_publications"] == 1
        store.close()

        recovered = DurableLifecycleStore(db_path, profile, stream, witness)
        recovered.flush_witness_outbox()
        after = recovered.state()
        assert after["pending_witness_publications"] == 0
        assert witness.heads[stream][0] == 1
        try:
            recovered.admit(session.sid, 0, sha256(b"prompt-0"), profile.policy_digest)
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("duplicate (sid, seq) admission was accepted")
        recovered.close()
        return {"before_recovery": before, "after_recovery": after, "witness_head": witness.heads[stream]}


def main() -> None:
    profile = ClassicalProfile(sha256(b"PQGuard R11 fixed policy"))
    result = {
        "record_derivation": check_record_derivation(profile),
        "durable_outbox": check_durable_outbox(profile),
        "status": "pass",
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
