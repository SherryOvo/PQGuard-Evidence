#!/usr/bin/env python3
"""Recoverable local-audit to witness publication bridge for PQGuard R11.

The local SQLite transaction persists a signed witness outbox record before a
network publication is attempted.  If publication fails, the caller fails
closed and a later restart retries the same authenticated counter and digest.
This is an outbox protocol, not a claim of atomic commit across two hosts.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Protocol

from r7_crypto_profiles import canonical, sha256
from r7_witness import witness_message


class WitnessClient(Protocol):
    def publish(self, stream: str, counter: int, digest: str, signature: bytes) -> dict[str, Any]: ...


class WitnessUnavailable(RuntimeError):
    """A terminal record is durable locally but not yet externally witnessed."""


class DurableLifecycleStore:
    def __init__(self, path: Path, profile: Any, stream: str, witness: WitnessClient) -> None:
        self.profile = profile
        self.stream = stream
        self.witness = witness
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS admissions (
                sid TEXT NOT NULL, seq INTEGER NOT NULL, prompt_hash TEXT NOT NULL,
                policy_digest TEXT NOT NULL, receipt BLOB NOT NULL, status TEXT NOT NULL,
                PRIMARY KEY(sid, seq)
            );
            CREATE TABLE IF NOT EXISTS completions (
                sid TEXT NOT NULL, seq INTEGER NOT NULL, response_hash TEXT NOT NULL,
                entry BLOB NOT NULL, entry_digest TEXT NOT NULL, audit_signature BLOB NOT NULL,
                witness_counter INTEGER NOT NULL, witness_digest TEXT NOT NULL,
                PRIMARY KEY(sid, seq)
            );
            CREATE TABLE IF NOT EXISTS witness_outbox (
                stream TEXT NOT NULL, counter INTEGER NOT NULL, digest TEXT NOT NULL,
                signature BLOB NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending', 'published')),
                PRIMARY KEY(stream, counter)
            );
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """
        )
        self.db.execute("INSERT OR IGNORE INTO metadata(key,value) VALUES('counter','0')")
        self.db.execute("INSERT OR IGNORE INTO metadata(key,value) VALUES('head','genesis')")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def _metadata(self, key: str) -> str:
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        if row is None:
            raise RuntimeError(f"missing metadata key: {key}")
        return str(row[0])

    def admit(self, sid: str, seq: int, prompt_hash: str, policy_digest: str) -> tuple[bytes, int]:
        start = time.perf_counter_ns()
        self.flush_witness_outbox()
        message = canonical(
            {"kind": "admission", "sid": sid, "seq": seq, "prompt_hash": prompt_hash, "policy": policy_digest}
        )
        receipt = self.profile.sign_identity(message)
        if not self.profile.verify_identity(message, receipt):
            raise RuntimeError("admission signature verification failed")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute(
                    "INSERT INTO admissions VALUES(?,?,?,?,?,?)",
                    (sid, seq, prompt_hash, policy_digest, receipt, "pending"),
                )
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
        return receipt, time.perf_counter_ns() - start

    def complete(self, sid: str, seq: int, response_hash: str) -> dict[str, Any]:
        """Persist a terminal entry, then publish it or fail closed with an outbox record."""
        start = time.perf_counter_ns()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT prompt_hash,policy_digest,status FROM admissions WHERE sid=? AND seq=?", (sid, seq)
                ).fetchone()
                if row is None or row[2] != "pending":
                    raise RuntimeError("missing or non-pending admission")
                counter = int(self._metadata("counter")) + 1
                previous = self._metadata("head")
                entry = canonical(
                    {
                        "kind": "completion",
                        "sid": sid,
                        "seq": seq,
                        "prompt_hash": row[0],
                        "response_hash": response_hash,
                        "policy": row[1],
                        "previous": previous,
                    }
                )
                audit_signature = self.profile.sign_audit(entry)
                if not self.profile.verify_audit(entry, audit_signature):
                    raise RuntimeError("audit signature verification failed")
                entry_digest = sha256(entry + audit_signature)
                witness_digest = sha256(canonical({"previous": previous, "entry": entry_digest, "counter": counter}))
                witness_signature = self.profile.sign_audit(witness_message(self.stream, counter, witness_digest))
                self.db.execute(
                    "INSERT INTO completions VALUES(?,?,?,?,?,?,?,?)",
                    (sid, seq, response_hash, entry, entry_digest, audit_signature, counter, witness_digest),
                )
                self.db.execute("UPDATE admissions SET status='completed' WHERE sid=? AND seq=?", (sid, seq))
                self.db.execute("UPDATE metadata SET value=? WHERE key='counter'", (str(counter),))
                self.db.execute("UPDATE metadata SET value=? WHERE key='head'", (witness_digest,))
                self.db.execute(
                    "INSERT INTO witness_outbox VALUES(?,?,?,?, 'pending')",
                    (self.stream, counter, witness_digest, witness_signature),
                )
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
        self.flush_witness_outbox()
        return {
            "audit_verified": True,
            "entry_digest": entry_digest,
            "lifecycle_ns": time.perf_counter_ns() - start,
            "witness_counter": counter,
            "witness_digest": witness_digest,
            "witness_reason": "published",
        }

    def flush_witness_outbox(self) -> None:
        """Publish pending records in counter order; never skip an unavailable head."""
        with self.lock:
            rows = self.db.execute(
                "SELECT counter,digest,signature FROM witness_outbox "
                "WHERE stream=? AND status='pending' ORDER BY counter",
                (self.stream,),
            ).fetchall()
            for counter, digest, signature in rows:
                response = self.witness.publish(self.stream, int(counter), str(digest), bytes(signature))
                if not response.get("ok"):
                    raise WitnessUnavailable(
                        f"witness has not accepted {self.stream}:{counter}: {response.get('reason', 'unavailable')}"
                    )
                self.db.execute(
                    "UPDATE witness_outbox SET status='published' WHERE stream=? AND counter=?",
                    (self.stream, counter),
                )
                self.db.commit()

    def state(self) -> dict[str, Any]:
        with self.lock:
            pending = self.db.execute(
                "SELECT COUNT(*) FROM witness_outbox WHERE stream=? AND status='pending'", (self.stream,)
            ).fetchone()[0]
            completed = self.db.execute("SELECT COUNT(*) FROM completions").fetchone()[0]
            admissions = self.db.execute("SELECT COUNT(*) FROM admissions").fetchone()[0]
            return {
                "admissions": admissions,
                "completed": completed,
                "counter": int(self._metadata("counter")),
                "head": self._metadata("head"),
                "pending_witness_publications": int(pending),
                "integrity": self.db.execute("PRAGMA integrity_check").fetchone()[0],
            }

    def integrity(self) -> dict[str, Any]:
        state = self.state()
        pending_admissions = self.db.execute(
            "SELECT COUNT(*) FROM admissions WHERE status='pending'"
        ).fetchone()[0]
        return {
            "completed": state["completed"],
            "counter": state["counter"],
            "head": state["head"],
            "integrity": state["integrity"],
            "pending": int(pending_admissions),
            "pending_witness_publications": state["pending_witness_publications"],
        }
