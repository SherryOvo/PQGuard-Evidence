#!/usr/bin/env python3
"""Durable Merkle terminal records; release only after witnessed signed root.

This is a new evaluated schedule, not a relabeling of old measurements.
Staged terminal records survive a worker crash but are not released evidence.
The caller supplies a trusted signer; key-management/reprovisioning is outside
this store. Admissions remain individually signed and transaction-bound.
"""
import hashlib
import json
import sqlite3
import threading
import time

from r7_crypto_profiles import canonical, sha256
from r7_witness import witness_message


def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def tree(entries):
    levels = [[leaf_hash(x) for x in entries]]
    while len(levels[-1]) > 1:
        a = levels[-1]
        levels.append([hashlib.sha256(b"\x01" + a[i] + a[i + 1]).digest()
                       if i + 1 < len(a) else a[i] for i in range(0, len(a), 2)])
    proofs = []
    for pos in range(len(entries)):
        p, index = [], pos
        for level in levels[:-1]:
            other = index ^ 1
            if other < len(level):
                p.append(dict(side="left" if other < index else "right", digest=level[other].hex()))
            else:
                p.append(dict(side="promote"))
            index //= 2
        proofs.append(p)
    return levels[-1][0].hex(), proofs


class MerkleStore:
    def __init__(self, path, profile, stream, witness, batch_size=8, max_wait_ms=50,
                 failure_hook=None, start_worker=True):
        self.profile, self.stream, self.witness = profile, stream, witness
        self.batch_size, self.max_wait = batch_size, max_wait_ms / 1000
        self.hook = failure_hook or (lambda _: None)
        self.lock = threading.RLock()
        self.condition = threading.Condition(self.lock)
        self.events, self.errors = {}, {}
        self.stop, self.fatal = False, None
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS admissions (
          sid TEXT NOT NULL,seq INTEGER NOT NULL,prompt_hash TEXT NOT NULL,
          policy_digest TEXT NOT NULL,receipt BLOB NOT NULL,status TEXT NOT NULL,
          PRIMARY KEY(sid,seq));
        CREATE TABLE IF NOT EXISTS staged (
          id INTEGER PRIMARY KEY AUTOINCREMENT,sid TEXT NOT NULL,seq INTEGER NOT NULL,
          entry BLOB NOT NULL,leaf_digest TEXT NOT NULL,staged_ns INTEGER NOT NULL,
          batch_counter INTEGER,UNIQUE(sid,seq));
        CREATE TABLE IF NOT EXISTS batches (
          counter INTEGER PRIMARY KEY,header BLOB NOT NULL,root_signature BLOB NOT NULL,
          digest TEXT NOT NULL,witness_signature BLOB NOT NULL,status TEXT NOT NULL,
          sign_ns INTEGER NOT NULL,seal_ns INTEGER NOT NULL,publish_ns INTEGER);
        CREATE TABLE IF NOT EXISTS proofs (
          record_id INTEGER PRIMARY KEY,batch_counter INTEGER NOT NULL,
          leaf_position INTEGER NOT NULL,proof TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT OR IGNORE INTO metadata VALUES('batch_counter','0');
        INSERT OR IGNORE INTO metadata VALUES('batch_head','genesis');
        INSERT OR IGNORE INTO metadata VALUES('leaf_head','genesis');
        """)
        self.db.commit()
        # Recover with caller-supplied signer before any new admission/release.
        with self.lock:
            self._publish_pending()
            while self.db.execute("SELECT COUNT(*) FROM staged WHERE batch_counter IS NULL").fetchone()[0]:
                self._seal()
        self.worker = None
        if start_worker:
            self.worker = threading.Thread(target=self._worker, daemon=False)
            self.worker.start()

    def admit(self, sid, seq, prompt_hash, policy_digest):
        started = time.perf_counter_ns()
        message = canonical(dict(kind="admission", sid=sid, seq=seq,
                                 prompt_hash=prompt_hash, policy=policy_digest))
        receipt = self.profile.sign_identity(message)
        if not self.profile.verify_identity(message, receipt):
            raise ValueError("invalid admission signature")
        with self.lock:
            if self.fatal:
                raise RuntimeError("audit worker failed closed") from self.fatal
            self._publish_pending()
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?)",
                                (sid, seq, prompt_hash, policy_digest, receipt, "pending"))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        return receipt, time.perf_counter_ns() - started

    def stage(self, sid, seq, response_hash):
        with self.condition:
            if self.fatal:
                raise RuntimeError("audit worker failed closed") from self.fatal
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT prompt_hash,policy_digest,status FROM admissions WHERE sid=? AND seq=?", (sid, seq)).fetchone()
                if not row or row[2] != "pending":
                    raise ValueError("missing or non-pending admission")
                previous = self.db.execute("SELECT value FROM metadata WHERE key='leaf_head'").fetchone()[0]
                entry = canonical(dict(kind="completion", sid=sid, seq=seq, prompt_hash=row[0],
                                       response_hash=response_hash, policy=row[1], previous=previous))
                digest = leaf_hash(entry).hex()
                cursor = self.db.execute("INSERT INTO staged(sid,seq,entry,leaf_digest,staged_ns) VALUES(?,?,?,?,?)",
                                         (sid, seq, entry, digest, time.monotonic_ns()))
                self.db.execute("UPDATE admissions SET status='staged' WHERE sid=? AND seq=?", (sid, seq))
                self.db.execute("UPDATE metadata SET value=? WHERE key='leaf_head'", (digest,))
                self.db.commit()
                record_id = cursor.lastrowid
            except BaseException:
                self.db.rollback()
                raise
            event = self.events[record_id] = threading.Event()
            self.hook("after_stage_commit")
            self.condition.notify_all()
            return record_id, event

    def complete(self, sid, seq, response_hash):
        start = time.perf_counter_ns()
        record_id, event = self.stage(sid, seq, response_hash)
        if not event.wait(timeout=180):
            raise TimeoutError("witnessed batch acknowledgement not received; response withheld")
        with self.lock:
            if record_id in self.errors:
                raise RuntimeError("batch publication failed; response withheld") from self.errors[record_id]
            row = self.db.execute("SELECT b.counter,b.digest,b.status FROM proofs p JOIN batches b ON p.batch_counter=b.counter WHERE p.record_id=?", (record_id,)).fetchone()
            if not row or row[2] != "published":
                raise RuntimeError("unpublished terminal record; response withheld")
            return dict(lifecycle_ns=time.perf_counter_ns() - start, witness_counter=row[0],
                        witness_digest=row[1], record_id=record_id, batch_size_limit=self.batch_size)

    def _seal(self):
        start = time.perf_counter_ns()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            rows = self.db.execute("SELECT id,entry FROM staged WHERE batch_counter IS NULL ORDER BY id LIMIT ?", (self.batch_size,)).fetchall()
            if not rows:
                self.db.rollback()
                return
            meta = dict(self.db.execute("SELECT key,value FROM metadata"))
            counter = int(meta["batch_counter"]) + 1
            root, proofs = tree([bytes(x[1]) for x in rows])
            header = canonical(dict(kind="merkle_terminal_checkpoint_v1", stream=self.stream,
                counter=counter, first_id=rows[0][0], last_id=rows[-1][0], count=len(rows),
                root=root, previous=meta["batch_head"], policy=self.profile.policy_digest))
            sign_start = time.perf_counter_ns()
            signature = self.profile.sign_audit(header)
            if not self.profile.verify_audit(header, signature):
                raise ValueError("invalid signed root")
            digest = sha256(header + signature)
            witness_signature = self.profile.sign_audit(witness_message(self.stream, counter, digest))
            sign_ns = time.perf_counter_ns() - sign_start
            self.db.execute("INSERT INTO batches VALUES(?,?,?,?,?,'pending',?,?,NULL)",
                (counter, header, signature, digest, witness_signature, sign_ns, time.perf_counter_ns() - start))
            for pos, (row, proof) in enumerate(zip(rows, proofs)):
                self.db.execute("INSERT INTO proofs VALUES(?,?,?,?)", (row[0], counter, pos, json.dumps(proof)))
                self.db.execute("UPDATE staged SET batch_counter=? WHERE id=?", (counter, row[0]))
            self.db.execute("UPDATE metadata SET value=? WHERE key='batch_counter'", (str(counter),))
            self.db.execute("UPDATE metadata SET value=? WHERE key='batch_head'", (digest,))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        self.hook("after_seal_commit")
        self._publish_pending()

    def _publish_pending(self):
        for counter, digest, signature in self.db.execute("SELECT counter,digest,witness_signature FROM batches WHERE status='pending' ORDER BY counter").fetchall():
            start = time.perf_counter_ns()
            reply = self.witness.publish(self.stream, counter, digest, bytes(signature))
            if not reply.get("ok"):
                raise RuntimeError("witness did not acknowledge: " + str(reply.get("reason")))
            self.hook("after_witness_ack_before_publish_commit")
            self.db.execute("UPDATE batches SET status='published',publish_ns=? WHERE counter=?", (time.perf_counter_ns() - start, counter))
            self.db.execute("UPDATE admissions SET status='completed' WHERE (sid,seq) IN (SELECT sid,seq FROM staged WHERE batch_counter=?)", (counter,))
            self.db.commit()
            for (record_id,) in self.db.execute("SELECT id FROM staged WHERE batch_counter=?", (counter,)):
                if record_id in self.events:
                    self.events[record_id].set()

    def _worker(self):
        try:
            while True:
                with self.condition:
                    count, oldest = self.db.execute("SELECT COUNT(*),MIN(staged_ns) FROM staged WHERE batch_counter IS NULL").fetchone()
                    age = (time.monotonic_ns() - oldest) / 1e9 if oldest else 0
                    if count and (count >= self.batch_size or age >= self.max_wait or self.stop):
                        self._seal()
                    elif self.stop:
                        return
                    else:
                        self.condition.wait(timeout=max(.001, self.max_wait - age))
        except BaseException as e:
            with self.condition:
                self.fatal = e
                for key, event in self.events.items():
                    if not event.is_set():
                        self.errors[key] = e
                        event.set()

    def integrity(self):
        with self.lock:
            return dict(integrity=self.db.execute("PRAGMA integrity_check").fetchone()[0],
                admissions=self.db.execute("SELECT COUNT(*) FROM admissions").fetchone()[0],
                completed=self.db.execute("SELECT COUNT(*) FROM admissions WHERE status='completed'").fetchone()[0],
                staged_unsealed=self.db.execute("SELECT COUNT(*) FROM staged WHERE batch_counter IS NULL").fetchone()[0],
                pending_witness_publications=self.db.execute("SELECT COUNT(*) FROM batches WHERE status!='published'").fetchone()[0],
                batches=self.db.execute("SELECT COUNT(*) FROM batches").fetchone()[0],
                fatal=type(self.fatal).__name__ if self.fatal else None)

    def close(self):
        with self.condition:
            self.stop = True
            self.condition.notify_all()
        if self.worker:
            self.worker.join(timeout=190)
            if self.worker.is_alive():
                raise TimeoutError("audit worker did not stop")
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.close()
