"""Independent conventional composition with the SAME contract and wire bytes.

This intentionally is not a weakened component-only baseline. It binds policy,
admission, completion and witness heads, uses two durable local transactions,
and publishes through a transactional outbox, just as the submitted construction.
It makes no claim of source-code equivalence or a performance advantage.
"""
import json
import hashlib
import sqlite3
import threading
import time


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


class ConventionalStrongStore:
    def __init__(self, path, profile, stream, witness):
        self.profile, self.stream, self.witness = profile, stream, witness
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS admissions (
          sid TEXT NOT NULL, seq INTEGER NOT NULL, prompt_hash TEXT NOT NULL,
          policy_digest TEXT NOT NULL, receipt BLOB NOT NULL, status TEXT NOT NULL,
          PRIMARY KEY(sid,seq));
        CREATE TABLE IF NOT EXISTS completions (
          sid TEXT NOT NULL, seq INTEGER NOT NULL, response_hash TEXT NOT NULL,
          entry BLOB NOT NULL, entry_digest TEXT NOT NULL, audit_signature BLOB NOT NULL,
          witness_counter INTEGER NOT NULL, witness_digest TEXT NOT NULL,
          PRIMARY KEY(sid,seq));
        CREATE TABLE IF NOT EXISTS witness_outbox (
          stream TEXT NOT NULL, counter INTEGER NOT NULL, digest TEXT NOT NULL,
          signature BLOB NOT NULL, status TEXT NOT NULL,
          PRIMARY KEY(stream,counter));
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT OR IGNORE INTO metadata VALUES('counter','0');
        INSERT OR IGNORE INTO metadata VALUES('head','genesis');
        """)
        self.db.commit()

    def admit(self, sid, seq, prompt_hash, policy_digest):
        started = time.perf_counter_ns()
        self.flush_witness_outbox()
        message = encode(dict(kind="admission", sid=sid, seq=seq,
                              prompt_hash=prompt_hash, policy=policy_digest))
        receipt = self.profile.sign_identity(message)
        if not self.profile.verify_identity(message, receipt):
            raise ValueError("invalid admission signature")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?)",
                                (sid, seq, prompt_hash, policy_digest, receipt, "pending"))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        return receipt, time.perf_counter_ns() - started

    def complete(self, sid, seq, response_hash):
        started = time.perf_counter_ns()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT prompt_hash,policy_digest,status FROM admissions "
                                      "WHERE sid=? AND seq=?", (sid, seq)).fetchone()
                if not row or row[2] != "pending":
                    raise ValueError("missing or non-pending admission")
                meta = dict(self.db.execute("SELECT key,value FROM metadata"))
                counter, previous = int(meta["counter"]) + 1, meta["head"]
                entry = encode(dict(kind="completion", sid=sid, seq=seq,
                                    prompt_hash=row[0], response_hash=response_hash,
                                    policy=row[1], previous=previous))
                signature = self.profile.sign_audit(entry)
                if not self.profile.verify_audit(entry, signature):
                    raise ValueError("invalid completion signature")
                entry_digest = digest(entry + signature)
                head = digest(encode(dict(previous=previous, entry=entry_digest, counter=counter)))
                publication = b"PQGUARD-WITNESS-V1\0" + encode(dict(stream=self.stream, counter=counter, digest=head))
                witness_signature = self.profile.sign_audit(publication)
                self.db.execute("INSERT INTO completions VALUES(?,?,?,?,?,?,?,?)",
                                (sid, seq, response_hash, entry, entry_digest, signature, counter, head))
                self.db.execute("UPDATE admissions SET status='completed' WHERE sid=? AND seq=?", (sid, seq))
                self.db.execute("UPDATE metadata SET value=? WHERE key='counter'", (str(counter),))
                self.db.execute("UPDATE metadata SET value=? WHERE key='head'", (head,))
                self.db.execute("INSERT INTO witness_outbox VALUES(?,?,?,?,?)",
                                (self.stream, counter, head, witness_signature, "pending"))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
        self.flush_witness_outbox()
        return dict(lifecycle_ns=time.perf_counter_ns() - started,
                    witness_counter=counter, witness_digest=head)

    def flush_witness_outbox(self):
        with self.lock:
            rows = self.db.execute("SELECT counter,digest,signature FROM witness_outbox "
                                   "WHERE stream=? AND status='pending' ORDER BY counter", (self.stream,)).fetchall()
            for counter, head, signature in rows:
                reply = self.witness.publish(self.stream, counter, head, bytes(signature))
                if not reply.get("ok"):
                    raise RuntimeError("witness unavailable: " + str(reply.get("reason")))
                self.db.execute("UPDATE witness_outbox SET status='published' WHERE stream=? AND counter=?",
                                (self.stream, counter))
                self.db.commit()

    def integrity(self):
        with self.lock:
            meta = dict(self.db.execute("SELECT key,value FROM metadata"))
            return dict(integrity=self.db.execute("PRAGMA integrity_check").fetchone()[0],
                        completed=self.db.execute("SELECT COUNT(*) FROM completions").fetchone()[0],
                        pending=self.db.execute("SELECT COUNT(*) FROM admissions WHERE status='pending'").fetchone()[0],
                        pending_witness_publications=self.db.execute("SELECT COUNT(*) FROM witness_outbox WHERE status='pending'").fetchone()[0],
                        counter=int(meta["counter"]), head=meta["head"])

    def close(self):
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.close()
