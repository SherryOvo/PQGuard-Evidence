#!/usr/bin/env python3
"""Independent-process monotonic witness used by the R7 CBAS experiment."""

from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import threading
from pathlib import Path
from typing import Any

try:
    import oqs
except ModuleNotFoundError:  # Classical witness tests do not require liboqs.
    oqs = None
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from r7_crypto_profiles import canonical


def witness_message(stream: str, counter: int, digest: str) -> bytes:
    return b"PQGUARD-WITNESS-V1\0" + canonical({"counter": counter, "digest": digest, "stream": stream})


def verify_signature(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if algorithm == "Ed25519":
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        if oqs is None:
            return False
        with oqs.Signature(algorithm) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except Exception:
        return False


class WitnessStore:
    def __init__(self, db_path: Path, registry: dict[str, dict[str, str]]) -> None:
        self.registry = registry
        self.lock = threading.Lock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS heads ("
            "stream TEXT PRIMARY KEY, counter INTEGER NOT NULL, digest TEXT NOT NULL, "
            "signature BLOB NOT NULL, algorithm TEXT NOT NULL)"
        )
        self.db.commit()

    def publish(self, request: dict[str, Any]) -> dict[str, Any]:
        stream = str(request["stream"])
        counter = int(request["counter"])
        digest = str(request["digest"])
        signature = bytes.fromhex(str(request["signature_hex"]))
        entry = self.registry.get(stream)
        if entry is None:
            return {"ok": False, "reason": "unknown_stream"}
        algorithm = entry["algorithm"]
        public_key = bytes.fromhex(entry["public_key_hex"])
        if not verify_signature(algorithm, public_key, witness_message(stream, counter, digest), signature):
            return {"ok": False, "reason": "invalid_signature"}
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT counter,digest,signature FROM heads WHERE stream=?", (stream,)).fetchone()
            if row is None:
                if counter != 1:
                    self.db.rollback()
                    return {"ok": False, "reason": "counter_gap"}
                decision = "accepted"
            elif counter < row[0]:
                self.db.rollback()
                return {"ok": False, "reason": "counter_regression", "current_counter": row[0]}
            elif counter == row[0]:
                # Randomized signature schemes can produce different valid bytes
                # for the same checkpoint, so idempotence is defined by the
                # authenticated (stream, counter, digest) tuple.
                if digest == row[1]:
                    self.db.rollback()
                    return {"ok": True, "reason": "idempotent", "counter": row[0], "digest": row[1]}
                self.db.rollback()
                return {"ok": False, "reason": "same_counter_conflict", "current_counter": row[0]}
            elif counter != row[0] + 1:
                self.db.rollback()
                return {"ok": False, "reason": "counter_gap", "current_counter": row[0]}
            else:
                decision = "accepted"
            self.db.execute(
                "INSERT INTO heads(stream,counter,digest,signature,algorithm) VALUES(?,?,?,?,?) "
                "ON CONFLICT(stream) DO UPDATE SET counter=excluded.counter,digest=excluded.digest,"
                "signature=excluded.signature,algorithm=excluded.algorithm",
                (stream, counter, digest, signature, algorithm),
            )
            self.db.commit()
            return {"ok": True, "reason": decision, "counter": counter, "digest": digest}

    def fetch(self, stream: str) -> dict[str, Any]:
        row = self.db.execute("SELECT counter,digest,algorithm FROM heads WHERE stream=?", (stream,)).fetchone()
        if row is None:
            return {"ok": False, "reason": "not_found"}
        return {"ok": True, "counter": row[0], "digest": row[1], "algorithm": row[2]}


def handle_connection(conn: socket.socket, store: WitnessStore) -> None:
    with conn:
        raw = b""
        while not raw.endswith(b"\n") and len(raw) < 8_000_000:
            chunk = conn.recv(65536)
            if not chunk:
                break
            raw += chunk
        try:
            request = json.loads(raw)
            if request.get("op") == "publish":
                response = store.publish(request)
            elif request.get("op") == "fetch":
                response = store.fetch(str(request["stream"]))
            elif request.get("op") == "health":
                response = {"ok": True, "reason": "healthy"}
            else:
                response = {"ok": False, "reason": "unknown_operation"}
        except Exception as exc:
            response = {"ok": False, "reason": "malformed_request", "detail": type(exc).__name__}
        conn.sendall(canonical(response) + b"\n")


def serve(host: str, port: int, db_path: Path, registry_path: Path, ready_path: Path) -> None:
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    store = WitnessStore(db_path, registry)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(128)
        actual_port = server.getsockname()[1]
        ready_path.write_text(json.dumps({"host": host, "port": actual_port}), encoding="utf-8")
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handle_connection, args=(conn, store), daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    serve(args.host, args.port, args.db, args.registry, args.ready)


if __name__ == "__main__":
    main()
