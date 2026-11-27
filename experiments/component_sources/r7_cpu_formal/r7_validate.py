#!/usr/bin/env python3
"""Independent consistency and signature validator for an R7 result directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import oqs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from r7_crypto_profiles import canonical, sha256


def verify(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if algorithm == "Ed25519":
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        with oqs.Signature(algorithm) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except Exception:
        return False


def validate(root: Path) -> dict[str, Any]:
    public = json.loads((root / "public_material.json").read_text(encoding="utf-8"))
    records = [json.loads(line) for line in (root / "raw" / "requests.jsonl").read_text(encoding="utf-8").splitlines()]
    cells = json.loads((root / "cells.json").read_text(encoding="utf-8"))
    checks: list[dict[str, Any]] = []
    expected_records = sum(int(cell["requests"]) for cell in cells)
    checks.append({"name": "raw_record_count", "passed": len(records) == expected_records, "value": len(records)})
    checks.append({"name": "all_requests_successful", "passed": all(row["success"] for row in records)})
    checks.append({"name": "all_bundles_verified", "passed": all(row["bundle_verified"] for row in records)})
    checks.append({"name": "all_policies_verified", "passed": all(row["policy_verified"] for row in records)})
    sessions: dict[tuple[str, int, int, bool], list[dict[str, Any]]] = {}
    for row in records:
        key = (row["profile"], row["concurrency"], row["repetition"], row["full_cbas"])
        sessions.setdefault(key, []).append(row)
    session_shape_ok = all(
        len({row["sid"] for row in group}) == 1
        and sorted(int(row["request_index"]) for row in group) == list(range(len(group)))
        for group in sessions.values()
    )
    checks.append({"name": "persistent_session_unique_sequences", "passed": session_shape_ok})
    full_records = [row for row in records if row["full_cbas"]]
    checks.append(
        {
            "name": "all_full_records_witnessed",
            "passed": all(row["audit_verified"] and row["witness_reason"] == "published" for row in full_records),
            "value": len(full_records),
        }
    )
    witness_db = sqlite3.connect(root / "state" / "witness.sqlite3")
    witness_heads = {row[0]: (row[1], row[2]) for row in witness_db.execute("SELECT stream,counter,digest FROM heads")}
    witness_db.close()
    signature_total = 0
    signature_valid = 0
    for db_path in sorted((root / "state").glob("*-cbas-*.sqlite3")):
        profile_name = db_path.name.split("-cbas-")[0]
        material = public[profile_name]
        identity_algorithm = material["identity"]
        audit_algorithm = material["audit"]
        identity_pk = bytes.fromhex(material["identity_public_key"])
        audit_pk = bytes.fromhex(material["audit_public_key"])
        db = sqlite3.connect(db_path)
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        pending = db.execute("SELECT COUNT(*) FROM admissions WHERE status!='completed'").fetchone()[0]
        pending_outbox = db.execute(
            "SELECT COUNT(*) FROM witness_outbox WHERE status!='published'"
        ).fetchone()[0]
        checks.append(
            {
                "name": f"{db_path.stem}_integrity",
                "passed": integrity == "ok" and pending == 0 and pending_outbox == 0,
            }
        )
        for sid, seq, prompt_hash, policy, receipt in db.execute(
            "SELECT sid,seq,prompt_hash,policy_digest,receipt FROM admissions"
        ):
            message = canonical(
                {"kind": "admission", "sid": sid, "seq": seq, "prompt_hash": prompt_hash, "policy": policy}
            )
            signature_total += 1
            signature_valid += int(verify(identity_algorithm, identity_pk, message, receipt))
        for entry, entry_digest, audit_signature in db.execute(
            "SELECT entry,entry_digest,audit_signature FROM completions"
        ):
            signature_total += 1
            signature_valid += int(sha256(entry + audit_signature) == entry_digest and verify(audit_algorithm, audit_pk, entry, audit_signature))
        counter = int(db.execute("SELECT value FROM metadata WHERE key='counter'").fetchone()[0])
        head = db.execute("SELECT value FROM metadata WHERE key='head'").fetchone()[0]
        witnessed = witness_heads.get(db_path.stem)
        checks.append(
            {
                "name": f"{db_path.stem}_witness_head",
                "passed": witnessed == (counter, head),
                "counter": counter,
            }
        )
        db.close()
    checks.append(
        {
            "name": "independent_signature_verification",
            "passed": signature_total > 0 and signature_total == signature_valid,
            "valid": signature_valid,
            "total": signature_total,
        }
    )
    fault = json.loads((root / "witness_fault_tests.json").read_text(encoding="utf-8"))
    checks.append(
        {
            "name": "witness_fault_suite",
            "passed": all(item["passed"] for item in fault["cases"])
            and fault["outage_fail_closed"]
            and fault["restart_persistence_passed"],
        }
    )
    report = {"passed": all(check["passed"] for check in checks), "checks": checks}
    (root / "validation_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    hashes: list[str] = []
    for path in sorted(
        item
        for item in root.rglob("*")
        if item.is_file()
        and item.name != "SHA256SUMS"
        and not item.name.endswith(("-wal", "-shm"))
    ):
        hashes.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}")
    (root / "SHA256SUMS").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()
    report = validate(args.result_dir)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
