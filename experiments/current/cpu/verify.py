#!/usr/bin/env python3
"""Independent verifier: does NOT import experiment or protocol modules."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()


def sha(x):
    return hashlib.sha256(x).hexdigest()


def signature(algorithm, public, message, sig):
    if algorithm == "Ed25519":
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(bytes(sig), message)
    else:
        import oqs
        with oqs.Signature(algorithm) as v:
            if not v.verify(message, bytes(sig), bytes.fromhex(public)):
                raise ValueError("invalid " + algorithm + " signature")


def verify(directory):
    material = json.loads((directory / "public_material.json").read_text())
    db = sqlite3.connect(f"file:{directory / 'lifecycle.sqlite'}?mode=ro", uri=True)
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    admissions = {}
    verified = 0
    for sid, seq, hp, policy, sig, status in db.execute("SELECT * FROM admissions"):
        msg = canonical(dict(kind="admission", sid=sid, seq=seq, prompt_hash=hp, policy=policy))
        signature(material["identity"], material["identity_public_key"], msg, sig)
        admissions[(sid, seq)] = (hp, policy, status)
        verified += 1
    previous = "genesis"
    count = 0
    completed = {}
    for sid, seq, hr, entry, entry_hash, sig, counter, head in db.execute("SELECT * FROM completions ORDER BY witness_counter"):
        obj = json.loads(bytes(entry))
        assert obj["kind"] == "completion"
        assert obj["sid"] == sid and obj["seq"] == seq and obj["response_hash"] == hr
        hp, policy, status = admissions[(sid, seq)]
        assert obj["prompt_hash"] == hp and obj["policy"] == policy and status == "completed"
        assert policy == material["policy_descriptor"]["policy_digest"]
        signature(material["audit"], material["audit_public_key"], bytes(entry), sig)
        assert sha(bytes(entry) + bytes(sig)) == entry_hash
        assert obj["previous"] == previous and counter == count + 1
        assert sha(canonical(dict(previous=previous, entry=entry_hash, counter=counter))) == head
        stream, ctr, out_head, out_sig, pub_status = db.execute(
            "SELECT * FROM witness_outbox WHERE counter=?", (counter,)).fetchone()
        assert ctr == counter and out_head == head and pub_status == "published"
        msg = b"PQGUARD-WITNESS-V1\0" + canonical(dict(stream=stream, counter=counter, digest=head))
        signature(material["audit"], material["audit_public_key"], msg, out_sig)
        completed[(sid, seq)] = (hp, hr)
        previous, count = head, count + 1
        verified += 2
    meta = dict(db.execute("SELECT key,value FROM metadata"))
    assert int(meta["counter"]) == count and meta["head"] == previous
    assert db.execute("SELECT COUNT(*) FROM admissions WHERE status='pending'").fetchone()[0] == 0
    wdb = sqlite3.connect(f"file:{directory / 'witness.sqlite'}?mode=ro", uri=True)
    assert wdb.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    w = wdb.execute("SELECT counter,digest FROM heads WHERE stream='review-cpu-stream'").fetchone()
    assert w == (count, previous)
    raw_success = 0
    raw_failure = 0
    for line in (directory / "requests.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r["success"]:
            assert r["response_released"]
            assert completed[(r["sid"], r["seq"])] == (r["prompt_hash"], r["response_hash"])
            raw_success += 1
        else:
            raw_failure += 1
    fixture = directory / "relation_fixture.json"
    if fixture.exists():
        f = json.loads(fixture.read_text())
        a, c = bytes.fromhex(f["admission_hex"]), bytes.fromhex(f["completion_hex"])
        signature(material["identity"], material["identity_public_key"], a, bytes.fromhex(f["admission_signature_hex"]))
        signature(material["audit"], material["audit_public_key"], c, bytes.fromhex(f["completion_signature_hex"]))
        aa, cc = json.loads(a), json.loads(c)
        assert any(aa[k] != cc[k] for k in ("sid", "seq", "prompt_hash", "policy"))
    db.close()
    wdb.close()
    return dict(passed=True, signatures_verified=verified, admissions=len(admissions),
                completed=count, raw_success=raw_success, raw_failures_retained=raw_failure,
                scope="signature/link/field/state verification; NOT full handshake verification")


if __name__ == "__main__":
    try:
        report = verify(Path(sys.argv[1]))
    except Exception as e:
        report = dict(passed=False, error_type=type(e).__name__, error=str(e))
    print(json.dumps(report, sort_keys=True))
    sys.exit(0 if report["passed"] else 1)
