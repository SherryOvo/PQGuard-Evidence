#!/usr/bin/env python3
"""Independent verifier: imports no profile, store, driver or Merkle module."""
import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def enc(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def h(x):
    return hashlib.sha256(x).hexdigest()


def verify_sig(algorithm, pk, message, signature):
    if algorithm == "Ed25519":
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(signature, message)
    else:
        import oqs
        with oqs.Signature(algorithm) as v:
            assert v.verify(message, signature, bytes.fromhex(pk)), "invalid signature"


def membership(entry, position, count, proof, root):
    value = hashlib.sha256(b"\0" + entry).digest()
    index, width = position, count
    for part in proof:
        assert width > 1
        if (index ^ 1) >= width:
            assert part == {"side": "promote"}
        elif index % 2:
            assert part["side"] == "left"
            value = hashlib.sha256(b"\1" + bytes.fromhex(part["digest"]) + value).digest()
        else:
            assert part["side"] == "right"
            value = hashlib.sha256(b"\1" + value + bytes.fromhex(part["digest"])).digest()
        index //= 2
        width = (width + 1) // 2
    assert width == 1 and value.hex() == root


def verify_case(case, require_complete=True):
    case = Path(case)
    public = json.loads((case / "public_material.json").read_text())
    db = sqlite3.connect("file:" + str(case / "lifecycle.sqlite") + "?mode=ro", uri=True)
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    admissions = {}
    for sid, seq, hp, policy, receipt, status in db.execute("SELECT * FROM admissions"):
        message = enc(dict(kind="admission", sid=sid, seq=seq, prompt_hash=hp, policy=policy))
        verify_sig(public["identity"], public["identity_public_key"], message, bytes(receipt))
        assert policy == public["policy_descriptor"]["policy_digest"]
        assert (sid, seq) not in admissions
        admissions[sid, seq] = dict(prompt_hash=hp, policy=policy, status=status)
        if require_complete:
            assert status == "completed"
    tables = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    completed, signatures, proofs_count, published_heads = {}, len(admissions), 0, {}
    if "batches" in tables:
        previous = "genesis"
        batches = {}
        expected_id = 1
        for counter, header, signature, digest, witness_sig, status, *_ in db.execute("SELECT * FROM batches ORDER BY counter"):
            header, signature = bytes(header), bytes(signature)
            x = json.loads(header)
            assert x["counter"] == len(batches) + 1 == counter
            assert x["kind"] == "merkle_terminal_checkpoint_v1"
            assert x["previous"] == previous and x["first_id"] == expected_id
            assert x["count"] == x["last_id"] - x["first_id"] + 1
            assert x["policy"] == public["policy_descriptor"]["policy_digest"]
            verify_sig(public["audit"], public["audit_public_key"], header, signature)
            assert h(header + signature) == digest
            msg = b"PQGUARD-WITNESS-V1\0" + enc(dict(stream=x["stream"], counter=counter, digest=digest))
            verify_sig(public["audit"], public["audit_public_key"], msg, bytes(witness_sig))
            signatures += 2
            if require_complete:
                assert status == "published"
            if status == "published":
                published_heads[x["stream"]] = (counter, digest, bytes(witness_sig))
            batches[counter] = x
            previous, expected_id = digest, x["last_id"] + 1
        previous = "genesis"
        for record_id, sid, seq, entry, leaf_digest, staged_ns, counter in db.execute("SELECT * FROM staged ORDER BY id"):
            entry = bytes(entry)
            x = json.loads(entry)
            assert x["kind"] == "completion" and x["previous"] == previous
            previous = hashlib.sha256(b"\0" + entry).hexdigest()
            assert previous == leaf_digest
            a = admissions[sid, seq]
            assert x["sid"] == sid and x["seq"] == seq and x["prompt_hash"] == a["prompt_hash"] and x["policy"] == a["policy"]
            if counter is None:
                assert not require_complete
                continue
            b = batches[counter]
            p = db.execute("SELECT batch_counter,leaf_position,proof FROM proofs WHERE record_id=?", (record_id,)).fetchone()
            assert p[0] == counter and p[1] == record_id - b["first_id"]
            membership(entry, p[1], b["count"], json.loads(p[2]), b["root"])
            proofs_count += 1
            completed[sid, seq] = x
        assert proofs_count == sum(b["count"] for b in batches.values())
    else:
        previous = "genesis"
        for sid, seq, response_hash, entry, digest, signature, counter, witness_digest in db.execute("SELECT * FROM completions ORDER BY witness_counter"):
            assert counter == len(completed) + 1
            entry, signature = bytes(entry), bytes(signature)
            x = json.loads(entry)
            assert x["kind"] == "completion" and x["previous"] == previous
            a = admissions[sid, seq]
            assert x["sid"] == sid and x["seq"] == seq and x["prompt_hash"] == a["prompt_hash"] and x["policy"] == a["policy"]
            assert x["response_hash"] == response_hash
            verify_sig(public["audit"], public["audit_public_key"], entry, signature)
            assert h(entry + signature) == digest
            assert h(enc(dict(previous=previous, entry=digest, counter=counter))) == witness_digest
            out = db.execute("SELECT stream,digest,signature,status FROM witness_outbox WHERE counter=?", (counter,)).fetchone()
            assert out[1] == witness_digest
            msg = b"PQGUARD-WITNESS-V1\0" + enc(dict(stream=out[0], counter=counter, digest=witness_digest))
            verify_sig(public["audit"], public["audit_public_key"], msg, bytes(out[2]))
            signatures += 2
            if require_complete:
                assert out[3] == "published"
            if out[3] == "published":
                published_heads[out[0]] = (counter, witness_digest, bytes(out[2]))
            completed[sid, seq], previous = x, witness_digest
    witness = sqlite3.connect("file:" + str(case / "witness.sqlite") + "?mode=ro", uri=True)
    assert witness.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    for stream, (counter, digest, signature) in published_heads.items():
        row = witness.execute("SELECT counter,digest FROM heads WHERE stream=?", (stream,)).fetchone()
        assert row == (counter, digest)
    raw_count = 0
    datasets = {}
    if (case / "requests.jsonl").exists():
        for line in (case / "requests.jsonl").read_text().splitlines():
            row = json.loads(line)
            dataset_path = case.parent / "datasets" / (row.get("workload", "unknown") + ".json")
            if dataset_path.exists():
                if row["workload"] not in datasets:
                    datasets[row["workload"]] = json.loads(dataset_path.read_text())
                plan = datasets[row["workload"]][row["workload_index"]]
                assert row["prompt_hash"] == h(enc(plan["input_token_ids"]))
                assert row["input_tokens"] == len(plan["input_token_ids"])
                assert row["tenant"] == plan["tenant"]
                assert row["target_output_tokens"] == plan["target_output_tokens"]
            if row.get("success"):
                key = row["sid"], row["sequence"]
                assert row["response_released"] and key in completed
                assert completed[key]["response_hash"] == row["response_hash"] == h(enc(row["output_token_ids"]))
                assert admissions[key]["prompt_hash"] == row["prompt_hash"]
                raw_count += 1
            else:
                assert not row["response_released"]
    if require_complete:
        assert len(completed) == len(admissions)
        if (case / "requests.jsonl").exists():
            assert raw_count == len(completed)
    db.close()
    witness.close()
    return dict(passed=True, admissions=len(admissions), completed=len(completed),
                signatures_verified=signatures, inclusion_proofs=proofs_count,
                raw_bindings_verified=raw_count, scope="public-key/state/terminal-root verification; not full AKE or implementation proof")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("case", type=Path)
    p.add_argument("--allow-pending", action="store_true")
    a = p.parse_args()
    result = verify_case(a.case, not a.allow_pending)
    tmp = a.case / "verification.json.tmp"
    tmp.write_text(json.dumps(result, indent=2))
    tmp.replace(a.case / "verification.json")
    print(json.dumps(result))
