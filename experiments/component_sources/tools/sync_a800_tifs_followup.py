#!/usr/bin/env python3
"""Validate and publish the A800 TIFS follow-up source data.

The script accepts an extracted evidence directory.  It refuses to publish any
derived table unless the run-level counters, randomized-block structure, audit
verification, and fixed-work batching records pass their consistency checks.
No manuscript value is entered by hand.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_gpu(data: dict[str, Any]) -> None:
    assert data["schema"] == "pqguard-a800-integrated-v1"
    assert data["design"] == "randomized complete block"
    blocks = int(data["blocks"])
    records = data["records"]
    assert len(records) == blocks * 3
    validation = data["validation"]
    for key in (
        "each_block_has_all_modes",
        "response_hash_and_length_match_within_block",
        "all_audit_signatures_and_links_verify",
        "entry_signature_count_matches_full_requests",
        "checkpoint_count_matches_schedule",
    ):
        assert validation[key] is True, (key, validation[key])
    audit = data["audit"]
    assert "SLH_DSA" in audit["algorithm"]
    assert audit["signature_bytes"] == 17088
    counters = audit["counters"]
    assert counters["entry_signatures"] == blocks
    assert counters["checkpoint_signatures"] == blocks // audit["batch_size"]
    assert counters["write_count"] == counters["checkpoint_signatures"]
    assert counters["durable_write_count"] == (counters["write_count"] if audit["fsync"] else 0)

    by_block: dict[int, list[dict[str, Any]]] = {}
    for row in records:
        by_block.setdefault(int(row["block"]), []).append(row)
    assert sorted(by_block) == list(range(1, blocks + 1))
    for rows in by_block.values():
        assert {row["mode"] for row in rows} == {"plain", "transport", "full"}
        assert len({row["response_sha256"] for row in rows}) == 1
        assert len({row["output_tokens"] for row in rows}) == 1


def validate_cpu(data: dict[str, Any], expected_batch: int) -> None:
    assert "SLH_DSA" in data["backend"]
    assert data["signature_bytes"] == 17088
    assert data["batch_size"] == expected_batch
    total = int(data["total_entries"])
    repeats = int(data["repeats"])
    expected_batches = (total + expected_batch - 1) // expected_batch
    for level in ("1", "8", "32", "64"):
        cell = data["levels"][level]
        per_record = cell["per-record"]["runs"]
        batched = cell["batched"]["runs"]
        assert len(per_record) == repeats == len(batched)
        assert all(row["entries"] == total for row in per_record + batched)
        assert all(row["signatures"] == total for row in per_record)
        assert all(row["signatures"] == expected_batches for row in batched)
        assert all(sum(row["batch_leaf_counts"]) == total for row in batched)
        assert all(max(row["batch_leaf_counts"]) <= expected_batch for row in batched)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty table: {path}")
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    evidence = args.evidence.resolve()
    results = evidence / "results"
    gpu_path = results / "gpu_full" / "integrated_results.json"
    admission_path = results / "admission" / "gpu_admission.json"
    required = [gpu_path, admission_path]
    cpu_paths = {size: results / f"cpu_batch_{size}.json" for size in (10, 50, 100)}
    required.extend(cpu_paths.values())
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit(f"missing evidence files: {missing}")

    gpu = load(gpu_path)
    validate_gpu(gpu)
    cpu = {size: load(path) for size, path in cpu_paths.items()}
    for size, data in cpu.items():
        validate_cpu(data, size)
    admission = load(admission_path)
    artifact = admission["admission"]["artifacts"]
    assert artifact["trials"] >= 3
    assert artifact["bytes"] >= 25_000_000_000

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    raw = out / "raw"
    raw.mkdir(exist_ok=True)
    for path in required:
        shutil.copy2(path, raw / path.name)

    gpu_rows = []
    for row in gpu["records"]:
        gpu_rows.append({
            "block": row["block"],
            "position": row["position"],
            "mode": row["mode"],
            "prompt_id": row["prompt_id"],
            "output_tokens": row["output_tokens"],
            "response_sha256": row["response_sha256"],
            "generation_ms": row["generation_ms"],
            "response_encrypt_ms": row["response_encrypt_ms"],
            "audit_hash_ms": row["hash_ms"],
            "entry_sign_ms": row["entry_sign_ms"],
            "checkpoint_build_ms": row["checkpoint_build_ms"],
            "checkpoint_sign_ms": row["checkpoint_sign_ms"],
            "persist_ms": row["persist_ms"],
            "entry_signatures": row["entry_signatures"],
            "checkpoint_signatures": row["checkpoint_signatures"],
            "write_count": row["write_count"],
            "durable_write_count": row["durable_write_count"],
            "bytes_written": row["bytes_written"],
            "total_ms": row["total_ms"],
        })
    write_csv(out / "a800_integrated_records.csv", gpu_rows)

    paired_rows = []
    for contrast, row in gpu["paired"].items():
        paired_rows.append({
            "contrast": contrast,
            "n_blocks": row["n_blocks"],
            "mean_difference_ms": row["mean_difference_ms"],
            "ci95_low_ms": row["bootstrap95_ms"][0],
            "ci95_high_ms": row["bootstrap95_ms"][1],
            "relative_percent": row["relative_to_baseline_mean_percent"],
            "fraction_treatment_faster": row["fraction_treatment_faster"],
        })
    write_csv(out / "a800_integrated_paired_summary.csv", paired_rows)

    cpu_rows = []
    for batch, data in cpu.items():
        for concurrency, cell in data["levels"].items():
            for schedule in ("per-record", "batched"):
                row = cell[schedule]
                cpu_rows.append({
                    "batch_size": batch,
                    "concurrency": concurrency,
                    "schedule": schedule,
                    "total_entries_per_repeat": data["total_entries"],
                    "repeats": data["repeats"],
                    "median_entries_per_s": row["entries_per_s"],
                    "median_ms_per_entry": row["ms_per_entry"],
                    "median_lock_wait_ms": row["mean_lock_wait_ms"],
                    "median_lock_hold_ms": row.get("mean_sign_hold_ms", row.get("mean_buffer_hold_ms")),
                    "median_signatures": row["signatures"],
                    "throughput_ratio_batched_over_per_record": cell["throughput_ratio"],
                })
    write_csv(out / "slh_dsa_batching_summary.csv", cpu_rows)

    report = {
        "schema": "pqguard-tifs-followup-publication-audit-v1",
        "status": "PASS",
        "evidence_root": str(evidence),
        "gpu": {
            "blocks": gpu["blocks"],
            "algorithm": gpu["audit"]["algorithm"],
            "paired": gpu["paired"],
            "validation": gpu["validation"],
        },
        "admission": artifact,
        "cpu_batching": {
            str(size): {
                "backend": data["backend"],
                "signature_bytes": data["signature_bytes"],
                "total_entries": data["total_entries"],
                "repeats": data["repeats"],
            }
            for size, data in cpu.items()
        },
        "input_sha256": {str(path.relative_to(evidence)): sha256(path) for path in required},
    }
    (out / "A800_TIFS_FOLLOWUP_AUDIT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = {
        str(path.relative_to(out)): sha256(path)
        for path in sorted(out.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS.txt"
    }
    (out / "SHA256SUMS.txt").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in manifest.items()),
        encoding="utf-8",
    )
    print(json.dumps({"status": "PASS", "out": str(out), "files": len(manifest) + 1}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
