#!/usr/bin/env python3
"""Create manuscript-facing summaries from validated R7 cell measurements."""

from __future__ import annotations

import argparse
import csv
import json
import random
from collections import defaultdict
from pathlib import Path
from statistics import median
from typing import Any


def bootstrap_ci(values: list[float], seed: int, draws: int = 10_000) -> list[float]:
    rng = random.Random(seed)
    estimates = sorted(median([rng.choice(values) for _ in values]) for _ in range(draws))
    return [estimates[int(0.025 * draws)], estimates[int(0.975 * draws) - 1]]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    args = parser.parse_args()
    validation = json.loads((args.result_dir / "validation_report.json").read_text(encoding="utf-8"))
    if not validation["passed"]:
        raise SystemExit("refusing to analyze an unvalidated result directory")
    cells = json.loads((args.result_dir / "cells.json").read_text(encoding="utf-8"))
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    by_key: dict[tuple[str, int, int], dict[str, Any]] = {}
    for row in cells:
        grouped[(row["mode"], row["concurrency"])].append(row)
        by_key[(row["mode"], row["concurrency"], row["repetition"])] = row
    aggregate: list[dict[str, Any]] = []
    for (mode, concurrency), rows in sorted(grouped.items()):
        aggregate.append(
            {
                "mode": mode,
                "concurrency": concurrency,
                "repetitions": len(rows),
                "requests_total": sum(row["requests"] for row in rows),
                "median_cell_latency_ms": median(row["median_ms"] for row in rows),
                "median_cell_p95_ms": median(row["p95_ms"] for row in rows),
                "median_throughput_req_s": median(row["throughput_req_s"] for row in rows),
                "min_success_rate": min(row["successes"] / row["requests"] for row in rows),
            }
        )
    contrasts: list[dict[str, Any]] = []
    pairs = [
        ("classical_cbas", "classical_transport", "classical CBAS increment"),
        ("post_quantum_cbas", "post_quantum_transport", "post-quantum CBAS increment"),
        ("post_quantum_cbas", "classical_cbas", "post-quantum premium within CBAS"),
        ("post_quantum_transport", "classical_transport", "post-quantum premium within transport"),
    ]
    for concurrency in sorted({row["concurrency"] for row in cells}):
        repetitions = sorted({row["repetition"] for row in cells if row["concurrency"] == concurrency})
        for left, right, label in pairs:
            latency_deltas = [
                by_key[(left, concurrency, repetition)]["median_ms"]
                - by_key[(right, concurrency, repetition)]["median_ms"]
                for repetition in repetitions
            ]
            throughput_ratios = [
                by_key[(left, concurrency, repetition)]["throughput_req_s"]
                / by_key[(right, concurrency, repetition)]["throughput_req_s"]
                for repetition in repetitions
            ]
            seed = sum(ord(character) for character in f"{left}:{right}:{concurrency}")
            contrasts.append(
                {
                    "contrast": label,
                    "left": left,
                    "right": right,
                    "concurrency": concurrency,
                    "paired_repetitions": len(repetitions),
                    "median_latency_delta_ms": median(latency_deltas),
                    "latency_delta_bootstrap_95_ci_ms": bootstrap_ci(latency_deltas, seed),
                    "median_throughput_ratio": median(throughput_ratios),
                    "throughput_ratio_bootstrap_95_ci": bootstrap_ci(throughput_ratios, seed + 1),
                }
            )
    report = {
        "scope": {
            "workload": "deterministic CPU cryptographic lifecycle; no LLM inference",
            "witness": "separate loopback process and database; not separately administered",
            "confidence_interval": "paired cell-level nonparametric bootstrap over five repetitions",
        },
        "aggregate": aggregate,
        "contrasts": contrasts,
    }
    (args.result_dir / "analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    with (args.result_dir / "aggregate.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=aggregate[0].keys())
        writer.writeheader()
        writer.writerows(aggregate)
    with (args.result_dir / "contrasts.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = [key for key in contrasts[0] if "ci" not in key]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in contrasts:
            writer.writerow({key: row[key] for key in fields})
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
