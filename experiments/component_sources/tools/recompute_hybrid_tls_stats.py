#!/usr/bin/env python3
"""Recompute serial hybrid-TLS statistics from preserved observations.

The original Go harness selected percentile indices before sorting. Serial
files retain one observation per round in ``per_round_handshake_p50_ms``;
with concurrency one, these are the raw handshake latencies. This script
sorts those observations and emits a derived, auditable correction file.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    position = p * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def recompute(path: Path) -> dict[str, object]:
    source = json.loads(path.read_text(encoding="utf-8"))
    if source.get("connections") != 1:
        raise ValueError(f"{path}: only concurrency-one files contain raw observations")
    values = [float(v) for v in source["per_round_handshake_p50_ms"]]
    if len(values) != int(source["accepted"]):
        raise ValueError(f"{path}: observation count does not match accepted handshakes")
    result = {
        "source": str(path),
        "variant": source["variant"],
        "requested_groups": source["requested_groups"],
        "n": len(values),
        "failed": int(source["failed"]),
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "maximum_ms": max(values),
        "minimum_ms": min(values),
        "raw_handshake_ms": values,
    }
    assert result["maximum_ms"] >= result["p95_ms"] >= result["median_ms"]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    summaries = [recompute(path) for path in args.inputs]
    by_variant = {row["variant"]: row for row in summaries}
    x25519 = by_variant["x25519"]["median_ms"]
    hybrid = by_variant["hybrid-only"]["median_ms"]
    payload = {
        "method": "sorted raw concurrency-one observations with linear p95 interpolation",
        "summaries": summaries,
        "hybrid_minus_x25519_median_ms": hybrid - x25519,
        "hybrid_minus_x25519_median_percent": (hybrid - x25519) / x25519 * 100,
    }
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
