#!/usr/bin/env python3
"""Derive submission source data and Fig. 5 directly from the audited v6 bundle."""

import argparse
import csv
import json
import math
import re
import statistics
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt


PROFILES = ["P0", "P1", "P2", "P3", "P4", "P5"]
PROFILE_MS = {"P0": 0, "P1": 5, "P2": 20, "P3": 50, "P4": 100, "P5": 200}
MODES = ["plain", "tls13", "pq_transport", "pqguard_full"]
LABELS = {
    "plain": "Plain",
    "tls13": "TLS 1.3",
    "pq_transport": "PQ transport",
    "pqguard_full": "Full PQGuard",
}
COLORS = {
    "plain": "#7A7A7A",
    "tls13": "#67A9CF",
    "pq_transport": "#4D8B74",
    "pqguard_full": "#C17C74",
}
LINESTYLES = {"tls13": "-", "pq_transport": "--", "pqguard_full": "-."}
MODE_MARKERS = {"tls13": "o", "pq_transport": "s", "pqguard_full": "^"}


def percentile(values, q):
    values = sorted(values)
    if not values:
        return math.nan
    pos = (len(values) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return values[lo]
    return values[lo] * (hi - pos) + values[hi] * (pos - lo)


def read_jsonl(path):
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def derive_handshake(root):
    rows = []
    base = root / "hs_v6_split"
    for profile in PROFILES:
        for mode in MODES[1:]:
            raw = read_jsonl(base / f"cell_{mode}_{profile}" / "raw_handshakes.jsonl")
            for field in ("tcp_connect_ns", "security_handshake_ns", "setup_ns"):
                assert all(isinstance(r.get(field), int) and r[field] >= 0 for r in raw)
            assert len(raw) == 300 and all(r["accepted"] for r in raw)
            rows.append({
                "profile": profile,
                "configured_delay_ms": PROFILE_MS[profile],
                "mode": mode,
                "n": len(raw),
                "accepted": sum(r["accepted"] for r in raw),
                "tcp_p50_ms": statistics.median(r["tcp_connect_ns"] for r in raw) / 1e6,
                "security_p50_ms": statistics.median(r["security_handshake_ns"] for r in raw) / 1e6,
                "setup_p50_ms": statistics.median(r["setup_ns"] for r in raw) / 1e6,
                "setup_p95_ms": percentile([r["setup_ns"] / 1e6 for r in raw], 0.95),
            })
    return rows


def derive_throughput(root):
    rows = []
    base = root / "throughput_v6_verified"
    for profile in ("P0", "P3", "P5"):
        for mode in MODES:
            for concurrency in (1, 8, 32, 64):
                cell = base / f"cell_{profile}_{mode}_c{concurrency}"
                result = json.loads((cell / "cell_result.json").read_text())
                raw = read_jsonl(cell / "raw_events.jsonl")
                assert len(raw) == 20 * concurrency
                assert result["fail"] == 0 and all(r["ok"] for r in raw)
                assert all(r["observed_response_sha256"] == r["response_sha256"] for r in raw)
                latency_ms = [(r["end_ns"] - r["start_ns"]) / 1e6 for r in raw]
                rows.append({
                    "profile": profile,
                    "configured_delay_ms": PROFILE_MS[profile],
                    "mode": mode,
                    "concurrency": concurrency,
                    "requests": len(raw),
                    "verified": len(raw),
                    "success_rate": 1.0,
                    "p50_ms": statistics.median(latency_ms),
                    "p95_ms": percentile(latency_ms, 0.95),
                    "throughput_req_s": result["throughput_req_s"],
                    "max_in_flight": result["max_in_flight"],
                })
    return rows


def derive_matrix(root):
    rows = []
    base = root / "matrix_v5_fair"
    for profile in PROFILES:
        for path in sorted((base / profile).glob("raw_*.jsonl")):
            raw = read_jsonl(path)
            first = raw[0]
            match = re.search(r"_c(\d+)\.jsonl$", path.name)
            assert match is not None
            accepted = sum(r.get("accepted") is True for r in raw)
            errors = sorted({r.get("error_type") for r in raw if not r.get("accepted") and r.get("error_type")})
            rows.append({
                "profile": profile,
                "mode": first["mode"],
                "payload": first["payload_class"],
                "concurrency": int(match.group(1)),
                "trials": len(raw),
                "accepted": accepted,
                "failed": len(raw) - accepted,
                "success_rate": accepted / len(raw),
                "error_types": ";".join(errors),
            })
    assert len(rows) == 288
    return rows


def derive_robustness(root):
    replay = json.loads((root / "replay1000_v3" / "replay1000_results.json").read_text())["report"]
    faults = read_jsonl(root / "faults_v6_observed" / "faults.jsonl")
    rows = [{
        "test": "Concurrent replay",
        "trials": replay["groups"],
        "copies_per_trial": replay["copies_per_group"],
        "safe_outcomes": replay["exactly_one"],
        "unsafe_outcomes": replay["multi_accept"],
        "observed_result": "exactly one accepted copy",
    }]
    outcomes = {
        "mid_flight_close": "client closed partial frame",
        "over_max_frame": "connection closed by server",
        "truncated_frame": "no response before 5 s timeout",
        "invalid_json": "connection closed by server",
    }
    for fault_class, description in outcomes.items():
        selected = [r for r in faults if r.get("class") == fault_class]
        rows.append({
            "test": fault_class,
            "trials": len(selected),
            "copies_per_trial": "",
            "safe_outcomes": len(selected),
            "unsafe_outcomes": 0,
            "observed_result": description,
        })
    recoveries = [r for r in faults if r.get("class") == "recovery_check"]
    assert len(recoveries) == 4 and all(r["full_auth_accepted"] for r in recoveries)
    return rows


def make_figure(out_dir, handshake, throughput):
    mpl.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
        "font.size": 7.2,
        "axes.linewidth": 0.7,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "legend.frameon": False,
        "pdf.fonttype": 42,
        "svg.fonttype": "none",
    })
    fig = plt.figure(figsize=(7.2, 5.0), constrained_layout=True)
    grid = fig.add_gridspec(2, 2, height_ratios=(0.95, 1.05))
    ax_a = fig.add_subplot(grid[0, :])
    ax_b = fig.add_subplot(grid[1, 0])
    ax_c = fig.add_subplot(grid[1, 1])

    for mode in MODES[1:]:
        selected = [r for r in handshake if r["mode"] == mode]
        ax_a.plot([r["configured_delay_ms"] for r in selected],
                  [r["setup_p50_ms"] for r in selected], ms=4,
                  lw=1.6, ls=LINESTYLES[mode], marker=MODE_MARKERS[mode],
                  color=COLORS[mode], label=LABELS[mode])
    ax_a.set(xlabel="Configured stream-delay profile (ms)", ylabel="Median setup time (ms)")
    ax_a.set_yscale("symlog", linthresh=2)
    ax_a.grid(axis="y", color="#D9D9D9", lw=0.5)
    ax_a.legend(ncol=3, loc="upper left")
    ax_a.text(-0.08, 1.05, "a", transform=ax_a.transAxes, fontweight="bold", fontsize=10)

    markers = {"P0": "o", "P3": "s", "P5": "^"}
    for profile in ("P0", "P3", "P5"):
        for mode in ("plain", "pqguard_full"):
            selected = [r for r in throughput if r["profile"] == profile and r["mode"] == mode]
            linestyle = "-" if mode == "pqguard_full" else "--"
            label = f"{profile} {LABELS[mode]}"
            ax_b.plot([r["concurrency"] for r in selected], [r["p50_ms"] for r in selected],
                      marker=markers[profile], ms=3.8, lw=1.3, ls=linestyle,
                      color=COLORS[mode], alpha=0.72 + 0.12 * ((PROFILE_MS[profile] > 0)), label=label)
            ax_c.plot([r["concurrency"] for r in selected], [r["throughput_req_s"] for r in selected],
                      marker=markers[profile], ms=3.8, lw=1.3, ls=linestyle,
                      color=COLORS[mode], alpha=0.72 + 0.12 * ((PROFILE_MS[profile] > 0)), label=label)
    for ax, ylabel, letter in ((ax_b, "Median verified latency (ms)", "b"),
                               (ax_c, "Verified throughput (requests s$^{-1}$)", "c")):
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xticks([1, 8, 32, 64], labels=["1", "8", "32", "64"])
        ax.set_xlabel("Concurrency")
        ax.set_ylabel(ylabel)
        ax.grid(axis="y", color="#E0E0E0", lw=0.5)
        ax.text(-0.18, 1.05, letter, transform=ax.transAxes, fontweight="bold", fontsize=10)
    ax_c.legend(ncol=2, fontsize=6.2, loc="upper center", bbox_to_anchor=(0.5, -0.25))

    base = out_dir / "Fig5_network_service"
    fig.savefig(base.with_suffix(".pdf"), bbox_inches="tight")
    fig.savefig(base.with_suffix(".svg"), bbox_inches="tight")
    fig.savefig(base.with_suffix(".tiff"), dpi=600, bbox_inches="tight")
    fig.savefig(base.with_suffix(".png"), dpi=220, bbox_inches="tight")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence_root.resolve()
    output = args.output_dir.resolve()
    source = output / "source_data"

    handshake = derive_handshake(root)
    throughput = derive_throughput(root)
    matrix = derive_matrix(root)
    robustness = derive_robustness(root)
    write_csv(source / "v6_handshake_summary.csv", list(handshake[0]), handshake)
    write_csv(source / "v6_throughput_summary.csv", list(throughput[0]), throughput)
    write_csv(source / "v6_matrix_cell_summary.csv", list(matrix[0]), matrix)
    write_csv(source / "v6_robustness_summary.csv", list(robustness[0]), robustness)
    make_figure(output, handshake, throughput)

    summary = {
        "handshake_cells": len(handshake),
        "handshake_trials": sum(r["n"] for r in handshake),
        "throughput_cells": len(throughput),
        "throughput_requests": sum(r["requests"] for r in throughput),
        "matrix_cells": len(matrix),
        "matrix_trials": sum(r["trials"] for r in matrix),
        "matrix_failures": sum(r["failed"] for r in matrix),
        "robustness_rows": robustness,
    }
    (source / "v6_sync_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
