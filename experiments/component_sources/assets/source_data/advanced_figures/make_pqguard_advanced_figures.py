from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap, LogNorm
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401


ROOT = Path(__file__).resolve().parents[3]
DATA = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
CORE = ROOT / "assets" / "source_data" / "core"

PALETTE = {
    "navy": "#242F4D",
    "blue": "#465A66",
    "steel": "#6382AA",
    "slate": "#828E99",
    "rose": "#7F606D",
    "sand": "#C5AB71",
    "olive": "#5A5745",
    "green": "#9DA780",
    "darkgreen": "#3C3F27",
}

mpl.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "font.size": 7.2,
        "axes.linewidth": 0.7,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
    }
)


def read_csv(name: str) -> list[dict[str, str]]:
    with (DATA / name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_json(name: str):
    with (DATA / name).open(encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(name: str) -> list[dict]:
    rows = []
    with (DATA / name).open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def lifecycle_figure() -> None:
    startup = read_csv("exp1_startup_overhead.csv")
    components = [
        ("manifest", "manifest_parse_ms", PALETTE["steel"]),
        ("hash", "weight_hash_ms", PALETTE["navy"]),
        ("signature", "model_signature_verify_ms", PALETTE["rose"]),
        ("template", "prompt_template_verify_ms", PALETTE["green"]),
        ("audit init", "audit_init_ms", PALETTE["sand"]),
    ]
    models = []
    for r in startup:
        if r["model"] not in models:
            models.append(r["model"])
    comp_mean = {m: [np.mean([float(r[c]) for r in startup if r["model"] == m]) for _, c, _ in components] for m in models}

    interleaved = []
    for file_name, hardware in [("a800_interleaved_raw.json", "A800"), ("rtx5090_interleaved_raw.json", "RTX 5090")]:
        obj = load_json(file_name)
        for r in obj["records"]:
            interleaved.append({"hardware": hardware, "mode": r["mode"], "latency_ms": float(r["latency_ms"])})
    mode_order = ["plain", "transport", "full"]
    hw_order = ["A800", "RTX 5090"]

    policy_rows = read_jsonl("raw_records.jsonl")
    policy_components = [
        ("handshake", "handshake_ms"),
        ("policy digest", "policy_digest_ms"),
        ("state commit", "state_commit_ms"),
        ("audit append", "audit_append_ms"),
    ]
    proto = load_json("pqguard_local_protocol_overhead.json")
    size_keys = [
        ("KEM public key", "kem_public_key_bytes"),
        ("KEM ciphertext", "kem_ciphertext_bytes"),
        ("request overhead", "request_overhead_bytes"),
        ("response overhead", "response_overhead_bytes"),
        ("signed entry", "signed_audit_entry_bytes"),
        ("batch signature", "batch_signature_bytes"),
    ]

    fig = plt.figure(figsize=(7.3, 5.5), constrained_layout=True)
    gs = fig.add_gridspec(2, 2, height_ratios=[1.0, 0.95])
    ax0 = fig.add_subplot(gs[0, 0])
    totals = np.array([sum(comp_mean[m]) for m in models])
    hash_idx = [name for name, _, _ in components].index("hash")
    hash_share = np.array([comp_mean[m][hash_idx] / sum(comp_mean[m]) for m in models])
    ax0.barh(models, totals / 1000.0, color=PALETTE["navy"], edgecolor="white", linewidth=0.4)
    for y_pos, total_s, share in zip(range(len(models)), totals / 1000.0, hash_share):
        ax0.text(total_s + 0.6, y_pos, f"hashing {share*100:.1f}%", va="center", fontsize=6.6, color=PALETTE["navy"])
    ax0.set_xlabel("startup verification time (s)")
    ax0.set_title("a. Admission cost is hashing dominated", fontweight="bold", loc="left")
    ax0.set_xlim(0, max(totals / 1000.0) * 1.18)
    ax0.grid(axis="x", color="#dddddd", linewidth=0.45, alpha=0.7)

    ax1 = fig.add_subplot(gs[0, 1])
    positions = []
    labels = []
    values = []
    colors = []
    pos = 1
    for hw in hw_order:
        for mode in mode_order:
            vals = [r["latency_ms"] for r in interleaved if r["hardware"] == hw and r["mode"] == mode]
            values.append(vals)
            positions.append(pos)
            labels.append(f"{hw}\n{mode}")
            colors.append({"plain": PALETTE["slate"], "transport": PALETTE["steel"], "full": PALETTE["rose"]}[mode])
            pos += 1
        pos += 0.55
    bp = ax1.boxplot(values, positions=positions, patch_artist=True, widths=0.55, showfliers=False)
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.72)
        patch.set_edgecolor(PALETTE["navy"])
    for key in ["whiskers", "caps", "medians"]:
        for item in bp[key]:
            item.set_color(PALETTE["navy"])
            item.set_linewidth(0.8)
    ax1.set_xticks(positions, labels, rotation=35, ha="right", fontsize=6.4)
    ax1.set_ylabel("latency (ms)")
    ax1.set_title("b. Raw interleaved GPU latency", fontweight="bold", loc="left")
    ax1.grid(axis="y", color="#dddddd", linewidth=0.45, alpha=0.7)

    ax2 = fig.add_subplot(gs[1, 0])
    pc_vals = [[float(r[key]) for r in policy_rows if r.get(key) is not None] for _, key in policy_components]
    vp = ax2.violinplot(pc_vals, showmedians=True, widths=0.75)
    for body, color in zip(vp["bodies"], [PALETTE["steel"], PALETTE["green"], PALETTE["sand"], PALETTE["rose"]]):
        body.set_facecolor(color)
        body.set_edgecolor(PALETTE["navy"])
        body.set_alpha(0.68)
    for key in ["cmedians", "cmins", "cmaxes", "cbars"]:
        vp[key].set_color(PALETTE["navy"])
        vp[key].set_linewidth(0.8)
    ax2.set_yscale("log")
    ax2.set_xticks(range(1, len(policy_components) + 1), [x[0] for x in policy_components], rotation=24, ha="right")
    ax2.set_ylabel("component latency (ms, log)")
    ax2.set_title("c. Policy-continuity component spread", fontweight="bold", loc="left")
    ax2.grid(axis="y", color="#dddddd", linewidth=0.45, alpha=0.7)

    ax3 = fig.add_subplot(gs[1, 1])
    names = [k for k, _ in size_keys]
    vals = [float(proto[key]) for _, key in size_keys]
    y = np.arange(len(names))
    ax3.barh(y, vals, color=[PALETTE["navy"], PALETTE["steel"], PALETTE["green"], PALETTE["slate"], PALETTE["rose"], PALETTE["sand"]], edgecolor="white", linewidth=0.4)
    ax3.set_xscale("log")
    ax3.set_yticks(y, names)
    ax3.invert_yaxis()
    ax3.set_xlabel("bytes (log)")
    ax3.set_title("d. Protocol and retention object sizes", fontweight="bold", loc="left")
    ax3.grid(axis="x", color="#dddddd", linewidth=0.45, alpha=0.7)
    fig.savefig(ASSETS / "Fig3.pdf", bbox_inches="tight")
    fig.savefig(ASSETS / "Fig3.png", dpi=450, bbox_inches="tight")
    plt.close(fig)


def load_attack_summary() -> tuple[list[dict], list[dict]]:
    trials = []
    with (CORE / "standard_attack_control_traces.jsonl").open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                trials.append(json.loads(line))
    with (CORE / "standard_attack_control_summary.json").open(encoding="utf-8") as f:
        summary = json.load(f)["summaries"]
    return trials, summary


def draw_small_heatmap(ax, matrix, xlabels, ylabels, title, vmin=0, vmax=1, fmt="{:.2f}"):
    cmap = LinearSegmentedColormap.from_list("pq_heat", ["#f9f7ef", PALETTE["green"], PALETTE["steel"], PALETTE["navy"]])
    im = ax.imshow(matrix, vmin=vmin, vmax=vmax, aspect="auto", cmap=cmap)
    ax.set_xticks(range(len(xlabels)), xlabels, rotation=25, ha="right")
    ax.set_yticks(range(len(ylabels)), ylabels)
    ax.set_title(title, fontweight="bold", loc="left")
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            val = matrix[i, j]
            ax.text(j, i, fmt.format(val), ha="center", va="center", fontsize=6.2, color=("white" if val > 0.58 else PALETTE["navy"]))
    return im


def load_attack_figure() -> None:
    load_rows = read_csv("exp4_load.csv")
    selected = [
        r
        for r in load_rows
        if r["config"] == "PQGuard" and r["prompt_len"] == "2048"
    ]
    x = np.array([float(r["concurrency"]) for r in selected])
    y = np.array([float(r["output_len"]) for r in selected])
    z = np.array([float(r["p95_ms"]) / 1000.0 for r in selected])

    unsat = read_csv("load_results_unsaturated.csv")
    conc = sorted({int(r["concurrency"]) for r in unsat})
    schemes = ["Baseline-1", "PQGuard"]
    queue = np.zeros((len(schemes), len(conc)))
    for r in unsat:
        queue[schemes.index(r["scheme"]), conc.index(int(r["concurrency"]))] = float(r["avg_queue_ms"])

    trials, summary = load_attack_summary()
    attacks = [s["attack"] for s in summary]
    attack_vals = [
        [float(r["latency_ms"]) for r in trials if r["sample_type"] == "attack" and r["attack"] == attack]
        for attack in attacks
    ]
    attack_percentiles = np.array(
        [
            [
                np.percentile(vals, 50),
                np.percentile(vals, 95),
                np.max(vals),
            ]
            for vals in attack_vals
        ]
    )

    fig = plt.figure(figsize=(7.3, 5.4), constrained_layout=True)
    gs = fig.add_gridspec(2, 2, width_ratios=[1.05, 1.0])
    ax0 = fig.add_subplot(gs[0, 0], projection="3d")
    surf = ax0.plot_trisurf(
        x,
        y,
        z,
        cmap=LinearSegmentedColormap.from_list("pq_surf", [PALETTE["green"], PALETTE["sand"], PALETTE["rose"], PALETTE["navy"]]),
        linewidth=0.25,
        edgecolor="white",
        alpha=0.84,
    )
    ax0.scatter(x, y, z, color=PALETTE["navy"], s=20, depthshade=False)
    ax0.set_xlabel("concurrency")
    ax0.set_ylabel("output tokens")
    ax0.set_zlabel("p95 latency (s)")
    ax0.set_title("a. PQGuard load surface", fontweight="bold", loc="left", pad=2)
    ax0.view_init(elev=25, azim=-128)
    fig.colorbar(surf, ax=ax0, shrink=0.5, pad=0.06, label="p95 latency")

    ax1 = fig.add_subplot(gs[0, 1])
    im = draw_small_heatmap(
        ax1,
        queue,
        [str(c) for c in conc],
        ["plain", "PQGuard"],
        "b. Unsaturated queue delay (ms)",
        vmin=0,
        vmax=max(1, float(np.nanmax(queue))),
        fmt="{:.0f}",
    )
    fig.colorbar(im, ax=ax1, fraction=0.046, pad=0.02, label="ms")

    ax2 = fig.add_subplot(gs[1, 0])
    vp = ax2.violinplot(attack_vals, showmedians=True, widths=0.8)
    for body in vp["bodies"]:
        body.set_facecolor(PALETTE["rose"])
        body.set_edgecolor(PALETTE["navy"])
        body.set_alpha(0.66)
    for key in ["cmedians", "cmins", "cmaxes", "cbars"]:
        vp[key].set_color(PALETTE["navy"])
        vp[key].set_linewidth(0.75)
    ax2.set_yscale("log")
    short_attack = {
        "Adapter swap": "Adapter",
        "Audit log forgery": "Audit log",
        "MITM tampering": "MITM",
        "Model weight tampering": "Weights",
        "Prompt/template tampering": "Template",
        "Replay": "Replay",
    }
    ax2.set_xticks(range(1, len(attacks) + 1), [short_attack.get(a, a) for a in attacks], rotation=22, ha="right", fontsize=6.0)
    ax2.set_ylabel("detection latency (ms, log)")
    ax2.set_title("c. Matched attack-latency distributions", fontweight="bold", loc="left")
    ax2.grid(axis="y", color="#dddddd", linewidth=0.45, alpha=0.7)

    ax3 = fig.add_subplot(gs[1, 1])
    labels = [short_attack.get(a, a) for a in attacks]
    y_pos = np.arange(len(attacks))
    height = 0.22
    colors = [PALETTE["green"], PALETTE["steel"], PALETTE["rose"]]
    names = ["p50", "p95", "max"]
    for offset, col, name, color in zip([-height, 0.0, height], range(3), names, colors):
        ax3.barh(
            y_pos + offset,
            attack_percentiles[:, col],
            height=height,
            color=color,
            edgecolor="white",
            linewidth=0.35,
            label=name,
        )
    ax3.set_yticks(y_pos, labels)
    ax3.invert_yaxis()
    ax3.set_xscale("log")
    ax3.set_xlabel("detection latency (ms, log)")
    ax3.set_title("d. Attack latency percentiles", fontweight="bold", loc="left")
    ax3.grid(axis="x", color="#dddddd", linewidth=0.45, alpha=0.7)
    ax3.legend(frameon=False, fontsize=6.2, loc="lower right", ncol=3, handlelength=1.0, columnspacing=0.8)
    fig.savefig(ASSETS / "Fig4.pdf", bbox_inches="tight")
    fig.savefig(ASSETS / "Fig4.png", dpi=450, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    lifecycle_figure()
    load_attack_figure()
