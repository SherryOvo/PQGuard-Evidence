import json
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "assets" / "source_data"
OUT = ROOT / "assets" / "Fig6_cpu_followup"
obj = json.loads((DATA / "cpu_followup_summary.json").read_text())
atomic = json.loads((DATA / "atomic_netem_followup_audit.json").read_text())
assert atomic["pass"]
assert atomic["atomic"]["crash_trials_passed"] == 20
assert atomic["atomic"]["exactly_one_verified"] == 1000
assert atomic["atomic"]["independent_database_and_signature_check"]["verified_signatures"] == 1000

COLORS = {"transport": "#5B7898", "full": "#A65F5F", "lock": "#D59B61",
          "signature": "#7D98B3", "sqlite": "#94A57E", "other": "#D9D5C7",
          "ink": "#263238", "danger": "#B44A4A", "safe": "#4F7D61"}
mpl.rcParams.update({"font.family": "DejaVu Sans", "font.size": 7.2,
                     "pdf.fonttype": 42, "svg.fonttype": "none",
                     "axes.spines.top": False, "axes.spines.right": False,
                     "axes.linewidth": .7, "figure.facecolor": "white"})

fig = plt.figure(figsize=(7.45, 3.05), constrained_layout=True)
gs = fig.add_gridspec(1, 3, width_ratios=[1.0, 1.08, 1.25])

ax = fig.add_subplot(gs[0, 0])
for mode, color, label in [("pq_transport", COLORS["transport"], "PQ transport"),
                           ("pqguard_full", COLORS["full"], "Full PQGuard")]:
    groups = sorted([g for g in obj["groups"] if g["variant"] == mode], key=lambda x:x["concurrency"])
    x = np.array([g["concurrency"] for g in groups])
    values = np.array([g["run_request_p50_ms"] for g in groups])
    y = np.median(values, axis=1)
    ax.fill_between(x, values.min(1), values.max(1), color=color, alpha=.14, linewidth=0)
    ax.plot(x, y, marker="o", ms=4.5, lw=1.7, color=color, label=label)
ax.set_yscale("log"); ax.set_xticks([1,8,32,64]); ax.set_xlabel("concurrency")
ax.set_ylabel("request p50 (ms, log)"); ax.grid(axis="y", lw=.45, color="#dddddd")
ax.legend(frameon=False, loc="upper left", fontsize=6.3)
ax.set_title("a  Serialization under load", loc="left", fontweight="bold", fontsize=7.6)

ax = fig.add_subplot(gs[0, 1])
groups=sorted([g for g in obj["groups"] if g["variant"]=="pqguard_full"],key=lambda x:x["concurrency"])
y=np.arange(len(groups)); left=np.zeros(len(groups))
parts=[("audit_lock_wait_mean_ms","lock wait",COLORS["lock"]),
       ("signature_mean_ms","signature",COLORS["signature"]),
       ("audit_sql_mean_ms","SQL",COLORS["sqlite"]),
       ("audit_commit_mean_ms","commit",COLORS["other"])]
for key,label,color in parts:
    vals=np.array([g[key] for g in groups])
    ax.barh(y,vals,left=left,color=color,height=.62,label=label,edgecolor="white",linewidth=.3)
    left+=vals
ax.set_yticks(y,[f"c={g['concurrency']}" for g in groups]);ax.invert_yaxis()
ax.set_xlabel("mean server-stage time (ms)");ax.grid(axis="x",lw=.45,color="#dddddd")
ax.legend(frameon=False,fontsize=5.8,ncol=2,loc="lower right")
ax.set_title("b  Audit-lock attribution",loc="left",fontweight="bold",fontsize=7.6)

ax = fig.add_subplot(gs[0, 2]);ax.set_xlim(0,1);ax.set_ylim(0,1);ax.axis("off")
boxes=[(.02,.68,.17,.14,"AEAD\nvalid"),(.27,.68,.18,.14,"BEGIN\nIMMEDIATE"),
       (.52,.68,.22,.14,"Replay + audit\nrows inserted"),(.81,.68,.16,.14,"COMMIT\nbefore reply")]
for x,y0,w,h,label in boxes:
    ax.add_patch(FancyBboxPatch((x,y0),w,h,boxstyle="round,pad=.02",fc="#F7F6F1",ec="#71808A",lw=.8))
    ax.text(x+w/2,y0+h/2,label,ha="center",va="center",fontsize=5.6,fontweight="bold")
for i in range(3):
    x1=boxes[i][0]+boxes[i][2];x2=boxes[i+1][0]
    ax.annotate("",(x2-.012,.735),(x1+.012,.735),arrowprops=dict(arrowstyle="-|>",lw=.9,color=COLORS["ink"]))
inside_tx = 10
after_commit = atomic["atomic"]["crash_trials_passed"] - inside_tx
for x, color, text in [
    (.04, "#F8ECEA", f"Crash inside transaction\n{inside_tx}/10 roll back both rows"),
    (.55, "#EAF3EC", f"Crash after commit\n{after_commit}/10 retain both rows"),
]:
    ax.add_patch(FancyBboxPatch((x,.32),.41,.18,boxstyle="round,pad=.025",fc=color,ec="#71808A",lw=.8))
    ax.text(x+.205,.41,text,ha="center",va="center",fontsize=5.7,fontweight="bold",color=COLORS["ink"])
ax.annotate("",(.245,.52),(.63,.67),arrowprops=dict(arrowstyle="-|>",color=COLORS["danger"],lw=1.0))
ax.annotate("",(.755,.52),(.89,.67),arrowprops=dict(arrowstyle="-|>",color=COLORS["safe"],lw=1.0))
groups = atomic["atomic"]["concurrent_groups"]
verified = atomic["atomic"]["independent_database_and_signature_check"]["verified_signatures"]
ax.text(.5,.12,f"{groups:,}/{groups:,} replay groups admit one request\n{verified:,}/{verified:,} admission signatures and links verify",
        ha="center",va="center",fontsize=5.6)
ax.set_title("c  Atomic state under crashes",loc="left",fontweight="bold",fontsize=7.6)

fig.savefig(OUT.with_suffix('.pdf'),bbox_inches='tight')
fig.savefig(OUT.with_suffix('.svg'),bbox_inches='tight')
fig.savefig(OUT.with_suffix('.tiff'),dpi=600,bbox_inches='tight',pil_kwargs={'compression':'tiff_lzw'})
fig.savefig(OUT.with_suffix('.png'),dpi=300,bbox_inches='tight')
plt.close(fig)
