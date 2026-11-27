#!/usr/bin/env python3
"""What survives a crash between admission commit and response completion?

Section 6.4 of the manuscript states that the single-database transaction ends
before inference, so the atomicity result does not establish exactly-once
inference, response-completion logging, or client delivery. That gap is stated
but never quantified. This harness measures it.

Design
------
One SQLite database holds the replay claim and the signed request-admission row,
committed together before inference, exactly as the evaluated single-database
path does. A worker process then simulates inference and writes a
response-completion row. The parent kills the worker at a chosen boundary and
reports the durable database state:

  after_admission_commit   admission rows present, no completion rows
  mid_inference            killed inside the simulated inference window
  after_completion_write   completion row written but not yet committed
  after_completion_commit  both rows durable

The quantity of interest is the admitted-but-uncompleted count at each boundary:
those are requests the server accepted, for which a client may have received a
response, and for which no completion record exists. It bounds how much of the
served traffic the audit trail can miss under a crash.

Run:
    python3 commit_boundary_experiment.py --trials 5 --infer-ms 400 \
        --json-out commit_boundary.json
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

WORKER = r'''
import json, os, sqlite3, sys, time
db, marker, infer_ms, boundary = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
seq = int(sys.argv[5])
conn = sqlite3.connect(db, isolation_level=None)
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA synchronous=FULL")
conn.execute("BEGIN IMMEDIATE")
conn.execute("INSERT OR ABORT INTO replay_claims(session_id,direction,sequence) VALUES(?,?,?)",
             ("s", "request", seq))
conn.execute("INSERT OR ABORT INTO admissions(session_id,sequence,signature) VALUES(?,?,?)",
             ("s", seq, "aa" * 500))
conn.execute("COMMIT")
open(marker + ".admitted", "w").close()
if boundary == "after_admission_commit":
    time.sleep(30)
# simulated inference window
time.sleep(infer_ms / 1000.0)
conn.execute("BEGIN IMMEDIATE")
conn.execute("INSERT OR ABORT INTO completions(session_id,sequence,response_hash) VALUES(?,?,?)",
             ("s", seq, "bb" * 32))
if boundary == "after_completion_write":
    open(marker + ".written", "w").close()
    time.sleep(30)
conn.execute("COMMIT")
open(marker + ".committed", "w").close()
time.sleep(30)
'''

SCHEMA = """
CREATE TABLE IF NOT EXISTS replay_claims (
    session_id TEXT NOT NULL, direction TEXT NOT NULL, sequence INTEGER NOT NULL,
    PRIMARY KEY (session_id, direction, sequence));
CREATE TABLE IF NOT EXISTS admissions (
    session_id TEXT NOT NULL, sequence INTEGER NOT NULL, signature TEXT NOT NULL,
    PRIMARY KEY (session_id, sequence));
CREATE TABLE IF NOT EXISTS completions (
    session_id TEXT NOT NULL, sequence INTEGER NOT NULL, response_hash TEXT NOT NULL,
    PRIMARY KEY (session_id, sequence));
"""


def state(db: Path) -> Dict[str, int]:
    con = sqlite3.connect(str(db))
    try:
        q = lambda t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        replay, adm, comp = q("replay_claims"), q("admissions"), q("completions")
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        return {
            "replay_claims": replay,
            "admissions": adm,
            "completions": comp,
            "admitted_without_completion": adm - comp,
            "integrity": integrity,
        }
    finally:
        con.close()


def run_trial(boundary: str, infer_ms: float, seq: int, workdir: Path,
              worker_src: Path) -> Dict[str, Any]:
    db = workdir / f"state_{boundary}_{seq}.sqlite3"
    marker = workdir / f"marker_{boundary}_{seq}"
    con = sqlite3.connect(str(db))
    con.executescript(SCHEMA)
    con.commit()
    con.close()

    proc = subprocess.Popen(
        [sys.executable, str(worker_src), str(db), str(marker), str(infer_ms),
         boundary, str(seq)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    # Wait for the boundary signal we intend to kill at.
    targets = {
        "after_admission_commit": Path(str(marker) + ".admitted"),
        "mid_inference": Path(str(marker) + ".admitted"),
        "after_completion_write": Path(str(marker) + ".written"),
        "after_completion_commit": Path(str(marker) + ".committed"),
    }
    wait_for = targets[boundary]
    deadline = time.time() + 20
    while not wait_for.exists() and time.time() < deadline:
        time.sleep(0.005)
    if boundary == "mid_inference":
        # Kill part-way through the inference window.
        time.sleep(infer_ms / 2000.0)
    signalled = wait_for.exists()
    if not signalled:
        proc.kill()
        proc.wait(timeout=10)
        return {"boundary": boundary, "error": "boundary marker never appeared"}

    proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=10)

    # Remove WAL side files the way a crash leaves them, then read durable state.
    return {"boundary": boundary, "signalled": True, **state(db)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--infer-ms", type=float, default=400.0)
    ap.add_argument("--json-out", type=str, default=None)
    args = ap.parse_args()

    boundaries = ["after_admission_commit", "mid_inference",
                  "after_completion_write", "after_completion_commit"]

    with tempfile.TemporaryDirectory(prefix="pqguard-commit-") as tmp:
        workdir = Path(tmp)
        worker_src = workdir / "worker.py"
        worker_src.write_text(WORKER, encoding="utf-8")

        results: Dict[str, List[Dict[str, Any]]] = {b: [] for b in boundaries}
        for b in boundaries:
            for t in range(args.trials):
                r = run_trial(b, args.infer_ms, t, workdir, worker_src)
                results[b].append(r)

    summary: Dict[str, Any] = {"trials_per_boundary": args.trials,
                               "infer_ms": args.infer_ms, "boundaries": {}}
    print(f"{'boundary':26} {'trials':>6} {'admissions':>11} {'completions':>12} "
          f"{'admitted w/o completion':>24}")
    for b, rows in results.items():
        adm = [r.get("admissions", 0) for r in rows]
        comp = [r.get("completions", 0) for r in rows]
        gap = [r.get("admitted_without_completion", 0) for r in rows]
        integrity = {r.get("integrity") for r in rows}
        summary["boundaries"][b] = {
            "admissions": adm, "completions": comp,
            "admitted_without_completion": gap,
            "integrity": sorted(str(i) for i in integrity),
            "raw": rows,
        }
        print(f"{b:26} {len(rows):>6} {sum(adm)/len(adm):>11.1f} {sum(comp)/len(comp):>12.1f} "
              f"{sum(gap)/len(gap):>24.1f}")

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwritten to {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
