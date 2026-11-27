#!/usr/bin/env python3
"""Does the blocking TLS accept delay new connections?

An internal audit flagged that the evaluated server performs the TLS handshake
inside ``get_request``, which runs on the accept thread, so one in-flight
handshake blocks acceptance of every other new connection, while the
post-quantum modes handshake in the handler thread. This driver measures that
directly: it opens N concurrent TLS connections and reports the distribution of
TCP connect latency for the connections that queue behind a handshake.

Run against two server variants (evaluated vs. handshake moved to the worker
thread) and compare. Client-side connect latency is the quantity an arriving
client experiences, so it is the right measure of an accept-thread stall.

    python3 tls_accept_stress.py --port 9701 --connections 32 --rounds 20 \
        --json-out accept_stress.json
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List


def one_connect(host: str, port: int, ctx: ssl.SSLContext,
                barrier: threading.Barrier, results: List[Dict[str, Any]],
                idx: int) -> None:
    rec: Dict[str, Any] = {"idx": idx}
    try:
        barrier.wait(timeout=30)
        s = socket.create_connection((host, port), timeout=15)
        t0 = time.perf_counter_ns()
        try:
            tls = ctx.wrap_socket(s, server_hostname="localhost")
            tls.close()
            rec["tcp_and_handshake_ms"] = (time.perf_counter_ns() - t0) / 1e6
            rec["ok"] = True
        except ssl.SSLError as e:
            rec["ok"] = False
            rec["error"] = f"SSLError: {e}"
            s.close()
    except Exception as e:  # noqa: BLE001
        rec["ok"] = False
        rec["error"] = f"{type(e).__name__}: {e}"
    results.append(rec)


def run_round(host: str, port: int, ctx: ssl.SSLContext, n: int) -> Dict[str, Any]:
    barrier = threading.Barrier(n)
    results: List[Dict[str, Any]] = []
    ts = [threading.Thread(target=one_connect,
                           args=(host, port, ctx, barrier, results, i))
          for i in range(n)]
    t0 = time.perf_counter()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    wall = time.perf_counter() - t0

    ok = [r for r in results if r.get("ok")]
    lat = sorted(r["tcp_and_handshake_ms"] for r in ok)
    def q(p: float) -> float:
        return lat[min(len(lat) - 1, int(p * len(lat)))] if lat else float("nan")
    return {
        "connections": n,
        "accepted": len(ok),
        "failed": n - len(ok),
        "wall_s": wall,
        "conns_per_s": n / wall,
        "connect_p50_ms": statistics.median(lat) if lat else float("nan"),
        "connect_p95_ms": q(0.95),
        "connect_max_ms": max(lat) if lat else float("nan"),
        "errors": sorted({r.get("error", "") for r in results if not r.get("ok")}),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--connections", type=int, default=32)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--json-out", type=str, default=None)
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    rounds = [run_round(args.host, args.port, ctx, args.connections)
              for _ in range(args.rounds)]

    summary = {
        "label": args.label,
        "connections_per_round": args.connections,
        "rounds": args.rounds,
        "accepted_total": sum(r["accepted"] for r in rounds),
        "attempted_total": sum(r["connections"] for r in rounds),
        "failed_total": sum(r["failed"] for r in rounds),
        "conns_per_s_median": statistics.median(r["conns_per_s"] for r in rounds),
        "connect_p50_ms_median": statistics.median(r["connect_p50_ms"] for r in rounds),
        "connect_p95_ms_median": statistics.median(r["connect_p95_ms"] for r in rounds),
        "connect_max_ms_worst": max(r["connect_max_ms"] for r in rounds),
        "per_round": rounds,
    }
    print(f"{args.label or 'server'}: accepted {summary['accepted_total']}/"
          f"{summary['attempted_total']}  "
          f"{summary['conns_per_s_median']:.1f} conns/s  "
          f"connect p50 {summary['connect_p50_ms_median']:.2f} ms  "
          f"p95 {summary['connect_p95_ms_median']:.2f} ms  "
          f"worst {summary['connect_max_ms_worst']:.1f} ms")
    if summary["failed_total"]:
        print(f"  failures: {summary['failed_total']}")

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
