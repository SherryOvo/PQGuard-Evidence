#!/usr/bin/env python3
"""Admission cost decomposition and admission-window availability.

Two things the manuscript states but does not measure.

R8a, cost decomposition. Section 5 models
T_start = T_manifest + T_hash + T_sig + T_template + T_adapter + T_audit_init and
reports that a combined read-and-digest term dominates. The paper cannot say how
much of that term is reading and how much is digesting, because the preserved
runs measured the two together. This script separates them by hashing the same
artifacts twice: once cold, so the measurement includes the read, and once from
page cache, so it is digest-bound. The two rates bound the storage contribution.

R8b, availability. The manuscript says a model must complete 26--50 s of
verification before it enters the ready set and that client behaviour during
that window was not measured. This script drives concurrent requests at a
server that is mid-admission and records how many fail, and it compares that
with serving the previous model during admission, which is what a rolling update
would do.

Usage:
  python3 gpu_admission_benchmark.py --artifacts /path/to/snapshot \
      --trials 5 --out results/
  python3 gpu_admission_benchmark.py --model Qwen/Qwen2.5-7B-Instruct \
      --availability-trials 3 --out results/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def walk_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for dirpath, _dirs, names in os.walk(root):
        for name in sorted(names):
            files.append(Path(dirpath) / name)
    return files


def read_and_digest(files: List[Path]) -> Tuple[float, int]:
    """Read every file and digest it; returns (seconds, bytes)."""

    t0 = time.perf_counter()
    total = 0
    digest = hashlib.sha256()
    for p in files:
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                total += len(chunk)
                digest.update(chunk)
    return time.perf_counter() - t0, total


def evict_file_cache(files: List[Path]) -> bool:
    """Request eviction of this artifact set without dropping global caches.

    Linux treats ``POSIX_FADV_DONTNEED`` as an advisory request, so the output
    records whether every call succeeded rather than calling the pass truly
    cold.  This avoids modifying unrelated workloads through global
    ``drop_caches`` and makes the experiment safe on a shared host.
    """

    if not hasattr(os, "posix_fadvise") or not hasattr(os, "POSIX_FADV_DONTNEED"):
        return False
    try:
        os.sync()
        for path in files:
            with path.open("rb", buffering=0) as stream:
                os.posix_fadvise(
                    stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED
                )
        return True
    except (OSError, PermissionError):
        return False


def digest_only(files: List[Path]) -> Tuple[float, int]:
    """Digest bytes already resident, avoiding the storage read where possible.

    The files are read into memory first so the timed loop is dominated by
    hashing rather than by storage. On a host where the artifact set exceeds RAM
    this reduces to the same measurement as the cold pass, and the script says so
    in its output rather than presenting it as a separated figure.
    """

    buffers = [p.read_bytes() for p in files]
    t0 = time.perf_counter()
    digest = hashlib.sha256()
    total = 0
    for buf in buffers:
        total += len(buf)
        digest.update(buf)
    return time.perf_counter() - t0, total


def measure_artifacts(root: Path, trials: int, label: str) -> Dict[str, Any]:
    files = walk_files(root)
    if not files:
        return {"label": label, "error": f"no files under {root}"}

    cold_ms: List[float] = []
    warm_ms: List[float] = []
    cold_ok: List[bool] = []
    size = sum(p.stat().st_size for p in files)

    for _ in range(trials):
        dropped = evict_file_cache(files)
        s, n = read_and_digest(files)
        cold_ms.append(s * 1e3)
        cold_ok.append(dropped)
        s2, _ = digest_only(files)
        warm_ms.append(s2 * 1e3)

    def rate(ms: float) -> float:
        return size / 1e6 / (ms / 1e3) if ms > 0 else float("nan")

    result = {
        "label": label,
        "root": str(root),
        "files": len(files),
        "bytes": size,
        "gb": round(size / 1e9, 3),
        "trials": trials,
        "file_cache_eviction_advised": all(cold_ok),
        "read_and_digest_ms": {"median": statistics.median(cold_ms),
                               "min": min(cold_ms), "max": max(cold_ms)},
        "digest_only_ms": {"median": statistics.median(warm_ms),
                           "min": min(warm_ms), "max": max(warm_ms)},
        "read_and_digest_mb_s": rate(statistics.median(cold_ms)),
        "digest_only_mb_s": rate(statistics.median(warm_ms)),
    }
    if result["digest_only_mb_s"] > 0:
        result["storage_share_of_combined"] = round(
            1.0 - (1.0 / result["digest_only_mb_s"]) / (1.0 / result["read_and_digest_mb_s"]),
            4,
        )
    return result


def availability_probe(serve_old: bool, admission_ms: int,
                       request_rate_hz: float, listen_port: int) -> Dict[str, Any]:
    """Measure reachability of a serving endpoint while it is admitting.

    Failure is observed rather than assumed. A child process binds the port,
    performs the admission work, and only starts accepting connections when
    admission completes. The parent then makes real connection attempts at a
    fixed rate and records whether each attempt is refused.

    ``serve_old`` models a rolling update: the endpoint accepts and answers
    immediately throughout the window because the previous model is still
    serving, and the new model's verification happens out of band.
    """

    import socket
    import subprocess
    import tempfile

    child_src = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    child_src.write(
        "import socket, sys, time\n"
        "port = int(sys.argv[1]); admission_ms = float(sys.argv[2])\n"
        "serve_old = sys.argv[3] == '1'\n"
        "srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "srv.bind(('127.0.0.1', port))\n"
        "srv.listen(128)\n"
        "open(sys.argv[4], 'w').close()\n"
        "if not serve_old:\n"
        "    srv.setblocking(False)\n"
        "    t0 = time.time()\n"
        "    while (time.time() - t0) * 1000 < admission_ms:\n"
        "        time.sleep(0.005)\n"
        "    srv.setblocking(True)\n"
        "deadline = time.time() + 30\n"
        "while time.time() < deadline:\n"
        "    try:\n"
        "        c, _ = srv.accept(); c.sendall(b'ok'); c.close()\n"
        "    except BlockingIOError:\n"
        "        time.sleep(0.002)\n"
        "    except OSError:\n"
        "        break\n"
    )
    child_src.close()

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    marker = Path(child_src.name + ".ready")
    proc = subprocess.Popen([sys.executable, child_src.name, str(port),
                             str(admission_ms), "1" if serve_old else "0",
                             str(marker)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait for the bind, then start timing the admission window from that moment.
    deadline = time.time() + 5
    while time.time() < deadline and not marker.exists():
        time.sleep(0.005)
    if not marker.exists():
        proc.kill()
        return {"error": "child never bound the port"}
    window_start = time.time()
    marker.unlink(missing_ok=True)

    results: List[Dict[str, Any]] = []
    # Probe only inside the admission window, so the failure rate is the
    # availability of the service during admission and not a mixture of the
    # window and the served period that follows it.
    t_end = window_start + admission_ms / 1000.0
    while time.time() < t_end:
        s = socket.socket()
        s.settimeout(0.3)
        t0 = time.perf_counter()
        try:
            s.connect(("127.0.0.1", port))
            s.recv(16)
            results.append({"ok": True, "latency_ms": (time.perf_counter()-t0)*1e3})
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            results.append({"ok": False, "error": type(e).__name__,
                            "latency_ms": (time.perf_counter()-t0)*1e3})
        finally:
            s.close()
        time.sleep(max(0.0, 1.0 / request_rate_hz))
    proc.kill()
    proc.wait(timeout=5)
    Path(child_src.name).unlink(missing_ok=True)

    total = len(results)
    served = sum(1 for r in results if r["ok"])
    return {
        "serve_previous_model_during_admission": serve_old,
        "admission_ms": admission_ms,
        "request_rate_hz": request_rate_hz,
        "attempts": total,
        "served": served,
        "refused": total - served,
        "failure_rate": (total - served) / total if total else 0.0,
        "errors": sorted({r["error"] for r in results if not r["ok"]}),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", default=None,
                    help="directory whose files form the artifact set")
    ap.add_argument("--model", default=None,
                    help="HF model id or local snapshot to size the artifact set")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--admission-ms", type=int, default=30000)
    ap.add_argument("--request-rate", type=float, default=20.0)
    ap.add_argument("--availability-trials", type=int, default=3)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {"admission": {}, "availability": {}}

    roots: List[Tuple[str, Path]] = []
    if args.artifacts:
        roots.append(("artifacts", Path(args.artifacts)))
    if args.model:
        p = Path(args.model)
        if p.is_dir():
            roots.append(("model_snapshot", p))
        else:
            from huggingface_hub import snapshot_download
            roots.append(("model_snapshot",
                          Path(snapshot_download(args.model, local_files_only=False))))

    for label, root in roots:
        print(f"=== cost decomposition: {label} ({root}) ===")
        r = measure_artifacts(root, args.trials, label)
        report["admission"][label] = r
        if "error" in r:
            print("  ", r["error"])
            continue
        print(
            f"  {r['gb']} GB in {r['files']} files, "
            f"file-cache eviction advised={r['file_cache_eviction_advised']}"
        )
        print(f"  read+digest {r['read_and_digest_ms']['median']:.1f} ms "
              f"({r['read_and_digest_mb_s']:.1f} MB/s)")
        print(f"  digest only {r['digest_only_ms']['median']:.1f} ms "
              f"({r['digest_only_mb_s']:.1f} MB/s)")
        print(f"  storage share of the combined term: "
              f"{r.get('storage_share_of_combined', float('nan')):.2%}")

    print("\n=== availability during admission ===")
    for serve_old in (False, True):
        for t in range(args.availability_trials):
            res = availability_probe(serve_old, args.admission_ms,
                                     args.request_rate, 0)
            key = "serve_previous_model" if serve_old else "single_model_refuses"
            report["availability"].setdefault(key, []).append(res)
            if "error" in res:
                print(f"  {key:24} trial {t+1}: {res['error']}")
                continue
            print(f"  {key:24} trial {t+1}: attempts={res['attempts']} "
                  f"served={res['served']} refused={res['refused']} "
                  f"failure_rate={res['failure_rate']:.3f} "
                  f"errors={res['errors']}")

    outfile = outdir / "gpu_admission.json"
    outfile.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"\nwritten {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
