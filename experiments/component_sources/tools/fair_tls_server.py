#!/usr/bin/env python3
"""Experimental server variant that measures whether the blocking TLS accept matters.

The evaluated server wraps the socket inside ``get_request``, which runs on the
accept thread, so one in-flight handshake blocks acceptance of every other new
connection. The post-quantum modes complete their handshake inside the handler
thread instead, so the two are not implemented symmetrically. An internal audit
flagged this and required either an execution-source proof or a minimal
controlled comparison before any protocol-superiority claim is retained.

This module provides the minimal comparison without touching the evaluated code.
It subclasses the evaluated server classes and moves only the TLS wrap from the
accept thread into the per-connection worker thread, leaving protocol handling,
timing boundaries and record format unchanged. Because the client measures TCP
connect and the security handshake as separate intervals, moving the wrap does
not move any measured quantity between those intervals for the accepted
connection; it only stops one client's handshake from delaying another client's
accept.

Usage:
  # baseline (evaluated behaviour): blocking wrap on the accept thread
  python3 fair_tls_server.py --mode tls13 --port 9500 --workdir /tmp/exp
  # fair variant: wrap inside the worker thread
  python3 fair_tls_server.py --mode tls13 --port 9500 --workdir /tmp/exp --fair

Then drive both with the evaluated client and compare.
"""

from __future__ import annotations

import argparse
import socketserver
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def _import_evaluated(src_dir: Optional[str]):
    if src_dir:
        sys.path.insert(0, src_dir)
    import pqguard_network_server as ev  # type: ignore
    return ev


def make_fair_server(ev, pq_server, mode: str):
    """Return a server class whose TLS handshake runs in the worker thread."""

    Base = ev.TLSThreadedTCPServer if mode == "tls13" else ev.ThreadedTCPServer

    class FairTLSThreadedTCPServer(Base):
        """TLS server that never blocks the accept loop on a handshake.

        ``get_request`` returns the raw socket. The handshake is performed at
        the start of the worker thread, and the time spent in it is recorded so
        the setup interval remains attributable.
        """

        handshake_ns: list = []

        def get_request(self) -> Tuple[Any, Any]:
            sock, addr = socketserver.TCPServer.get_request(self)
            if getattr(self, "_fair", False):
                # Fair variant: hand the raw socket to the worker thread, which
                # performs the handshake so the accept loop never blocks.
                return sock, addr
            if self.pq_server.ssl_ctx is None:
                return sock, addr
            # Baseline: the evaluated behaviour, handshake on the accept thread.
            try:
                return self.pq_server.ssl_ctx.wrap_socket(sock, server_side=True), addr
            except ssl.SSLError:
                sock.close()
                raise

        def process_request_thread(self, request, client_address) -> None:  # type: ignore[override]
            if getattr(self, "_fair", False):
                t0 = time.perf_counter_ns()
                try:
                    request = self.pq_server.ssl_ctx.wrap_socket(
                        request, server_side=True
                    )
                except ssl.SSLError:
                    try:
                        request.close()
                    finally:
                        self.shutdown_request(request)
                    return
                self.handshake_ns.append(time.perf_counter_ns() - t0)
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                self.shutdown_request(request)

    return FairTLSThreadedTCPServer


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--fair", action="store_true",
                    help="move the TLS handshake into the worker thread")
    ap.add_argument("--src-dir", default=None,
                    help="directory containing pqguard_network_server.py")
    ap.add_argument("--max-connections", type=int, default=25)
    ap.add_argument("--certfile", default=None)
    ap.add_argument("--keyfile", default=None)
    args = ap.parse_args()

    ev = _import_evaluated(args.src_dir)
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    certfile = Path(args.certfile) if args.certfile else None
    keyfile = Path(args.keyfile) if args.keyfile else None
    if args.mode == "tls13":
        if not (certfile and keyfile):
            raise SystemExit("--mode tls13 requires --certfile and --keyfile")
        for f in (certfile, keyfile):
            if not f.exists():
                raise SystemExit(f"missing {f}")

    # Reuse the evaluated server construction so protocol state is identical.
    server = ev.PQNetworkServer(
        mode=args.mode, server_id="fair-tls", workdir=workdir, port=args.port,
        certfile=certfile,
        keyfile=keyfile,
    )
    if args.mode == "tls13":
        server.ssl_ctx = ev.make_tls_context(certfile, keyfile)

    ServerClass = make_fair_server(ev, server, args.mode)
    httpd = ServerClass((args.listen, args.port), ev.PQServerHandler)
    httpd.pq_server = server
    httpd._fair = args.fair
    httpd.handshake_ns = []

    print(f"listening on {args.listen}:{args.port} mode={args.mode} "
          f"fair={args.fair}", flush=True)
    server.write_ready()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    if httpd.handshake_ns:
        import statistics
        ms = [x / 1e6 for x in httpd.handshake_ns]
        print(f"handshakes={len(ms)} median={statistics.median(ms):.3f} ms "
              f"p95={sorted(ms)[int(0.95*(len(ms)-1))]:.3f} ms", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
