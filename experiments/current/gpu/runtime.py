#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


def atomic(path, value):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, indent=2))
    os.replace(tmp, path)


class WitnessProcess:
    def __init__(self, case, public, stream):
        self.case, self.public, self.stream = Path(case), public, stream
        self.proc = None
        self.handle = None
        atomic(self.case / "registry.json", {stream: dict(algorithm=public["audit"], public_key_hex=public["audit_public_key"])})
        self.start()

    def start(self):
        ready = self.case / "witness_ready.json"
        ready.unlink(missing_ok=True)
        self.handle = (self.case / "witness.log").open("a")
        argv = [sys.executable, str(Path(__file__).with_name("r7_witness.py")),
                "--db", str(self.case / "witness.sqlite"), "--registry", str(self.case / "registry.json"),
                "--ready", str(ready)]
        self.proc = subprocess.Popen(argv, stdout=self.handle, stderr=subprocess.STDOUT)
        start = time.monotonic()
        while not ready.exists():
            if self.proc.poll() is not None or time.monotonic() - start > 60:
                raise RuntimeError("witness failed to start: " + str(self.case))
            time.sleep(.1)
        self.port = json.loads(ready.read_text())["port"]

    def request(self, value):
        with socket.create_connection(("127.0.0.1", self.port), timeout=60) as c:
            c.settimeout(60)
            c.sendall(json.dumps(value).encode() + b"\n")
            response = bytearray()
            while not response.endswith(b"\n"):
                part = c.recv(65536)
                if not part:
                    raise ConnectionError("incomplete witness reply")
                response.extend(part)
            return json.loads(response)

    def publish(self, stream, counter, digest, signature):
        return self.request(dict(op="publish", stream=stream, counter=counter,
                                 digest=digest, signature_hex=signature.hex()))

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.handle:
            self.handle.close()
