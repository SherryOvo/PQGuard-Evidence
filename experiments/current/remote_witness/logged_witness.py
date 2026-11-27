#!/usr/bin/env python3
"""Instrument the submitted witness on a second host; no GPU or TLS claims."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import threading
import time

from r7_witness import WitnessStore


def enc(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()


def atom(path, x):
    p=path.with_suffix(path.suffix+'.tmp');p.write_text(json.dumps(x,indent=2));p.replace(path)


def quota():
    out={}
    for k,p in {'cpu_stat':'/sys/fs/cgroup/cpu/cpu.stat',
                'memory_current':'/sys/fs/cgroup/memory/memory.usage_in_bytes',
                'memory_peak':'/sys/fs/cgroup/memory/memory.max_usage_in_bytes'}.items():
        try:out[k]=Path(p).read_text().strip()
        except OSError:out[k]=None
    return out


def main():
    p=argparse.ArgumentParser();p.add_argument('--case',type=Path,required=True);a=p.parse_args()
    a.case.mkdir(parents=True,exist_ok=True)
    store=WitnessStore(a.case/'witness.sqlite',json.loads((a.case/'registry.json').read_text()))
    stop=threading.Event();write_lock=threading.Lock();threads=[]
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    boot=dt.datetime.now(dt.timezone.utc).isoformat()
    (a.case/'resource_snapshots.jsonl').open('a').write(json.dumps({'event':'start','utc':boot,'pid':os.getpid(),**quota()})+'\n')
    log=(a.case/'witness_events.jsonl').open('a',buffering=1)
    def handle(conn):
        start=time.perf_counter_ns();cpu=time.thread_time_ns();req=None
        with conn:
            conn.settimeout(30);buf=bytearray()
            try:
                while not buf.endswith(b'\n'):
                    b=conn.recv(65536)
                    if not b:raise ConnectionError('incomplete frame')
                    buf.extend(b)
                    if len(buf)>8_000_000:raise ValueError('frame too large')
                req=json.loads(buf)
                if req.get('op')=='publish':reply=store.publish(req)
                elif req.get('op')=='fetch':reply=store.fetch(str(req['stream']))
                elif req.get('op')=='health':reply={'ok':True,'reason':'healthy'}
                else:reply={'ok':False,'reason':'unknown_operation'}
            except Exception as e:reply={'ok':False,'reason':'handler_exception','error_type':type(e).__name__}
            row={'utc':dt.datetime.now(dt.timezone.utc).isoformat(),'pid':os.getpid(),
                 'request':req,'reply':reply,'handler_wall_ns':time.perf_counter_ns()-start,
                 'handler_thread_cpu_ns':time.thread_time_ns()-cpu}
            with write_lock:
                log.write(json.dumps(row,sort_keys=True)+'\n');log.flush();os.fsync(log.fileno())
            try:conn.sendall(enc(reply)+b'\n')
            except OSError:pass
    try:
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            server.bind(('127.0.0.1',0));server.listen(128);server.settimeout(.5)
            atom(a.case/'ready.json',{'host':'127.0.0.1','port':server.getsockname()[1],
                                    'pid':os.getpid(),'started_utc':boot})
            atom(a.case/'PID.json',{'pid':os.getpid()})
            while not stop.is_set():
                try:conn,_=server.accept()
                except socket.timeout:continue
                t=threading.Thread(target=handle,args=(conn,),daemon=False);t.start();threads.append(t)
                threads=[t for t in threads if t.is_alive()]
    finally:
        for t in threads:t.join(timeout=35)
        with store.lock:
            store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)');store.db.close()
        log.close()
        with (a.case/'resource_snapshots.jsonl').open('a') as f:
            f.write(json.dumps({'event':'stop','utc':dt.datetime.now(dt.timezone.utc).isoformat(),
                                'pid':os.getpid(),**quota()})+'\n')
        atom(a.case/'STOPPED.json',{'utc':dt.datetime.now(dt.timezone.utc).isoformat(),'pid':os.getpid()})


if __name__=='__main__':main()
