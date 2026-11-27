#!/usr/bin/env python3
"""One experiment-only SSH forward. Bounded reconnect, no GPU execution."""
import fcntl,json,os,signal,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];child=None
def save(v):
 p=ROOT/'state/TUNNEL_STATUS.json';t=p.with_suffix('.tmp');t.write_text(json.dumps(v,indent=2));os.replace(t,p)
def stop(*_):
 if child and child.poll() is None:child.terminate()
 raise SystemExit(0)
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
lock=(ROOT/'state/tunnel.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
c=json.loads((ROOT/'private/link.json').read_text())
cmd=['ssh','-N','-i',str(ROOT/'private/witness_tunnel_key'),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(ROOT/'private/witness_known_hosts'),'-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','-o','ConnectTimeout=15','-o','ExitOnForwardFailure=yes','-L',f"127.0.0.1:{c['local_forward_port']}:127.0.0.1:{c['remote_agent_port']}",c['user']+'@'+c['host']]
for attempt in range(1,21):
 with (ROOT/'logs/tunnel.log').open('a') as log:
  child=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
  save(dict(status='CONNECTING_OR_RUNNING',attempt=attempt,pid=child.pid));rc=child.wait()
 save(dict(status='RECONNECT_WAIT',attempt=attempt,returncode=rc));time.sleep(min(60,attempt*5))
save(dict(status='STOPPED_RETRY_LIMIT',attempts=20));raise SystemExit(1)
