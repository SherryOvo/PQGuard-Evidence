#!/usr/bin/env python3
"""Independent-process Oracle client of the actual AutoDL witness.

Endpoint and password are supplied only over stdin and remain in memory.
All RPCs travel over a pinned SSH connection to a loopback listener on the
OTHER host. This is SSH-tunneled remote witness evidence, not direct WAN/TLS
measurement, independent administration, or malicious-witness tolerance.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import sqlite3
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

import paramiko
from experiment import Context, atomic, quantile
from r7_crypto_profiles import canonical, sha256
from r7_witness import witness_message
from verify import verify

ROOT=Path(__file__).resolve().parent
REMOTE_ROOT='/root/autodl-tmp/PQGuard_Remote_Witness_20261123'


class Remote:
    def __init__(self, secret, out):
        self.secret=secret
        self.out=out
        self.remote=REMOTE_ROOT+'/results/'+out.name
        self.lock=threading.Lock()
        self.log=(out/'rpc_events.jsonl').open('a',buffering=1)
        self.port=None
        self.client=None
        self.drop_ack=False
        self.connect()

    def connect(self):
        if self.client is not None:self.client.close()
        client=paramiko.SSHClient()
        client.load_host_keys(str(ROOT/'private/autodl_known_hosts'))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        s=self.secret
        client.connect(s['hostname'],port=s['port'],username=s['username'],password=s['password'],
                       look_for_keys=False,allow_agent=False,timeout=20,auth_timeout=20,banner_timeout=20)
        client.get_transport().set_keepalive(15)
        self.client=client

    def command(self, label, command, timeout=60):
        start=dt.datetime.now(dt.timezone.utc).isoformat()
        _,stdout,stderr=self.client.exec_command(command,timeout=timeout)
        answer=stdout.read().decode(errors='replace');err=stderr.read().decode(errors='replace')
        rc=stdout.channel.recv_exit_status()
        row=dict(label=label,utc=start,command=command,returncode=rc,stderr=err[:4000],stdout=answer[:4000])
        with (self.out/'remote_commands.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
        if rc:raise RuntimeError('remote operation failed: '+label+' rc='+str(rc))
        return answer

    def start(self, registry):
        r=self.remote;q=shlex.quote
        self.command('create_case','mkdir -p '+q(r))
        with self.client.open_sftp() as s:
            s.put(str(registry),r+'/registry.json.tmp');s.posix_rename(r+'/registry.json.tmp',r+'/registry.json')
        cmd=f'''set -eu
cd {q(REMOTE_ROOT)}
rm -f {q(r+'/ready.json')}
export PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
export OQS_INSTALL_PATH={q(REMOTE_ROOT+'/oqs_install')}
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib:${{LD_LIBRARY_PATH:-}}"
export PYTHONPATH={q(REMOTE_ROOT+'/vendor:'+REMOTE_ROOT)}
nohup setsid nice -n 15 /root/miniconda3/bin/python -u logged_witness.py --case {q(r)} </dev/null >>{q(r+'/console.log')} 2>&1 &
echo $! >{q(r+'/LAUNCH_PID')}
for i in $(seq 1 150); do
 if test -f {q(r+'/ready.json')}; then cat {q(r+'/ready.json')}; exit 0; fi
 sleep 0.1
done
exit 2
'''
        ready=json.loads(self.command('start_witness',cmd,timeout=35))
        self.port=int(ready['port']);self.pid=int(ready['pid'])
        atomic(self.out/'remote_ready.json',ready)
        ident="/root/miniconda3/bin/python -c \"from pathlib import Path;import hashlib,json,platform;print(json.dumps(dict(architecture=platform.machine(),campaign_host_identity_sha256=hashlib.sha256(b'pqguard-remote-20261123'+bytes([0])+Path('/etc/machine-id').read_bytes()).hexdigest())))\""
        atomic(self.out/'remote_host_identity.json',json.loads(self.command('read_host_identity',ident)))
        assert self.call({'op':'health'}).get('ok')

    def call(self, request):
        start=time.perf_counter_ns();result=None;error=None
        try:
            transport=self.client.get_transport() if self.client is not None else None
            if transport is None or not transport.is_active():
                raise ConnectionError('experiment SSH transport is closed')
            channel=transport.open_channel('direct-tcpip',('127.0.0.1',self.port),
                                                             ('127.0.0.1',0),timeout=15)
            with channel:
                channel.settimeout(30);channel.sendall(canonical(request)+b'\n');buf=bytearray()
                while not buf.endswith(b'\n'):
                    b=channel.recv(65536)
                    if not b:raise ConnectionError('incomplete remote reply')
                    buf.extend(b)
                    if len(buf)>8_000_000:raise ValueError('reply too large')
                result=json.loads(buf)
            if self.drop_ack and request.get('op')=='publish' and result.get('ok'):
                self.drop_ack=False
                raise ConnectionError('INJECTED acknowledgement loss after actual remote acceptance')
            return result
        except Exception as e:
            error=type(e).__name__+': '+str(e)
            raise
        finally:
            row=dict(utc=dt.datetime.now(dt.timezone.utc).isoformat(),request=request,reply=result,
                     error=error,roundtrip_ns=time.perf_counter_ns()-start,
                     path='persistent SSH transport; new direct-tcpip channel per RPC')
            with self.lock:self.log.write(json.dumps(row,sort_keys=True)+'\n')

    def stop(self, hard=False):
        transport=self.client.get_transport() if self.client is not None else None
        if transport is None or not transport.is_active():self.connect()
        sig='KILL' if hard else 'TERM'
        q=shlex.quote
        # A PID is signalled only if its command line includes this exact case.
        cmd=f'''set -eu
PID={self.pid}
if test -r /proc/$PID/cmdline; then
 grep -a -F -- {q(self.remote)} /proc/$PID/cmdline >/dev/null
 kill -{sig} "$PID"
fi
for i in $(seq 1 100); do
 if ! test -r /proc/$PID/stat; then exit 0; fi
 STATE=$(awk '{{print $3}}' /proc/$PID/stat 2>/dev/null) || exit 0
 if test "$STATE" = Z; then exit 0; fi
 sleep 0.1
done
exit 3
'''
        self.command('kill_own_witness_'+sig,cmd,timeout=20)

    def collect(self):
        dest=self.out/'remote_artifacts';dest.mkdir(exist_ok=True)
        names=['witness.sqlite','witness_events.jsonl','resource_snapshots.jsonl',
               'registry.json','ready.json','STOPPED.json','console.log']
        with self.client.open_sftp() as s:
            for name in names:
                try:s.get(self.remote+'/'+name,str(dest/name))
                except FileNotFoundError:continue
            s.get(self.remote+'/witness.sqlite',str(self.out/'witness.sqlite'))
            s.get(REMOTE_ROOT+'/witness_environment.json',str(self.out/'witness_environment.json'))
        atomic(self.out/'remote_artifact_hashes.json',
               {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(dest.iterdir()) if p.is_file()})

    def finish(self):
        try:
            self.stop();self.collect()
        finally:
            self.log.close();self.client.close()


class TunnelWitness:
    def __init__(self, remote):self.remote=remote
    def publish(self,stream,counter,digest,signature):
        return self.remote.call(dict(op='publish',stream=stream,counter=counter,
                                     digest=digest,signature_hex=signature.hex()))
    def fetch(self,stream):return self.remote.call(dict(op='fetch',stream=stream))


class RemoteContext(Context):
    def __init__(self,secret,out,profile):
        self.secret=secret;self.control=None
        super().__init__(out,'submitted_cbas',profile)
    def start_witness(self):
        if self.control is None:self.control=Remote(self.secret,self.out)
        self.control.start(self.out/'registry.json')
        self.witness=TunnelWitness(self.control)
    def stop_witness(self):self.control.finish()


def cell(args,secret):
    ctx=RemoteContext(secret,args.out,args.profile);rows=[];warm=[];failure=None
    try:
        for seq in range(5):warm.append(ctx.request(seq,'warmup'))
        barrier=threading.Barrier(args.workers)
        n=max(64,args.workers*4)
        start=time.perf_counter_ns()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            rows=list(pool.map(lambda j:ctx.request(1000+j,barrier=barrier),range(n)))
        wall=time.perf_counter_ns()-start
        integrity=ctx.store.integrity();head=ctx.witness.fetch(ctx.stream)
        values=[r['elapsed_ns']/1e6 for r in rows if r['success']]
        result=dict(profile=args.profile,workers=args.workers,repetition=args.repetition,
                    independent_process_pid=os.getpid(),requests=n,successes=len(values),
                    failures=n-len(values),warmups=len(warm),warmup_successes=sum(r['success'] for r in warm),
                    max_in_flight=ctx.max_inflight,wall_ns=wall,throughput_success_s=len(values)/(wall/1e9),
                    median_ms=quantile(values,.5),p95_ms=quantile(values,.95),
                    integrity=integrity,remote_head=head,session_setup_ns=ctx.session.setup_ns,
                    scope='Oracle CPU lifecycle through genuine AutoDL-host witness; SSH-tunneled',
                    no_gpu=True,latency_success_only=True,
                    excluded='LLM inference, client network transport, and SSH/session establishment')
        result['passed']=(all(r['success'] for r in warm) and len(values)==n
                          and integrity['integrity']=='ok' and integrity['pending']==0
                          and integrity['pending_witness_publications']==0
                          and head.get('counter')==integrity['counter'] and head.get('digest')==integrity['head'])
    finally:
        ctx.close()
    verification=verify(args.out)
    atomic(args.out/'independent_verification.json',verification)
    result['independent_verifier_passed']=verification['passed']
    result['passed']=result['passed'] and verification['passed']
    atomic(args.out/'cell.json',result)
    print(json.dumps(result),flush=True)
    return 0 if result['passed'] else 1


def faults(args,secret):
    ctx=RemoteContext(secret,args.out,args.profile);checks=[]
    def check(name,ok,**data):
        checks.append(dict(case=name,passed=bool(ok),**data))
        atomic(args.out/'fault_progress.json',checks)
    try:
        check('initial_authenticated_roundtrip',ctx.request(1,'fault_control')['success'])
        # Real remote process death, not a pre-write exception.
        ctx.control.stop(hard=True)
        row=ctx.request(2,'actual_remote_witness_SIGKILL')
        check('remote_process_death_blocks_release',not row['response_released']
              and ctx.store.integrity()['pending_witness_publications']==1)
        ctx.start_witness();ctx.store.witness=ctx.witness;ctx.store.flush_witness_outbox()
        check('remote_restart_recovers_pending_tuple',ctx.store.integrity()['pending_witness_publications']==0)
        # Close the actual authenticated inter-host SSH transport.
        ctx.control.client.close()
        row=ctx.request(3,'actual_experiment_SSH_transport_closed')
        check('tunnel_outage_blocks_release',not row['response_released']
              and ctx.store.integrity()['pending_witness_publications']==1)
        ctx.control.connect();ctx.store.flush_witness_outbox()
        check('tunnel_reconnect_recovers_outbox',ctx.store.integrity()['pending_witness_publications']==0)
        # Loss is explicitly injected AFTER receiving actual remote acceptance.
        ctx.control.drop_ack=True
        row=ctx.request(4,'injected_lost_ack_after_remote_commit')
        before=ctx.witness.fetch(ctx.stream)
        check('lost_ack_leaves_pending_without_release',not row['response_released']
              and ctx.store.integrity()['pending_witness_publications']==1)
        ctx.store.flush_witness_outbox();after=ctx.witness.fetch(ctx.stream)
        check('lost_ack_retry_idempotent',before==after and ctx.store.integrity()['pending_witness_publications']==0)
        # Preserve an authentic old local snapshot, then advance only live state.
        snapshot=args.out/'stale_snapshot.sqlite'
        with ctx.store.lock:
            target=sqlite3.connect(snapshot);ctx.store.db.backup(target);target.close()
        assert ctx.request(5,'advance_after_snapshot')['success']
        db=sqlite3.connect(snapshot)
        old_meta=dict(db.execute('SELECT key,value FROM metadata'))
        old_tuple=db.execute('SELECT stream,counter,digest,signature FROM witness_outbox ORDER BY counter DESC LIMIT 1').fetchone()
        db.close()
        current=ctx.witness.fetch(ctx.stream)
        check('authentic_snapshot_is_stale_against_remote',int(old_meta['counter'])<current['counter']
              and old_meta['head']!=current['digest'],old_head=old_meta,remote_head=current)
        rejected=ctx.witness.publish(old_tuple[0],old_tuple[1],old_tuple[2],bytes(old_tuple[3]))
        check('old_authentic_publication_rejected',rejected.get('reason')=='counter_regression',reply=rejected)
        for label,counter,digest,signature_override,expected in [
            ('same_counter_conflict',current['counter'],sha256(b'conflict'),None,'same_counter_conflict'),
            ('counter_gap',current['counter']+2,sha256(b'gap'),None,'counter_gap'),
            ('invalid_signature',current['counter']+1,sha256(b'invalid'),b'invalid','invalid_signature')]:
            sig=signature_override if signature_override is not None else ctx.profile.sign_audit(witness_message(ctx.stream,counter,digest))
            reply=ctx.witness.publish(ctx.stream,counter,digest,sig)
            check(label,reply.get('reason')==expected and not reply.get('ok'),reply=reply)
        b=threading.Barrier(32)
        with ThreadPoolExecutor(max_workers=32) as pool:
            copies=list(pool.map(lambda _:ctx.request(900,'32_copy_replay',b),range(32)))
        check('32_copy_replay_exactly_one',sum(r['success'] for r in copies)==1,
              accepted=sum(r['success'] for r in copies))
        final=ctx.store.integrity();head=ctx.witness.fetch(ctx.stream)
        check('final_remote_head_and_local_integrity',final['integrity']=='ok'
              and final['pending_witness_publications']==0 and head.get('digest')==final['head'],state=final,head=head)
    finally:ctx.close()
    verification=verify(args.out);atomic(args.out/'independent_verification.json',verification)
    report=dict(profile=args.profile,checks=checks,passed=all(c['passed'] for c in checks) and verification['passed'],
                scope='actual second-host process restart and SSH transport outage; injected ACK loss separately labeled',
                not_tested=['malicious witness','separate administration','direct routed-WAN protocol without SSH','GPU recovery'])
    atomic(args.out/'faults.json',report);print(json.dumps(report),flush=True)
    return 0 if report['passed'] else 1


def preflight(args,secret):
    ctx=RemoteContext(secret,args.out,'post_quantum')
    try:
        rows=[ctx.request(i,'preflight_not_performance_sample') for i in range(3)]
        assert all(r['success'] for r in rows)
        head=ctx.witness.fetch(ctx.stream);state=ctx.store.integrity()
        assert head.get('digest')==state['head']
    finally:ctx.close()
    report=verify(args.out);atomic(args.out/'independent_verification.json',report)
    print(json.dumps(report));return 0


def soak(args,secret):
    ctx=RemoteContext(secret,args.out,'post_quantum');start=time.monotonic();events=[];rows=[]
    try:
        for i in range(720):
            target=start+i*5
            time.sleep(max(0,target-time.monotonic()))
            late=max(0,time.monotonic()-target)
            row=ctx.request(10000+i,'scheduled_remote_1h_soak')
            rows.append(row)
            if not row['success']:
                try:
                    ctx.control.connect();ctx.store.flush_witness_outbox()
                    events.append(dict(index=i,recovery_attempt=True,utc=dt.datetime.now(dt.timezone.utc).isoformat()))
                except Exception as e:
                    events.append(dict(index=i,recovery_error=type(e).__name__))
            events.append(dict(index=i,scheduled_elapsed_s=i*5,start_lateness_s=late,success=row['success']))
            if (i+1)%180==0:
                ctx.control.stop();ctx.start_witness();ctx.store.witness=ctx.witness
                head=ctx.witness.fetch(ctx.stream)
                events.append(dict(index=i,restart=True,head=head))
            atomic(args.out/'soak_progress.json',dict(completed=len(rows),successes=sum(r['success'] for r in rows),
                   elapsed_s=time.monotonic()-start,last=events[-1]))
        final=ctx.store.integrity();head=ctx.witness.fetch(ctx.stream)
    finally:ctx.close()
    verified=verify(args.out);atomic(args.out/'independent_verification.json',verified)
    result=dict(scheduled_updates=720,attempted_updates=len(rows),successes=sum(r['success'] for r in rows),
                failures=sum(not r['success'] for r in rows),period_s=5,elapsed_s=time.monotonic()-start,
                planned_remote_process_restarts=4,events=events,final_local=final,final_remote=head,
                scope='one-hour scheduled actual cross-host SSH-tunneled witness; not a twelve-hour run',
                passed=all(r['success'] for r in rows) and verified['passed'] and head.get('digest')==final['head'])
    atomic(args.out/'soak.json',result);print(json.dumps({k:v for k,v in result.items() if k!='events'}),flush=True)
    return 0 if result['passed'] else 1


def main():
    a=argparse.ArgumentParser();a.add_argument('task',choices=['cell','faults','preflight','soak'])
    a.add_argument('--out',type=Path,required=True);a.add_argument('--profile',default='post_quantum')
    a.add_argument('--workers',type=int,default=1);a.add_argument('--repetition',type=int,default=0)
    args=a.parse_args();secret=json.loads(sys.stdin.readline())
    try:return {'cell':cell,'faults':faults,'preflight':preflight,'soak':soak}[args.task](args,secret)
    except Exception:
        args.out.mkdir(parents=True,exist_ok=True)
        (args.out/'EXCEPTION.txt').write_text(traceback.format_exc())
        raise


if __name__=='__main__':sys.exit(main())
