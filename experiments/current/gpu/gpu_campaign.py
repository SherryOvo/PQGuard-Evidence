#!/usr/bin/env python3
"""Actual vLLM continuous scheduling plus durable request-to-witness paths.

No CPU fake inference path exists. GPU load is gated by a separate launcher.
All warmups, errors and output token IDs are retained, including discrepancies
between modes. Per-request responses are released only after complete() ACKs.
"""
import argparse
import asyncio
import concurrent.futures
import hashlib
import json
import os
import platform
import random
import sqlite3
import sys
import time
import traceback
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from conventional_store import ConventionalStrongStore
from merkle_store import MerkleStore
from r11_durable_lifecycle import DurableLifecycleStore
from r7_crypto_profiles import build_profile, canonical, sha256
from runtime import WitnessProcess, atomic
from verify_artifacts import verify_case

ROOT = Path(__file__).resolve().parents[1]


def pct(x, q):
    a = sorted(x)
    if not a:
        return None
    where = (len(a) - 1) * q
    i = int(where)
    return a[i] + (a[min(i + 1, len(a) - 1)] - a[i]) * (where - i)


def resource_snapshot():
    r = {}
    for name, path in {"cpu_stat": "/sys/fs/cgroup/cpu/cpu.stat",
                       "memory_usage": "/sys/fs/cgroup/memory/memory.usage_in_bytes",
                       "memory_peak": "/sys/fs/cgroup/memory/memory.max_usage_in_bytes"}.items():
        p = Path(path)
        r[name] = p.read_text().strip() if p.exists() else None
    r["process_cpu_ns"] = time.process_time_ns()
    return r


async def main(args):
    import torch
    import vllm
    from vllm import SamplingParams
    from vllm.engine.arg_utils import AsyncEngineArgs
    from vllm.v1.engine.async_llm import AsyncLLM
    from transformers import AutoTokenizer
    from scheduler_logger import AuditStatLogger
    config = json.loads((ROOT / "config.json").read_text())
    out = ROOT / "runs" / args.run_id / ("seed_" + str(args.seed))
    out.mkdir(parents=True, exist_ok=False)
    assert torch.cuda.is_available(), "GPU is not enabled"
    assert "A800" in torch.cuda.get_device_name(0), "expected A800; do not silently change hardware"
    model = ROOT / "model/Qwen2.5-14B-Instruct"
    ready = json.loads((ROOT / "evidence/MODEL_READY.json").read_text())
    policy = sha256(canonical(ready["files"]))
    tokenizer = AutoTokenizer.from_pretrained(str(model), trust_remote_code=False, local_files_only=True)
    base = tokenizer.encode("Analyze the following research problem and explain the main limitations. " * 300,
                            add_special_tokens=False)
    plans = {}
    (out / "datasets").mkdir()
    for workload, pairs in config["workloads"].items():
        plans[workload] = [dict(tenant=i % 4,
            input_token_ids=base[i % 4:i % 4 + pairs[i % len(pairs)][0]],
            target_output_tokens=pairs[i % len(pairs)][1])
            for i in range(max(config["measured_requests_per_cell"], config["warmup_requests_per_cell"]))]
        atomic(out / "datasets" / (workload + ".json"), plans[workload])
    engine_args = AsyncEngineArgs(model=str(model), tokenizer=str(model), dtype="bfloat16",
        tensor_parallel_size=1, max_model_len=config["max_model_len"],
        max_num_seqs=config["max_num_seqs"], max_num_batched_tokens=config["max_num_batched_tokens"],
        gpu_memory_utilization=config["gpu_memory_utilization"], enforce_eager=True,
        enable_prefix_caching=False, seed=args.seed, disable_log_stats=False,
        trust_remote_code=False)
    engine = AsyncLLM.from_engine_args(engine_args, stat_loggers=[AuditStatLogger])
    atomic(out / "environment.json", dict(torch=torch.__version__, vllm=vllm.__version__,
        python=sys.version, gpu=torch.cuda.get_device_name(0),
        gpu_memory=torch.cuda.get_device_properties(0).total_memory, policy_digest=policy,
        settings=config, seed=args.seed, resource=resource_snapshot()))
    asyncio.get_running_loop().set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=40))
    conditions = [(w, c) for w in config["workloads"] for c in config["concurrency"]]
    modes = config["modes"]
    if args.pilot:
        conditions = [("short", 4)]
    rng = random.Random(args.seed)
    rng.shuffle(conditions)
    schedule = []
    for workload, concurrency in conditions:
        order = list(modes)
        rng.shuffle(order)
        schedule.extend((workload, concurrency, mode) for mode in order)
    atomic(out / "schedule.json", schedule)
    all_results = []
    try:
        for cell_index, (workload, concurrency, mode) in enumerate(schedule):
            case = out / f"{cell_index:03}_{workload}_c{concurrency}_{mode}"
            case.mkdir()
            profile = build_profile("post_quantum", policy)
            sessions = [profile.establish_session(canonical(dict(seed=args.seed, workload=workload,
                        mode=mode, tenant=i))) for i in range(4)]
            atomic(case / "public_material.json", profile.export_public())
            atomic(case / "session_setup.json", [dict(sid=s.sid, setup_ns=s.setup_ns,
                wire_bytes=s.wire_bytes, hybrid=s.hybrid) for s in sessions])
            stream = f"gpu-{args.seed}-{cell_index}"
            witness = store = None
            if mode not in ("plain", "transport"):
                witness = WitnessProcess(case, profile.export_public(), stream)
                cls = {"submitted_full": DurableLifecycleStore,
                       "conventional_full": ConventionalStrongStore,
                       "merkle8": MerkleStore}[mode]
                extra = dict(batch_size=config["batch_size"], max_wait_ms=config["batch_max_wait_ms"]) if mode == "merkle8" else {}
                store = cls(case / "lifecycle.sqlite", profile, stream, witness, **extra)
            raw_file = (case / "requests.jsonl").open("w", buffering=1)
            client_inflight = client_peak = engine_inflight = engine_peak = 0
            request_counter = 0
            measured = []

            async def phase(name, count):
                nonlocal client_inflight, client_peak, engine_inflight, engine_peak, request_counter
                queue = asyncio.Queue()
                for i in range(count):
                    queue.put_nowait(i)
                event = asyncio.Event()
                async def worker():
                    nonlocal client_inflight, client_peak, engine_inflight, engine_peak, request_counter
                    await event.wait()
                    while not queue.empty():
                        i = queue.get_nowait()
                        seq = request_counter
                        request_counter += 1
                        plan = plans[workload][i]
                        tenant = plan["tenant"]
                        session = sessions[tenant]
                        pair = config["workloads"][workload][i % len(config["workloads"][workload])]
                        # Four distinct logical sessions share one scheduler; no tenant isolation claim.
                        ids = plan["input_token_ids"]
                        assert len(ids) == pair[0]
                        prompt = canonical(ids)
                        hp = sha256(prompt)
                        row = dict(phase=name, sequence=seq, sid=session.sid, tenant=tenant,
                            workload=workload, workload_index=i, input_tokens=len(ids), target_output_tokens=pair[1],
                            prompt_hash=hp, mode=mode, response_released=False, success=False)
                        start = time.perf_counter_ns()
                        client_inflight += 1
                        client_peak = max(client_peak, client_inflight)
                        active_engine = False
                        try:
                            if mode != "plain":
                                t = time.perf_counter_ns()
                                key, nonce = profile.record_material(session, "request", seq)
                                aad = profile.associated_data(session, "request", seq)
                                encrypted = AESGCM(key).encrypt(nonce, prompt, aad)
                                assert AESGCM(key).decrypt(nonce, encrypted, aad) == prompt
                                row["request_protection_ns"] = time.perf_counter_ns() - t
                            if store:
                                _, row["admission_ns"] = await asyncio.to_thread(store.admit, session.sid, seq, hp, policy)
                            generation_start = time.perf_counter_ns()
                            row["engine_submit_ns"] = generation_start
                            engine_inflight += 1
                            active_engine = True
                            engine_peak = max(engine_peak, engine_inflight)
                            final = None
                            first_token_ns = None
                            params = SamplingParams(temperature=0, max_tokens=pair[1], ignore_eos=True, seed=args.seed)
                            async with asyncio.timeout(config["request_timeout_seconds"]):
                                async for output in engine.generate({"prompt_token_ids": ids}, params,
                                        request_id=f"{args.seed}-{cell_index}-{seq}"):
                                    final = output
                                    if output.outputs and output.outputs[0].token_ids and first_token_ns is None:
                                        first_token_ns = time.perf_counter_ns()
                            row["engine_finished_ns"] = time.perf_counter_ns()
                            engine_inflight -= 1
                            active_engine = False
                            assert final is not None and final.finished
                            tokens = list(final.outputs[0].token_ids)
                            assert len(tokens) == pair[1]
                            response = canonical(tokens)
                            row.update(output_token_ids=tokens, output_tokens=len(tokens),
                                response_hash=sha256(response), generation_ns=row["engine_finished_ns"] - generation_start,
                                internal_first_token_ns=(first_token_ns - start) if first_token_ns else None)
                            if mode != "plain":
                                t = time.perf_counter_ns()
                                key, nonce = profile.record_material(session, "response", seq)
                                aad = profile.associated_data(session, "response", seq)
                                protected = AESGCM(key).encrypt(nonce, response, aad)
                                assert AESGCM(key).decrypt(nonce, protected, aad) == response
                                row["response_protection_ns"] = time.perf_counter_ns() - t
                            if store:
                                terminal = await asyncio.to_thread(store.complete, session.sid, seq, row["response_hash"])
                                row.update(terminal)
                            row.update(response_released=True, success=True)
                        except Exception as e:
                            row.update(error_type=type(e).__name__, error=str(e)[:500])
                        finally:
                            if active_engine:
                                engine_inflight -= 1
                            client_inflight -= 1
                            row["total_ns"] = time.perf_counter_ns() - start
                            raw_file.write(json.dumps(row, sort_keys=True) + "\n")
                            if name == "measured":
                                measured.append(row)
                tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
                await asyncio.sleep(0)
                begin = time.perf_counter_ns()
                event.set()
                await asyncio.wait_for(asyncio.gather(*tasks), config["cell_timeout_seconds"])
                return time.perf_counter_ns() - begin
            before = resource_snapshot()
            try:
                AuditStatLogger.current_cell = case.name + "_warmup"
                await phase("warmup", 4 if args.pilot else config["warmup_requests_per_cell"])
                client_peak = engine_peak = 0
                AuditStatLogger.current_cell = case.name
                wall = await phase("measured", 8 if args.pilot else config["measured_requests_per_cell"])
                state = store.integrity() if store else None
            finally:
                raw_file.flush()
                os.fsync(raw_file.fileno())
                raw_file.close()
                if store:
                    store.close()
                if witness:
                    witness.close()
            verification = verify_case(case) if store else dict(passed=True, scope="no lifecycle evidence expected in this baseline")
            successes = [r for r in measured if r["success"]]
            latencies = [r["total_ns"] / 1e6 for r in successes]
            summary = dict(mode=mode, workload=workload, concurrency=concurrency,
                seed=args.seed, requests=len(measured), successes=len(successes), failures=len(measured)-len(successes),
                wall_ns=wall, throughput_requests_s=len(successes) / (wall/1e9),
                throughput_generated_tokens_s=sum(r["output_tokens"] for r in successes)/(wall/1e9),
                latency_p50_ms=pct(latencies,.5), latency_p95_ms=pct(latencies,.95), latency_p99_ms=pct(latencies,.99),
                max_client_inflight=client_peak, max_engine_submissions_inflight=engine_peak,
                actual_scheduler=AuditStatLogger.data.get(case.name, {}), state=state,
                independent_verification=verification, resource_before=before, resource_after=resource_snapshot(),
                performance_pass=not any(not r["success"] for r in measured),
                metric_boundary="closed-loop issue to full response release; internal first token is NOT client-visible streaming")
            atomic(case / "COMPLETE.json", summary)
            all_results.append(summary)
            atomic(out / "progress.json", dict(completed=len(all_results), expected=len(schedule), latest=case.name))
            print(json.dumps(dict(cell=case.name, complete=True, failures=summary["failures"], throughput=summary["throughput_requests_s"])), flush=True)
        atomic(out / "DONE.json", dict(finished=True, cells=len(all_results), results=all_results,
            all_performance_pass=all(r["performance_pass"] for r in all_results), pilot=args.pilot))
    finally:
        atomic(out / "scheduler_metrics.json", AuditStatLogger.data)
        engine.shutdown()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--pilot", action="store_true")
    a = p.parse_args()
    asyncio.run(main(a))
