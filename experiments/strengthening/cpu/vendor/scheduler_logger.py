#!/usr/bin/env python3
"""Pinned vLLM V1 scheduler observations, not nominal-client concurrency."""
import time

from vllm.v1.metrics.loggers import StatLoggerBase


class AuditStatLogger(StatLoggerBase):
    current_cell = "engine_initialization"
    data = {}

    def __init__(self, vllm_config, engine_index=0):
        self.engine_index = engine_index

    def record(self, scheduler_stats, iteration_stats, engine_idx=0):
        key = type(self).current_cell
        d = type(self).data.setdefault(key, dict(callbacks=0, max_running=0,
            max_waiting=0, max_kv_cache_usage=0.0, prompt_tokens=0,
            generation_tokens=0, preemptions=0, engine_queue_seconds=[]))
        d["callbacks"] += 1
        if scheduler_stats is not None:
            d["max_running"] = max(d["max_running"], scheduler_stats.num_running_reqs)
            d["max_waiting"] = max(d["max_waiting"], scheduler_stats.num_waiting_reqs)
            d["max_kv_cache_usage"] = max(d["max_kv_cache_usage"], scheduler_stats.kv_cache_usage)
        if iteration_stats is not None:
            d["prompt_tokens"] += iteration_stats.num_prompt_tokens
            d["generation_tokens"] += iteration_stats.num_generation_tokens
            d["preemptions"] += iteration_stats.num_preempted_reqs
            d["engine_queue_seconds"].extend(float(x.queued_time) for x in iteration_stats.finished_requests)

    def log_engine_initialized(self):
        type(self).initialized_monotonic = time.monotonic()

    def log(self):
        pass
