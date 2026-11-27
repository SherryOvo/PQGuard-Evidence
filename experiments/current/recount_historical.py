"""Recount retained legacy records. Does not use a GPU, network, or secret keys."""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import statistics as st


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path, required=True, help="component_data directory in ESM-2")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    startup = list(csv.DictReader((a.data / "core/startup_runs.csv").open()))
    results = []
    for model in sorted({x["model"] for x in startup}):
        rows = [x for x in startup if x["model"] == model]
        assert len(rows) == 5 and all(x["ok"] == "True" for x in rows)
        vals = [float(x["total_startup_verify_ms"]) / 1000 for x in rows]
        results.append(dict(model=model, runs=5, mean_startup_s=st.mean(vals),
                            sample_sd_s=st.stdev(vals),
                            read_digest_share_pct=100 * sum(float(x["weight_hash_ms"]) for x in rows)
                            / sum(float(x["total_startup_verify_ms"]) for x in rows)))
    cross = []
    for name in ["a800_interleaved_raw.json", "rtx5090_interleaved_raw.json"]:
        d = json.loads((a.data / "advanced_figures" / name).read_text())
        assert len(d["records"]) == 300 and d["blocks"] == 100
        for block in range(1, 101):
            rows = [x for x in d["records"] if x["block"] == block]
            assert {x["mode"] for x in rows} == {"plain", "transport", "full"}
            assert len({x["response_sha256"] for x in rows}) == 1
        for mode in ["plain", "transport", "full"]:
            vals = [x["latency_ms"] for x in d["records"] if x["mode"] == mode]
            assert len(vals) == 100
            cross.append(dict(device=d["platform_name"], mode=mode, records=100,
                              mean_ms=st.mean(vals), median_ms=st.median(vals)))
    records = completions = protected = failures = 0
    for path in (a.data / "proxy_matrix_raw").glob("P*/raw_*.jsonl"):
        for line in path.open():
            x = json.loads(line)
            records += 1
            completions += bool(x["accepted"])
            failures += not x["accepted"]
            if x["accepted"] and x["mode"] in ["pq_transport", "pqguard_full"]:
                assert x["response_verified"]
                assert x["response_sha256"] == x["verified_response_sha256"]
                protected += 1
    assert (records, completions, failures, protected) == (156960, 156836, 124, 78356)
    out = dict(startup=results, cross_platform=cross, proxy_records=records,
               proxy_completions=completions, proxy_failures=failures,
               protected_proxy_explicit_hash_matches=protected,
               plain_tls_completions_without_equivalent_verification_fields=completions-protected,
               three_model_summary_only_timings_not_raw_recounted=True)
    target = a.output / "HISTORICAL_RECOUNT.json"
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(out, indent=2) + "\n")
    temp.replace(target)
    print(json.dumps({k: v for k, v in out.items() if not isinstance(v, list)}))


if __name__ == "__main__":
    main()
