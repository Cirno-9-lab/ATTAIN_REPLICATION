import json
from pathlib import Path

log_path = Path("/home/xinweimao/alv_evaluate/myResearch/workspace/logs/llm_token_usage.jsonl")
bs_path = Path("/home/xinweimao/alv_evaluate/myResearch/workspace/code/difftrace/demo/target/seekpatch_only_20260418_150218/batch-summary.json")

if not log_path.exists():
    print("NO_LOG")
    raise SystemExit(0)

methods = {}
case_ids = set()

with log_path.open(encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        m = rec.get("method") or ""
        methods[m] = methods.get(m, 0) + 1
        cid = rec.get("case_id") or ""
        if cid:
            case_ids.add(cid)

print("methods_counts=", methods)
print("unique_case_ids_in_log=", len(case_ids))

if bs_path.exists():
    payload = json.loads(bs_path.read_text(encoding="utf-8"))
    total_cases = len(payload.get("cases", []))
    print("batch_summary_total_cases=", total_cases)
else:
    print("NO_BATCH_SUMMARY")
