import json
from pathlib import Path

log_path = Path("/home/xinweimao/alv_evaluate/myResearch/workspace/logs/llm_token_usage.jsonl")

if not log_path.exists():
    print("NO_LOG")
    raise SystemExit(0)

count = 0
pt = 0
ct = 0
total = 0
by_method = {}

with log_path.open(encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        # 只统计 llm_hunk_selector.py 相关的方法，排除 Excel 精修等其它来源
        method = rec.get("method") or ""
        if method.startswith("excel_refine"):
            continue
        count += 1
        prompt_tokens = rec.get("prompt_tokens") or 0
        completion_tokens = rec.get("completion_tokens") or 0
        total_tokens = rec.get("total_tokens") or (prompt_tokens + completion_tokens)
        pt += prompt_tokens
        ct += completion_tokens
        total += total_tokens
        m = by_method.setdefault(method, {"calls": 0, "pt": 0, "ct": 0, "total": 0})
        m["calls"] += 1
        m["pt"] += prompt_tokens
        m["ct"] += completion_tokens
        m["total"] += total_tokens

print("llm_hunk_selector_calls=", count)
print("llm_hunk_selector_prompt_tokens=", pt)
print("llm_hunk_selector_completion_tokens=", ct)
print("llm_hunk_selector_total_tokens=", total)
print("by_method=")
for method, stats in sorted(by_method.items()):
    print(method, stats)
