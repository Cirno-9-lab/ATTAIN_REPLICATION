import json
from pathlib import Path

log_path = Path("logs/llm_token_usage.jsonl")

if not log_path.exists():
    print("NO_LOG")
    raise SystemExit(0)

count = 0
pt = 0
ct = 0
total = 0

with log_path.open(encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("method") != "excel_refine":
            continue
        count += 1
        pt += rec.get("prompt_tokens") or 0
        ct += rec.get("completion_tokens") or 0
        total += rec.get("total_tokens") or 0

print("excel_refine_calls=", count)
print("excel_refine_prompt_tokens=", pt)
print("excel_refine_completion_tokens=", ct)
print("excel_refine_total_tokens=", total)
