import json
import random
from pathlib import Path

BASE_BS = Path("code/difftrace/demo/target/seekpatch_only_20260418_150218/batch-summary.json")
OUT_BS = Path("tmp/random23_tracediff_batch-summary.json")

payload = json.loads(BASE_BS.read_text(encoding="utf-8"))
cases = payload.get("cases", [])

filtered = [c for c in cases if c.get("status") in {"trace_diff", "execution_failure"}]

rng = random.Random(42)
rng.shuffle(filtered)

sample = filtered[:23]

out_payload = dict(payload)
out_payload["cases"] = sample

OUT_BS.write_text(json.dumps(out_payload, ensure_ascii=False, indent=2), encoding="utf-8")

print("base_cases=", len(cases))
print("filtered_cases=", len(filtered))
print("sample_cases=", len(sample))
print("sample_case_ids=", [c.get("case_id") for c in sample])
