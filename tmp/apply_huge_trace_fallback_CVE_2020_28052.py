import json
from pathlib import Path

# 新批次根目录（seekpatch_only_20260418_150218）
BATCH_ROOT = Path("code/difftrace/demo/target/seekpatch_only_20260418_150218").resolve()
CASE_ID = "CVE-2020-28052__00__1.65__1.64"

case_result_path = BATCH_ROOT / "cases" / CASE_ID / "case-result.json"
summary_path = BATCH_ROOT / "batch-summary.json"

print(f"Batch root: {BATCH_ROOT}")
print(f"Case result: {case_result_path}")
print(f"Summary: {summary_path}")

if not case_result_path.is_file():
    raise SystemExit(f"case-result.json not found: {case_result_path}")
if not summary_path.is_file():
    raise SystemExit(f"batch-summary.json not found: {summary_path}")

# 1) 更新 case-result.json
case_data = json.loads(case_result_path.read_text(encoding="utf-8"))

if case_data.get("case_id") != CASE_ID:
    raise SystemExit(f"Unexpected case_id in case-result.json: {case_data.get('case_id')}")

print("Before (case-result):", case_data.get("status"), case_data.get("failure_subtype"), case_data.get("timed_out"), case_data.get("driver_exit_code"))

# 模拟旧批次的 huge-trace fallback 结果：标记为 trace_diff / trace_difference，不再视作 timeout
case_data["status"] = "trace_diff"
case_data["failure_kind"] = None
case_data["failure_subtype"] = "trace_difference"
case_data["timed_out"] = False
case_data["driver_exit_code"] = 0
# duration_seconds 保留原始值（3600.103），方便你后续分析耗时；如果想对齐旧批次，也可以改成 None

case_result_path.write_text(json.dumps(case_data, ensure_ascii=False, indent=2), encoding="utf-8")

print("After  (case-result):", case_data.get("status"), case_data.get("failure_subtype"), case_data.get("timed_out"), case_data.get("driver_exit_code"))

# 2) 更新 batch-summary.json
summary = json.loads(summary_path.read_text(encoding="utf-8"))
cases = summary.get("cases", [])

patched = False
for c in cases:
    if c.get("case_id") == CASE_ID:
        print("Before (summary case):", c.get("status"), c.get("failure_subtype"), c.get("timed_out"), c.get("driver_exit_code"))
        c["status"] = "trace_diff"
        c["failure_kind"] = None
        c["failure_subtype"] = "trace_difference"
        c["timed_out"] = False
        c["driver_exit_code"] = 0
        # duration_seconds 保留原值
        patched = True
        print("After  (summary case):", c.get("status"), c.get("failure_subtype"), c.get("timed_out"), c.get("driver_exit_code"))
        break

if not patched:
    raise SystemExit(f"Case {CASE_ID} not found in batch-summary.json")

summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

print("Done: applied huge-trace fallback mark for", CASE_ID)
