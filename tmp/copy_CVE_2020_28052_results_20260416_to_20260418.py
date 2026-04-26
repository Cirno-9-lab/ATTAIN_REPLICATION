import json
from pathlib import Path

OLD_ROOT = Path("/data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260416_103100")
NEW_ROOT = Path("/data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260418_150218")
CASE_ID = "CVE-2020-28052__00__1.65__1.64"

old_case_result = OLD_ROOT / "cases" / CASE_ID / "case-result.json"
new_case_result = NEW_ROOT / "cases" / CASE_ID / "case-result.json"
old_summary_path = OLD_ROOT / "batch-summary.json"
new_summary_path = NEW_ROOT / "batch-summary.json"

print(f"OLD_ROOT={OLD_ROOT}")
print(f"NEW_ROOT={NEW_ROOT}")

if not old_case_result.is_file():
    raise SystemExit(f"old case-result not found: {old_case_result}")
if not new_case_result.is_file():
    raise SystemExit(f"new case-result not found: {new_case_result}")
if not old_summary_path.is_file():
    raise SystemExit(f"old batch-summary.json not found: {old_summary_path}")
if not new_summary_path.is_file():
    raise SystemExit(f"new batch-summary.json not found: {new_summary_path}")

old_case_payload = json.loads(old_case_result.read_text(encoding="utf-8"))
new_case_payload = json.loads(new_case_result.read_text(encoding="utf-8"))

if old_case_payload.get("case_id") != CASE_ID:
    raise SystemExit(f"unexpected case_id in old case-result: {old_case_payload.get('case_id')}")
if new_case_payload.get("case_id") != CASE_ID:
    raise SystemExit(f"unexpected case_id in new case-result: {new_case_payload.get('case_id')}")

print("before (new case-result):", new_case_payload.get("status"), new_case_payload.get("failure_subtype"), new_case_payload.get("timed_out"), new_case_payload.get("driver_exit_code"))

# 直接用旧批次的结果覆盖新批次的 case-result
merged_case = dict(old_case_payload)
# 标一下来源，方便以后排查
merged_case.setdefault("copied_from_batch", str(OLD_ROOT))

new_case_result.write_text(json.dumps(merged_case, ensure_ascii=False, indent=2), encoding="utf-8")

print("after  (new case-result):", merged_case.get("status"), merged_case.get("failure_subtype"), merged_case.get("timed_out"), merged_case.get("driver_exit_code"))

# 同步 batch-summary.json 中对应条目
old_summary = json.loads(old_summary_path.read_text(encoding="utf-8"))
new_summary = json.loads(new_summary_path.read_text(encoding="utf-8"))

old_cases = old_summary.get("cases", [])
new_cases = new_summary.get("cases", [])

old_entry = next((c for c in old_cases if c.get("case_id") == CASE_ID), None)
if old_entry is None:
    raise SystemExit(f"case {CASE_ID} not found in old batch-summary.json")

patched = False
for c in new_cases:
    if c.get("case_id") == CASE_ID:
        print("before (new summary case):", c.get("status"), c.get("failure_subtype"), c.get("timed_out"), c.get("driver_exit_code"))
        # 用旧批次的条目覆盖新批次对应条目
        c.clear()
        c.update(old_entry)
        # 同样加一个来源标记
        c.setdefault("copied_from_batch", str(OLD_ROOT))
        print("after  (new summary case):", c.get("status"), c.get("failure_subtype"), c.get("timed_out"), c.get("driver_exit_code"))
        patched = True
        break

if not patched:
    raise SystemExit(f"case {CASE_ID} not found in new batch-summary.json")

new_summary_path.write_text(json.dumps(new_summary, ensure_ascii=False, indent=2), encoding="utf-8")

print("Done: copied results for", CASE_ID)
