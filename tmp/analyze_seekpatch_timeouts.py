import json
from collections import Counter
from pathlib import Path

batch_path = Path("code/difftrace/demo/target/seekpatch_only_20260418_150218/batch-summary.json").resolve()
print(f"Analyzing {batch_path}\n")

data = json.loads(batch_path.read_text(encoding="utf-8"))
cases = data.get("cases", [])

timeouts = [
    c for c in cases
    if c.get("timed_out")
    or str(c.get("status")) == "timeout"
    or int(c.get("driver_exit_code") or 0) == 124
]

print(f"total_cases = {len(cases)}")
print(f"timeout_cases = {len(timeouts)}\n")

by_cve = Counter(c.get("cve_id") for c in timeouts)
print("Timeout count by CVE (top 20):")
for cve, n in by_cve.most_common(20):
    print(f"  {cve}: {n}")

print("\nSample timeouts (up to 10):")
for c in timeouts[:10]:
    print(
        f"- {c.get('case_id')} | status={c.get('status')} subtype={c.get('failure_subtype')} "
        f"driver_exit={c.get('driver_exit_code')} timed_out={c.get('timed_out')} "
        f"duration={c.get('duration_seconds')}s"
    )

subtypes = Counter((c.get("failure_subtype") or "<none>") for c in timeouts)
print("\nTimeout failure_subtype distribution:")
for name, n in subtypes.most_common():
    print(f"  {name}: {n}")
