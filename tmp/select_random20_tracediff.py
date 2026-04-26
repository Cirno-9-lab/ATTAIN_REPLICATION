#!/usr/bin/env python3
import collections
import datetime
import json
import pathlib
import random

SRC = pathlib.Path("/data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260416_103100/batch-summary.json")
OUT = pathlib.Path("/home/xinweimao/alv_evaluate/myResearch/workspace/tmp/random20_tracediff_batch-summary.current.json")
SEED = 20260416


def main() -> int:
    data = json.loads(SRC.read_text(encoding="utf-8"))
    groups = collections.defaultdict(list)
    for case in data.get("cases", []):
        if case.get("trace_has_difference") and case.get("cve_id"):
            groups[case["cve_id"]].append(case)

    rng = random.Random(SEED)
    cves = list(groups)
    rng.shuffle(cves)
    picked = [rng.choice(groups[cve]) for cve in cves[:20]]

    summary = {k: v for k, v in data.items() if k != "cases"}
    summary.update(
        {
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "source_batch_summary": str(SRC),
            "sampling_seed": SEED,
            "sampling_filter": "trace_has_difference == true, one random case per cve_id",
            "total_cases": len(picked),
            "completed_cases": len(picked),
            "trace_diff_cases": len(picked),
            "cases": picked,
        }
    )
    OUT.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"written {OUT}")
    print(f"selected_case_count {len(picked)}")
    print("selected_case_ids")
    for case in picked:
        print(case["case_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
