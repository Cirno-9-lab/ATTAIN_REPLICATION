#!/usr/bin/env python3

"""Backfill CVE descriptions into RQ3 batch-summary and per-case case-result files.

- Reads descriptions from dataset/list/cve_list_rq3.json (per CVE).
- Updates /data-1/.../batch-results/batch-summary.json cases[] entries.
- Updates each case's case-result.json (and nested test_results[].description if present).

Usage (from workspace root):

    python code/difftrace/demo/scripts/backfill_rq3_descriptions.py \
      --cve-list dataset/list/cve_list_rq3.json \
      --batch-summary /data-1/xinweimao/code/difftrace/demo/target/batch-results/batch-summary.json

After running this, you can re-run backfill_llm_scenarios.py --force to regenerate
llm-scenario.json files that include the description field, and then re-run the
LLM analysis pipeline.
"""

import argparse
import json
import pathlib
from typing import Dict, Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backfill CVE descriptions for RQ3 cases.")
    parser.add_argument(
        "--cve-list",
        required=True,
        help="Path to dataset/list/cve_list_rq3.json",
    )
    parser.add_argument(
        "--batch-summary",
        required=True,
        help="Path to batch-results/batch-summary.json",
    )
    return parser.parse_args()


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: pathlib.Path, payload: Any) -> None:
    # Keep it stable and human-readable
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False), encoding="utf-8")


def build_cve_description_map(cve_list_payload: Dict[str, Any]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for cve_id, entry in cve_list_payload.items():
        if not isinstance(entry, dict):
            continue
        desc = str(entry.get("description") or "").strip()
        if not desc:
            continue
        mapping[cve_id] = desc
    return mapping


def backfill_case_result(case_result_path: pathlib.Path, description: str) -> bool:
    if not case_result_path.exists():
        return False
    try:
        payload = load_json(case_result_path)
    except Exception:
        return False

    changed = False

    # Top-level description
    if isinstance(payload, dict):
        if str(payload.get("description") or "").strip() != description:
            payload["description"] = description
            changed = True

        # Nested test_results (if present)
        test_results = payload.get("test_results")
        if isinstance(test_results, list):
            for item in test_results:
                if not isinstance(item, dict):
                    continue
                if str(item.get("description") or "").strip() != description:
                    item["description"] = description
                    changed = True

    if changed:
        save_json(case_result_path, payload)
    return changed


def main() -> int:
    args = parse_args()

    cve_list_path = pathlib.Path(args.cve_list).expanduser().resolve()
    batch_summary_path = pathlib.Path(args.batch_summary).expanduser().resolve()

    cve_list_payload = load_json(cve_list_path)
    cve_desc_map = build_cve_description_map(cve_list_payload)

    summary = load_json(batch_summary_path)
    cases = summary.get("cases") or []

    updated_case_results = 0
    missing_cve_ids = set()

    for case in cases:
        if not isinstance(case, dict):
            continue
        cve_id = str(case.get("cve_id") or "").strip()
        if not cve_id:
            continue
        desc = cve_desc_map.get(cve_id)
        if not desc:
            missing_cve_ids.add(cve_id)
            continue

        # Update description in batch-summary case entry
        if str(case.get("description") or "").strip() != desc:
            case["description"] = desc

        # Update description in the corresponding case-result.json
        result_path_str = case.get("result_path")
        if not result_path_str:
            continue
        case_result_path = pathlib.Path(result_path_str).expanduser()
        if backfill_case_result(case_result_path, desc):
            updated_case_results += 1

    save_json(batch_summary_path, summary)

    print(
        json.dumps(
            {
                "cve_list": str(cve_list_path),
                "batch_summary": str(batch_summary_path),
                "known_cve_count": len(cve_desc_map),
                "updated_case_results": updated_case_results,
                "missing_cve_ids": sorted(missing_cve_ids),
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
