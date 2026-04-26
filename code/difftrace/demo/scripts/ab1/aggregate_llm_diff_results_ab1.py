#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import sys
from datetime import datetime
import csv
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Ensure we can import modules from the parent scripts directory
THIS_DIR = pathlib.Path(__file__).resolve().parent
PARENT_DIR = THIS_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

# Reuse the existing aggregate implementation
from aggregate_llm_diff_results import (  # type: ignore
    DIRECT_DIFF_PROMPT_VERSION,
    HUNK_JUDGMENT_PROMPT_VERSION,
    LLMAnalysisConfig,
    SECTION_NAMES,
    build_case_payload,
    build_entry,
    build_invalid_trace_entry,
    classify_evidence_kind,
    has_effective_trace_difference,
    iter_selected_cases,
    load_cached_hunk_judgments,
    load_cached_llm_judgment,
    load_version_diff_context,
    match_signal_patterns,
    normalize_diff_path,
    normalize_hunk_judgment,
    normalize_llm_judgment,
    resolve_llm_api_key,
    shorten_text,
    trace_invalid_reasons_from_case,
    truncate_multiline_text,
    unique_preserve_order,
)

# Constants copied and adjusted from the baseline script
# ab1 脚本路径为 REPO_ROOT/code/difftrace/demo/scripts/ab1，因此向上 5 级回到 REPO_ROOT
REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
DEFAULT_OUTPUT_JSON = REPO_ROOT / "dataset" / "llm_hunk_analysis_ab1.json"
DEFAULT_OUTPUT_CSV = REPO_ROOT / "dataset" / "llm_hunk_analysis_ab1.csv"
DEFAULT_LLM_MODEL = "deepseek-v3"
DEFAULT_LLM_BASE_URL = "https://api.chatanywhere.tech/v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate per-case llm-hunk-analysis_ab1.md outputs into a JSON/CSV table "
            "for downstream analysis and plotting (ab1 failure-only pipeline)."
        )
    )
    parser.add_argument(
        "--batch-summary",
        required=True,
        help="Path to the batch-summary.json that provides case metadata and analysis_dir.",
    )
    parser.add_argument(
        "--status-filter",
        default="trace_diff,execution_failure",
        help="Comma-separated case.status values to include. Default: trace_diff,execution_failure",
    )
    parser.add_argument(
        "--output-json",
        default=str(DEFAULT_OUTPUT_JSON),
        help=f"Path to output JSON summary. Default: {DEFAULT_OUTPUT_JSON}",
    )
    parser.add_argument(
        "--output-csv",
        default=str(DEFAULT_OUTPUT_CSV),
        help=f"Path to output CSV summary. Default: {DEFAULT_OUTPUT_CSV}",
    )
    parser.add_argument(
        "--require-final-response",
        action="store_true",
        help="Only aggregate cases whose llm-hunk-analysis_ab1.md contains a parsed Final response block.",
    )
    parser.add_argument(
        "--judgment-mode",
        choices=["rule", "llm", "hybrid"],
        default="hybrid",
        help=(
            "How to derive the final vulnerability judgment. "
            "rule = heuristic scoring only; llm = deepseek-v3 only; "
            "hybrid = prefer cached/generated LLM judgment and fall back to rule. Default: hybrid"
        ),
    )
    parser.add_argument(
        "--llm-model",
        default=DEFAULT_LLM_MODEL,
        help=f"LLM model name for the final judgment stage. Default: {DEFAULT_LLM_MODEL}",
    )
    parser.add_argument(
        "--llm-base-url",
        default=DEFAULT_LLM_BASE_URL,
        help=f"LLM base URL for the final judgment stage. Default: {DEFAULT_LLM_BASE_URL}",
    )
    parser.add_argument(
        "--llm-api-key",
        default=None,
        help="Optional API key for final judgment. Defaults to CHATANYWHERE_API_KEY or OPENAI_API_KEY.",
    )
    parser.add_argument(
        "--refresh-llm-judgment",
        action="store_true",
        help="Regenerate analysis_dir/llm-vulnerability-judgment.json even if it already exists.",
    )
    return parser.parse_args()


def _read_text_if_exists(path: pathlib.Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    args = parse_args()

    batch_summary_path = pathlib.Path(args.batch_summary).expanduser().resolve()
    summary = json.loads(batch_summary_path.read_text(encoding="utf-8"))

    status_filter: List[str] = args.status_filter.split(",") if args.status_filter else []
    selected_cases = list(iter_selected_cases(summary, status_filter))

    llm_api_key = resolve_llm_api_key(args)

    entries: List[dict] = []
    missing_final_response = 0

    for index, case in enumerate(selected_cases, start=1):
        case_id = case.get("case_id")
        analysis_dir = case.get("analysis_dir")
        if not analysis_dir:
            print(f"[ab1][{index}] Skipping {case_id}: missing analysis_dir")
            continue

        analysis_root = pathlib.Path(analysis_dir).expanduser().resolve()
        scenario_path = analysis_root / "llm-scenario.json"
        if not scenario_path.exists():
            print(f"[ab1][{index}] Skipping {case_id}: llm-scenario.json not found under {analysis_root}")
            continue

        markdown_path = analysis_root / "llm-hunk-analysis_ab1.md"
        if not markdown_path.exists():
            print(f"[ab1][{index}] Skipping {case_id}: llm-hunk-analysis_ab1.md not found under {analysis_root}")
            continue

        try:
            scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        except Exception as error:
            print(f"[ab1][{index}] Skipping {case_id}: failed to load scenario: {error}")
            continue

        markdown_text = _read_text_if_exists(markdown_path)
        if not markdown_text.strip():
            print(f"[ab1][{index}] Skipping {case_id}: empty llm-hunk-analysis_ab1.md")
            continue

        entry = build_entry(
            case=case,
            scenario=scenario,
            analysis_root=analysis_root,
            markdown_text=markdown_text,
            args=args,
            llm_api_key=llm_api_key,
        )
        if entry is None:
            missing_final_response += 1
            if args.require_final_response:
                print(f"[ab1][{index}] Skipping {case_id}: no Final response parsed")
                continue

        if entry is not None:
            entries.append(entry)

    output_payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "description": "Aggregated LLM hunk analysis entries for ab1 failure-only pipeline.",
        "entries": entries,
    }

    output_json_path = pathlib.Path(args.output_json).expanduser().resolve()
    output_json_path.write_text(json.dumps(output_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    output_csv_path = pathlib.Path(args.output_csv).expanduser().resolve()
    with output_csv_path.open("w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        header = [
            "case_id",
            "cve_id",
            "artifact",
            "baseline_version",
            "target_version",
            "status",
            "failure_kind",
            "failure_subtype",
            "scenario_type",
            "vulnerability_presence_score",
            "final_failure_reason",
            "vulnerability_presence_verdict",
            "judgment_confidence",
        ]
        writer.writerow(header)
        for entry in entries:
            writer.writerow([
                entry.get("case_id"),
                entry.get("cve_id"),
                entry.get("artifact"),
                entry.get("baseline_version"),
                entry.get("target_version"),
                entry.get("status"),
                entry.get("failure_kind"),
                entry.get("failure_subtype"),
                entry.get("scenario_type"),
                entry.get("vulnerability_presence_score"),
                entry.get("final_failure_reason"),
                entry.get("vulnerability_presence_verdict"),
                entry.get("judgment_confidence"),
            ])

    print(
        f"[ab1] Aggregated {len(entries)} entries. Missing Final response in {missing_final_response} cases "
        f"(require_final_response={args.require_final_response})."
    )

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
