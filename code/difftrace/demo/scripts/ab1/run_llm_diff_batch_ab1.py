#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import random
import sys
from typing import Iterable, List

# Ensure we can import modules from the parent scripts directory and ab1 helpers
THIS_DIR = pathlib.Path(__file__).resolve().parent
PARENT_DIR = THIS_DIR.parent
for path in (THIS_DIR, PARENT_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from llm_hunk_selector_ab1 import LLMAnalysisConfig, run_llm_hunk_selection_sync
from run_version_regression_analysis import DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Batch driver (ab1) for running LLM hunk analysis over an existing seek-patch-false batch "
            "using precomputed analysis_dir and llm-scenario.json for each case. "
            "This ablation writes llm-hunk-analysis_ab1.md alongside the baseline outputs."
        )
    )
    parser.add_argument(
        "--batch-summary",
        required=True,
        help="Path to batch-summary.json for the seek-patch-false-results batch.",
    )
    parser.add_argument(
        "--status-filter",
        default="trace_diff,execution_failure",
        help=(
            "Comma-separated list of case.status values to include. "
            "Default: trace_diff,execution_failure"
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of cases to process (for smoke-testing).",
    )
    parser.add_argument(
        "--llm-model",
        default=DEFAULT_LLM_MODEL,
        help=f"LLM model name for AutoGen. Default: {DEFAULT_LLM_MODEL}",
    )
    parser.add_argument(
        "--llm-base-url",
        default=DEFAULT_LLM_BASE_URL,
        help=f"LLM base URL. Default: {DEFAULT_LLM_BASE_URL}",
    )
    parser.add_argument(
        "--llm-api-key",
        default=None,
        help=(
            "LLM API key. Defaults to CHATANYWHERE_API_KEY (or OPENAI_API_KEY) when not provided."
        ),
    )
    parser.add_argument(
        "--llm-max-rounds",
        type=int,
        default=3,
        help="Maximum LLM tool rounds per case. Default: 3",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=None,
        help=(
            "Optional random seed. When set, the selected cases are shuffled with this seed "
            "before applying --limit, so you can sample a random subset (e.g., 20 cases).",
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Re-run ab1 LLM analysis even if llm-hunk-analysis_ab1.md already exists, and refresh stale outputs."
        ),
    )
    return parser.parse_args()


def iter_selected_cases(summary: dict, status_filter: Iterable[str]) -> Iterable[dict]:
    wanted = {status.strip() for status in status_filter if status.strip()}
    for case in summary.get("cases", []):
        if wanted and case.get("status") not in wanted:
            continue
        yield case


def main() -> int:
    args = parse_args()

    api_key = (
        args.llm_api_key
        or os.environ.get("CHATANYWHERE_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )
    if not api_key:
        raise SystemExit(
            "LLM batch analysis (ab1) requested but neither CHATANYWHERE_API_KEY nor OPENAI_API_KEY is set, "
            "and --llm-api-key was not provided."
        )

    batch_summary_path = pathlib.Path(args.batch_summary).expanduser().resolve()
    summary = json.loads(batch_summary_path.read_text(encoding="utf-8"))

    status_filter: List[str] = args.status_filter.split(",") if args.status_filter else []
    selected_cases = list(iter_selected_cases(summary, status_filter))
    if args.random_seed is not None and selected_cases:
        rng = random.Random(args.random_seed)
        rng.shuffle(selected_cases)
    if args.limit is not None:
        selected_cases = selected_cases[: args.limit]

    print(
        "[ab1] Running LLM hunk analysis for {} / {} cases (statuses: {}).".format(
            len(selected_cases),
            len(summary.get("cases", [])),
            ",".join(sorted({c.get("status") for c in selected_cases})),
        )
    )

    for index, case in enumerate(selected_cases, start=1):
        case_id = case.get("case_id")
        analysis_dir = case.get("analysis_dir")
        if not analysis_dir:
            print("[ab1][{}] Skipping {}: missing analysis_dir".format(index, case_id))
            continue

        analysis_root = pathlib.Path(analysis_dir).expanduser().resolve()
        scenario_path = analysis_root / "llm-scenario.json"
        if not scenario_path.exists():
            print("[ab1][{}] Skipping {}: llm-scenario.json not found under {}".format(index, case_id, analysis_root))
            continue

        output_path = analysis_root / "llm-hunk-analysis_ab1.md"
        error_path = analysis_root / "llm-hunk-analysis_ab1.error.txt"
        if output_path.exists() and not args.force:
            print("[ab1][{}] Skipping {}: llm-hunk-analysis_ab1.md already exists".format(index, case_id))
            continue

        try:
            scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        except Exception as error:
            print("[ab1][{}] Skipping {}: failed to load scenario: {}".format(index, case_id, error))
            continue

        print("[ab1][{}] Running LLM hunk analysis for {} in {}".format(index, case_id, analysis_root))
        try:
            run_llm_hunk_selection_sync(
                analysis_root=analysis_root,
                scenario=scenario,
                output_path=output_path,
                config=LLMAnalysisConfig(
                    model=args.llm_model,
                    base_url=args.llm_base_url,
                    api_key=api_key,
                    max_rounds=args.llm_max_rounds,
                ),
            )
            if error_path.exists():
                error_path.unlink()
        except Exception as error:
            error_path.write_text(
                "LLM hunk analysis (ab1) failed.\n{}: {}\n".format(type(error).__name__, error),
                encoding="utf-8",
            )
            print("[ab1][{}] LLM analysis for {} failed. Details: {}".format(index, case_id, error_path))

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
