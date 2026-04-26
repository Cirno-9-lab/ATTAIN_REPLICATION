#!/usr/bin/env python3
import argparse
import json
import pathlib
import sys

SCRIPTS_DIR = pathlib.Path('/home/xinweimao/alv_evaluate/myResearch/workspace/code/difftrace/demo/scripts')
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from llm_hunk_selector import LLMAnalysisConfig, run_llm_hunk_selection_sync  # noqa: E402
from run_version_regression_analysis import DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run LLM hunk analysis for exactly one existing analysis_dir.')
    parser.add_argument('--analysis-root', required=True)
    parser.add_argument('--llm-model', default=DEFAULT_LLM_MODEL)
    parser.add_argument('--llm-base-url', default=DEFAULT_LLM_BASE_URL)
    parser.add_argument('--llm-api-key', required=True)
    parser.add_argument('--llm-max-rounds', type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    analysis_root = pathlib.Path(args.analysis_root).expanduser().resolve()
    scenario_path = analysis_root / 'llm-scenario.json'
    output_path = analysis_root / 'llm-hunk-analysis.md'

    if not scenario_path.exists():
        raise FileNotFoundError(f'llm-scenario.json not found under {analysis_root}')

    scenario = json.loads(scenario_path.read_text(encoding='utf-8'))
    run_llm_hunk_selection_sync(
        analysis_root=analysis_root,
        scenario=scenario,
        output_path=output_path,
        config=LLMAnalysisConfig(
            model=args.llm_model,
            base_url=args.llm_base_url,
            api_key=args.llm_api_key,
            max_rounds=args.llm_max_rounds,
        ),
    )
    print(f'[single-case] completed {analysis_root}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
