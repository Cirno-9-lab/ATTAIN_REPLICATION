#!/usr/bin/env python3

import argparse
import json
import pathlib
from collections import Counter

from trace_workflow_lib import extract_identifiers, write_json


NOT_RUN = "not_run"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backfill missing llm-scenario.json files from existing batch artifacts.")
    parser.add_argument("--batch-summary", required=True, help="Path to batch-summary.json")
    parser.add_argument("--force", action="store_true", help="Overwrite existing llm-scenario.json files")
    return parser.parse_args()


def load_optional_json(path: pathlib.Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def read_optional_text(path: pathlib.Path) -> str:
    if not path or not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def relative_to_analysis(analysis_root: pathlib.Path, path: pathlib.Path):
    if path is None or not path.exists():
        return None
    try:
        return str(path.relative_to(analysis_root))
    except ValueError:
        return None


def parse_command_from_log(log_path: pathlib.Path):
    if not log_path or not log_path.exists():
        return None
    for line in read_optional_text(log_path).splitlines():
        if line.startswith("Command: "):
            return line[len("Command: "):].strip()
    return None


def find_case_root(analysis_root: pathlib.Path):
    for candidate in [analysis_root, *analysis_root.parents]:
        if (candidate / "case-result.json").exists() or (candidate / "run-version-analysis.log").exists():
            return candidate
    return None


def enrich_case(case: dict, analysis_root: pathlib.Path) -> dict:
    case_root = find_case_root(analysis_root)
    if case_root is None:
        return dict(case)
    case_result = load_optional_json(case_root / "case-result.json") or {}
    merged = dict(case_result)
    merged.update({key: value for key, value in case.items() if value is not None})
    if merged.get("driver_output_path") is None and (case_root / "run-version-analysis.log").exists():
        merged["driver_output_path"] = str(case_root / "run-version-analysis.log")
    return merged


def pick_failure_excerpt_path(analysis_root: pathlib.Path, case: dict) -> pathlib.Path | None:
    candidates = []
    if case.get("failure_excerpt_path"):
        candidates.append(pathlib.Path(case["failure_excerpt_path"]))
    candidates.extend(
        [
            analysis_root / "target-failure-excerpt.txt",
            analysis_root / "baseline-observation-excerpt.txt",
            analysis_root / "target-observation-excerpt.txt",
        ]
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def base_scenario_fields(case: dict, analysis_root: pathlib.Path) -> dict:
    scenario = {
        "cve_id": case.get("cve_id"),
        "baseline_version": case.get("baseline_version"),
        "target_version": case.get("target_version"),
        "artifact": case.get("artifact"),
        "description": case.get("description"),
        "compare_url": case.get("compare_url"),
        "artifact_diff_root": "version-diff",
    }
    dependency_tree_diff = analysis_root / "dependency-tree.diff"
    baseline_trace = analysis_root / "baseline-trace.log"
    target_trace = analysis_root / "target-trace.log"
    if dependency_tree_diff.exists():
        scenario["dependency_tree_diff"] = str(dependency_tree_diff.relative_to(analysis_root))
    if baseline_trace.exists():
        scenario["baseline_trace"] = str(baseline_trace.relative_to(analysis_root))
    if target_trace.exists():
        scenario["target_trace"] = str(target_trace.relative_to(analysis_root))
    return scenario


def build_trace_or_no_diff_scenario(
    case: dict,
    analysis_root: pathlib.Path,
    trace_summary_text: str,
    has_difference: bool,
    trace_summary: dict | None = None,
) -> dict:
    exec_obs = load_optional_json(analysis_root / "execution-observations.json") or {}
    baseline = exec_obs.get("baseline") or {}
    target = exec_obs.get("target") or {}

    trace_summary = trace_summary or {}
    scenario = base_scenario_fields(case, analysis_root)
    scenario.update(
        {
            "scenario_type": "trace_diff" if has_difference else "no_diff",
            "baseline_command": baseline.get("command"),
            "target_command": target.get("command"),
            "baseline_execution_observation": case.get("baseline_execution_observation") or baseline.get("observation") or "unknown",
            "target_execution_observation": case.get("target_execution_observation") or target.get("observation") or "unknown",
            "trace_summary_file": str((analysis_root / "trace-diff-summary.txt").relative_to(analysis_root)),
            "trace_keywords": ", ".join(extract_identifiers(trace_summary_text)),
            "trace_has_effective_difference": trace_summary.get("has_effective_difference", has_difference),
            "trace_evidence_valid": trace_summary.get("trace_evidence_valid"),
            "trace_invalid_reasons": trace_summary.get("trace_invalid_reasons") or [],
            "first_divergence_is_noise": trace_summary.get("first_divergence_is_noise", False),
        }
    )
    return scenario


def build_failure_scenario(case: dict, analysis_root: pathlib.Path) -> dict:
    exec_obs = load_optional_json(analysis_root / "execution-observations.json") or {}
    baseline = exec_obs.get("baseline") or {}
    target = exec_obs.get("target") or {}
    log_path = pathlib.Path(case["driver_output_path"]) if case.get("driver_output_path") else None
    parsed_command = parse_command_from_log(log_path) if log_path else None
    excerpt_path = pick_failure_excerpt_path(analysis_root, case)
    excerpt_text = read_optional_text(excerpt_path) if excerpt_path else ""
    fallback_text = excerpt_text or str(case.get("dataset_cause") or "") or read_optional_text(log_path)[:1200]

    baseline_obs = case.get("baseline_execution_observation") or baseline.get("observation") or "unknown"
    target_obs = case.get("target_execution_observation") or target.get("observation")

    baseline_command = baseline.get("command") or parsed_command
    target_command = target.get("command")
    failing_command = target_command or baseline_command or parsed_command

    scenario = base_scenario_fields(case, analysis_root)
    scenario.update(
        {
            "scenario_type": case.get("failure_kind") or case.get("status") or "execution_failure",
            "baseline_command": baseline_command,
            "target_command": target_command,
            "failing_command": failing_command,
            "baseline_execution_observation": baseline_obs,
            "target_execution_observation": target_obs or NOT_RUN,
            "failure_excerpt_keywords": ", ".join(extract_identifiers(fallback_text)),
        }
    )
    excerpt_rel = relative_to_analysis(analysis_root, excerpt_path) if excerpt_path else None
    if excerpt_rel and excerpt_text:
        scenario["failure_excerpt_file"] = excerpt_rel
    return scenario


def build_scenario(case: dict) -> dict | None:
    analysis_dir = case.get("analysis_dir")
    if not analysis_dir:
        return None
    analysis_root = pathlib.Path(analysis_dir).expanduser().resolve()
    if not analysis_root.exists():
        return None

    enriched_case = enrich_case(case, analysis_root)
    trace_summary_path = analysis_root / "trace-diff-summary.json"
    trace_summary_txt_path = analysis_root / "trace-diff-summary.txt"
    trace_summary = load_optional_json(trace_summary_path) or {}
    trace_summary_text = read_optional_text(trace_summary_txt_path)
    has_effective_difference = bool(
        trace_summary.get("has_effective_difference", trace_summary.get("has_difference"))
    )
    if has_effective_difference or enriched_case.get("status") == "trace_diff":
        if not trace_summary_text and trace_summary:
            trace_summary_text = json.dumps(trace_summary, ensure_ascii=False, indent=2)
        return build_trace_or_no_diff_scenario(
            enriched_case,
            analysis_root,
            trace_summary_text,
            has_difference=True,
            trace_summary=trace_summary,
        )

    # 对 execution_failure 等失败场景，即便 trace-diff 有原始差异，也不要再包装成 trace/no_diff 场景，避免把无效 trace 当作主证据
    if enriched_case.get("status") == "no_diff":
        if not trace_summary_text and trace_summary:
            trace_summary_text = json.dumps(trace_summary, ensure_ascii=False, indent=2)
        elif not trace_summary_text:
            trace_summary_text = "No effective trace difference detected between baseline and target executions."
        return build_trace_or_no_diff_scenario(
            enriched_case,
            analysis_root,
            trace_summary_text,
            has_difference=False,
            trace_summary=trace_summary,
        )

    return build_failure_scenario(enriched_case, analysis_root)


def main() -> int:
    args = parse_args()
    summary_path = pathlib.Path(args.batch_summary).expanduser().resolve()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    written = 0
    skipped_existing = 0
    failed = 0
    status_counts = Counter()

    for case in summary.get("cases", []):
        analysis_dir = case.get("analysis_dir")
        if not analysis_dir:
            failed += 1
            continue
        analysis_root = pathlib.Path(analysis_dir).expanduser().resolve()
        scenario_path = analysis_root / "llm-scenario.json"
        if scenario_path.exists() and not args.force:
            skipped_existing += 1
            continue

        scenario = build_scenario(case)
        if not scenario:
            failed += 1
            continue

        scenario_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(scenario_path, scenario)
        written += 1
        status_counts[scenario.get("scenario_type") or "unknown"] += 1

    print(
        json.dumps(
            {
                "batch_summary": str(summary_path),
                "written": written,
                "skipped_existing": skipped_existing,
                "failed": failed,
                "scenario_type_counts": dict(status_counts),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
