#!/usr/bin/env python3

"""ab2 driver: aggregate llm-hunk-analysis with optional random diff evidence.

本脚本在不修改原生 `aggregate_llm_diff_results.py` 的前提下，实现模块二的 evidence 消融：
- evidence_mode=baseline：沿用原生脚本的 Selected Hunks 证据；
- evidence_mode=random：忽略 Selected Hunks，在 `analysis/version-diff/` 下随机抽样若干 `*.diff` 作为证据。

输出默认写入 dataset/llm_hunk_analysis_ab2.{json,csv}，字段格式与原生脚本保持兼容。
"""

import argparse
import csv
import json
import pathlib
import random
import sys
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

THIS_DIR = pathlib.Path(__file__).resolve().parent
PARENT_DIR = THIS_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

import aggregate_llm_diff_results as baseline


REPO_ROOT = baseline.REPO_ROOT
DEFAULT_OUTPUT_JSON = REPO_ROOT / "dataset" / "llm_hunk_analysis_ab2.json"
DEFAULT_OUTPUT_CSV = REPO_ROOT / "dataset" / "llm_hunk_analysis_ab2.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "[ab2] Aggregate per-case llm-hunk-analysis.md outputs into a JSON/CSV table "
            "with optional random diff evidence for ablation."
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
        help="Only aggregate cases whose llm-hunk-analysis.md contains a parsed Final response block.",
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
        default=baseline.DEFAULT_LLM_MODEL,
        help=f"LLM model name for the final judgment stage. Default: {baseline.DEFAULT_LLM_MODEL}",
    )
    parser.add_argument(
        "--llm-base-url",
        default=baseline.DEFAULT_LLM_BASE_URL,
        help=f"LLM base URL for the final judgment stage. Default: {baseline.DEFAULT_LLM_BASE_URL}",
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
    parser.add_argument(
        "--evidence-mode",
        choices=["baseline", "random"],
        default="random",
        help=(
            "Evidence construction mode for module-2 judgments. "
            "baseline = use module-1 Selected Hunks; "
            "random = ignore Selected Hunks and randomly sample diff files from version-diff/. "
            "Default: random (ablation)."
        ),
    )
    parser.add_argument(
        "--random-sample-size",
        type=int,
        default=3,
        help=(
            "Number of diff files to sample per case when --evidence-mode=random. "
            "Default: 3 (as described in AGENT_PAPER ab2-A)."
        ),
    )
    return parser.parse_args()


def build_random_selected_hunks(
    analysis_root: pathlib.Path,
    sample_size: int = 3,
) -> List[Dict[str, str]]:
    """从 analysis/version-diff 下随机抽样若干类级 diff 作为 evidence。

    抽样单位为 version-diff/api-diffs/ 和 version-diff/diffs/ 下的 *.diff 文件，
    返回格式与 baseline.parse_selected_hunks 相同，仅填充 path 和 details。
    """

    diff_root = analysis_root / "version-diff"
    candidates: List[str] = []

    for subdir in ("api-diffs", "diffs"):
        root = diff_root / subdir
        if not root.exists() or not root.is_dir():
            continue
        for path in root.rglob("*.diff"):
            rel = path.relative_to(analysis_root).as_posix()
            candidates.append(rel)

    candidates = sorted({c for c in candidates})
    if not candidates:
        return []

    k = max(1, min(sample_size, len(candidates)))
    rng = random.Random()
    sampled = rng.sample(candidates, k=k)

    selected: List[Dict[str, str]] = []
    for rel in sampled:
        selected.append(
            {
                "path": rel,
                "details": f"Randomly sampled diff file (ab2 evidence_mode=random): {rel}",
                "inline_diff_excerpt": "",
            }
        )
    return selected


def build_entry_ab2(
    case: dict,
    scenario: dict,
    analysis_root: pathlib.Path,
    markdown_text: str,
    args: argparse.Namespace,
    llm_api_key: Optional[str],
) -> Optional[dict]:
    """复制 baseline.build_entry 的主体逻辑，但允许切换 evidence-mode。"""

    final_response = baseline.extract_final_response(markdown_text)
    sections = (
        baseline.parse_sections(final_response)
        if final_response
        else {name: "" for name in baseline.SECTION_NAMES}
    )

    if args.evidence_mode == "baseline":
        selected_hunks = baseline.parse_selected_hunks(sections.get("Selected Hunks", ""))
    else:
        selected_hunks = build_random_selected_hunks(
            analysis_root=analysis_root,
            sample_size=max(1, int(args.random_sample_size or 1)),
        )
        # evidence_mode=random 且完全没有 diff 时，跳过该 case
        if not selected_hunks:
            return None

    selected_hunk_payloads = baseline.build_hunk_payloads(analysis_root, selected_hunks)
    judgment_payloads = baseline.build_judgment_payloads(
        analysis_root,
        case,
        scenario,
        selected_hunk_payloads,
    )
    hunk_judgments, hunk_judgment_path, hunk_judgment_error_path = baseline.maybe_load_or_generate_hunk_judgments(
        case=case,
        scenario=scenario,
        hunk_payloads=judgment_payloads,
        analysis_root=analysis_root,
        args=args,
        llm_api_key=llm_api_key,
    )
    rule_judgment = baseline.infer_final_judgment(
        case,
        scenario,
        sections,
        selected_hunks,
        judgment_payloads,
        hunk_judgments,
    )
    llm_judgment, llm_judgment_path, llm_judgment_error_path = baseline.maybe_load_or_generate_llm_judgment(
        case=case,
        scenario=scenario,
        hunk_payloads=judgment_payloads,
        analysis_root=analysis_root,
        args=args,
        llm_api_key=llm_api_key,
    )
    primary_judgment, judgment_source = baseline.choose_primary_judgment(
        rule_judgment=rule_judgment,
        llm_judgment=llm_judgment,
        judgment_mode=args.judgment_mode,
        hunk_judgments=hunk_judgments,
        judgment_payloads=judgment_payloads,
    )

    return {
        "case_id": case.get("case_id"),
        "cve_id": case.get("cve_id"),
        "pair_index": case.get("pair_index"),
        "artifact": case.get("artifact"),
        "description": case.get("description") or scenario.get("description"),
        "baseline_version": case.get("baseline_version"),
        "target_version": case.get("target_version"),
        "status": case.get("status"),
        "failure_kind": case.get("failure_kind"),
        "failure_subtype": case.get("failure_subtype"),
        "baseline_execution_observation": case.get("baseline_execution_observation"),
        "target_execution_observation": case.get("target_execution_observation"),
        "compare_url": case.get("compare_url"),
        "analysis_dir": str(analysis_root),
        "llm_output_path": str(analysis_root / "llm-hunk-analysis.md"),
        "llm_hunk_judgment_path": str(hunk_judgment_path) if hunk_judgment_path else None,
        "llm_hunk_judgment_error_path": str(hunk_judgment_error_path) if hunk_judgment_error_path else None,
        "llm_judgment_path": str(llm_judgment_path) if llm_judgment_path else None,
        "llm_judgment_error_path": str(llm_judgment_error_path) if llm_judgment_error_path else None,
        "scenario_type": scenario.get("scenario_type"),
        "trace_keywords": scenario.get("trace_keywords"),
        "trace_has_difference": case.get("trace_has_difference"),
        "trace_has_effective_difference": case.get("trace_has_effective_difference"),
        "trace_evidence_valid": case.get("trace_evidence_valid"),
        "trace_invalid_reasons": case.get("trace_invalid_reasons"),
        "failure_excerpt_keywords": scenario.get("failure_excerpt_keywords"),
        "baseline_command": scenario.get("baseline_command"),
        "target_command": scenario.get("target_command"),
        "has_final_response": final_response is not None,
        "diagnosis": sections.get("Diagnosis", ""),
        "diagnosis_short": baseline.shorten_text(sections.get("Diagnosis", "")),
        "selected_hunks_text": sections.get("Selected Hunks", ""),
        "selected_hunk_count": len(selected_hunks),
        "selected_hunk_paths": [item["path"] for item in selected_hunks],
        "selected_hunks": selected_hunks,
        "selected_hunk_payloads": selected_hunk_payloads,
        "judgment_payload_count": len(judgment_payloads),
        "judgment_payloads": judgment_payloads,
        "hunk_judgment_count": len(hunk_judgments or []),
        "hunk_judgments": hunk_judgments,
        "supporting_evidence": sections.get("Supporting Evidence", ""),
        "open_questions": sections.get("Open Questions", ""),
        "final_response_markdown": final_response,
        "judgment_source": judgment_source,
        "rule_judgment": rule_judgment,
        "llm_judgment": llm_judgment,
        "evidence_mode": args.evidence_mode,
        **primary_judgment,
    }


def main() -> int:
    args = parse_args()

    # 在 evidence_mode=random（ab2-A）下，如果用户没有显式指定 refresh-llm-judgment，
    # 默认强制刷新 per-hunk 和 case-level 的 LLM 判定，避免复用 baseline 证据下缓存的 judgment。
    if getattr(args, "evidence_mode", "baseline") == "random" and not getattr(
        args, "refresh_llm_judgment", False
    ):
        args.refresh_llm_judgment = True

    batch_summary_path = pathlib.Path(args.batch_summary).expanduser().resolve()
    output_json_path = pathlib.Path(args.output_json).expanduser().resolve()
    output_csv_path = pathlib.Path(args.output_csv).expanduser().resolve()
    llm_api_key = baseline.resolve_llm_api_key(args)

    summary = json.loads(batch_summary_path.read_text(encoding="utf-8"))
    status_filter = args.status_filter.split(",") if args.status_filter else []
    selected_cases = list(baseline.iter_selected_cases(summary, status_filter))

    entries: List[dict] = []
    missing_scenario = 0
    missing_markdown = 0
    missing_final_response = 0

    for case in selected_cases:
        analysis_dir = case.get("analysis_dir")
        if not analysis_dir:
            continue
        analysis_root = pathlib.Path(analysis_dir).expanduser().resolve()
        scenario_path = analysis_root / "llm-scenario.json"
        markdown_path = analysis_root / "llm-hunk-analysis.md"

        if not scenario_path.exists():
            missing_scenario += 1
            continue

        failure_subtype = str(case.get("failure_subtype") or "").strip().lower()
        seek_patch = case.get("seek_patch")
        if isinstance(seek_patch, bool):
            seek_patch_false = seek_patch is False
        elif seek_patch is None:
            seek_patch_false = False
        else:
            seek_patch_false = str(seek_patch).strip().lower() == "false"

        if not markdown_path.exists():
            # 复用 baseline 的 invalid_trace_difference 特例逻辑
            if failure_subtype == "invalid_trace_difference" and seek_patch_false:
                scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
                entry = baseline.build_invalid_trace_entry(
                    case=case,
                    scenario=scenario,
                    analysis_root=analysis_root,
                )
                entry["evidence_mode"] = args.evidence_mode
                entries.append(entry)
                continue
            missing_markdown += 1
            continue

        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        markdown_text = markdown_path.read_text(encoding="utf-8", errors="replace")
        entry = build_entry_ab2(
            case=case,
            scenario=scenario,
            analysis_root=analysis_root,
            markdown_text=markdown_text,
            args=args,
            llm_api_key=llm_api_key,
        )
        if entry is None:
            # evidence_mode=random 且没有可用 diff 的 case
            continue
        if args.require_final_response and not entry["has_final_response"]:
            missing_final_response += 1
            continue
        if not entry["has_final_response"]:
            missing_final_response += 1
        entries.append(entry)

    final_reason_counts = Counter(entry["final_failure_reason"] for entry in entries)
    vulnerability_presence_counts = Counter(entry["vulnerability_presence_verdict"] for entry in entries)
    confidence_counts = Counter(entry["judgment_confidence"] for entry in entries)
    judgment_source_counts = Counter(entry["judgment_source"] for entry in entries)
    llm_judgment_available_count = sum(1 for entry in entries if entry.get("llm_judgment"))

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "batch_summary_path": str(batch_summary_path),
        "score_no_threshold": baseline.VULNERABILITY_PRESENCE_SCORE_NO_THRESHOLD,
        "score_yes_threshold": baseline.VULNERABILITY_PRESENCE_SCORE_YES_THRESHOLD,
        "status_filter": [status.strip() for status in status_filter if status.strip()],
        "total_cases": len(summary.get("cases", [])),
        "selected_cases": len(selected_cases),
        "aggregated_entries": len(entries),
        "missing_scenario_count": missing_scenario,
        "missing_markdown_count": missing_markdown,
        "missing_final_response_count": missing_final_response,
        "judgment_mode": args.judgment_mode,
        "evidence_mode": args.evidence_mode,
        "judgment_source_counts": dict(judgment_source_counts),
        "llm_judgment_available_count": llm_judgment_available_count,
        "final_failure_reason_counts": dict(final_reason_counts),
        "vulnerability_presence_counts": dict(vulnerability_presence_counts),
        "judgment_confidence_counts": dict(confidence_counts),
        "entries": entries,
    }

    output_json_path.parent.mkdir(parents=True, exist_ok=True)
    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    output_json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    csv_rows = []
    for entry in entries:
        csv_rows.append(
            {
                "case_id": entry["case_id"],
                "cve_id": entry["cve_id"],
                "pair_index": entry["pair_index"],
                "artifact": entry["artifact"],
                "description": entry.get("description") or "",
                "baseline_version": entry["baseline_version"],
                "target_version": entry["target_version"],
                "status": entry["status"],
                "failure_kind": entry["failure_kind"],
                "failure_subtype": entry["failure_subtype"],
                "scenario_type": entry["scenario_type"],
                "selected_hunk_count": entry["selected_hunk_count"],
                "selected_hunk_paths": " ; ".join(entry["selected_hunk_paths"]),
                "hunk_judgment_count": entry.get("hunk_judgment_count") or 0,
                "hunk_judgment_labels": " ; ".join(
                    "{}:{}".format(item.get("hunk_path", ""), item.get("judgment", ""))
                    for item in (entry.get("hunk_judgments") or [])
                ),
                "diagnosis_short": entry["diagnosis_short"],
                "diagnosis": entry["diagnosis"],
                "vulnerability_presence_score": entry["vulnerability_presence_score"],
                "final_failure_reason": entry["final_failure_reason"],
                "vulnerability_presence_verdict": entry["vulnerability_presence_verdict"],
                "judgment_confidence": entry["judgment_confidence"],
                "judgment_source": entry["judgment_source"],
                "evidence_mode": entry.get("evidence_mode", args.evidence_mode),
                "fix_evidence_strength": entry.get("fix_evidence_strength", ""),
                "exploit_breakage_evidence_strength": entry.get("exploit_breakage_evidence_strength", ""),
                "llm_key_evidence": " ; ".join(entry.get("llm_key_evidence", [])),
                "judgment_rationale_short": entry["judgment_rationale_short"],
                "judgment_rationale": entry["judgment_rationale"],
                "trace_keywords": entry.get("trace_keywords") or "",
                "failure_excerpt_keywords": entry.get("failure_excerpt_keywords") or "",
                "analysis_dir": entry["analysis_dir"],
                "llm_output_path": entry["llm_output_path"],
                "llm_hunk_judgment_path": entry.get("llm_hunk_judgment_path") or "",
                "llm_judgment_path": entry.get("llm_judgment_path") or "",
            }
        )

    fieldnames = [
        "case_id",
        "cve_id",
        "pair_index",
        "artifact",
        "description",
        "baseline_version",
        "target_version",
        "status",
        "failure_kind",
        "failure_subtype",
        "scenario_type",
        "selected_hunk_count",
        "selected_hunk_paths",
        "hunk_judgment_count",
        "hunk_judgment_labels",
        "diagnosis_short",
        "diagnosis",
        "vulnerability_presence_score",
        "final_failure_reason",
        "vulnerability_presence_verdict",
        "judgment_confidence",
        "judgment_source",
        "evidence_mode",
        "fix_evidence_strength",
        "exploit_breakage_evidence_strength",
        "llm_key_evidence",
        "judgment_rationale_short",
        "judgment_rationale",
        "trace_keywords",
        "failure_excerpt_keywords",
        "analysis_dir",
        "llm_output_path",
        "llm_hunk_judgment_path",
        "llm_judgment_path",
    ]
    with output_csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    print(
        "[ab2] Wrote {} aggregated entries to {} and {} "
        "(selected_cases={}, missing_scenario={}, missing_markdown={}, missing_final_response={}, "
        "judgment_mode={}, evidence_mode={}, judgment_source_counts={}, final_failure_reason_counts={}, "
        "vulnerability_presence_counts={}).".format(
            len(entries),
            output_json_path,
            output_csv_path,
            len(selected_cases),
            missing_scenario,
            missing_markdown,
            missing_final_response,
            args.judgment_mode,
            args.evidence_mode,
            dict(judgment_source_counts),
            dict(final_reason_counts),
            dict(vulnerability_presence_counts),
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
