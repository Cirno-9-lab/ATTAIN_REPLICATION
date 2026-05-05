#!/usr/bin/env python3

import argparse
import json
import pathlib
import subprocess
import sys
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd


REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
CODE_ROOT = REPO_ROOT / "code"
DATASET_ROOT = REPO_ROOT / "dataset"
DEFAULT_EXCEL_PATH = DATASET_ROOT / "execution_result.xlsx"
DEFAULT_REFRESH_SCRIPT = CODE_ROOT / "refresh.py"
DEFAULT_PATCH_ANALYSIS_SCRIPT = CODE_ROOT / "patch_analysis.py"
DEFAULT_UNKNOWN_INFER_SCRIPT = CODE_ROOT / "unknown_infer.py"
DEFAULT_RESULT_ANALYSIS_SCRIPT = CODE_ROOT / "result_analysis.py"
DEFAULT_FULL_COVERAGE_RESULT_ANALYSIS_SCRIPT = CODE_ROOT / "result_analysis_full_coverage.py"
DEFAULT_WORKSPACE_TARGET_ROOT = REPO_ROOT / "code" / "difftrace" / "demo" / "target"
EVAL_FILENAME = "llm_vulnerability_presence_eval.json"

KNOWN_PREDICTIONS = {"affected", "not affected", "unknown"}
POSITIVE_LABEL = "affected"
NEGATIVE_LABEL = "not affected"
UNKNOWN_LABEL = "unknown"
INTRO_POSITIVE_VERDICT = "affected_intro"
INTRO_NEGATIVE_VERDICT = "not affected_intro"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "先执行 refresh.py，再把 difftrace 最终评估结果回填到 execution_result.xlsx，"
            "随后继续执行 patch_analysis.py、unknown_infer.py，并按模式执行 result_analysis.py 或 full-coverage 版本。"
        )
    )
    parser.add_argument(
        "--difftrace-eval-json",
        help="llm_vulnerability_presence_eval.json 路径；若不提供，会在常见 target 目录中自动寻找最新文件。",
    )
    parser.add_argument(
        "--difftrace-batch-root",
        help="某个 difftrace batch 根目录；若提供，会优先在该目录下搜索 llm_vulnerability_presence_eval.json。",
    )
    parser.add_argument(
        "--excel",
        default=str(DEFAULT_EXCEL_PATH),
        help=f"execution_result.xlsx 路径，默认 {DEFAULT_EXCEL_PATH}",
    )
    parser.add_argument(
        "--refresh-script",
        default=str(DEFAULT_REFRESH_SCRIPT),
        help=f"refresh.py 路径，默认 {DEFAULT_REFRESH_SCRIPT}",
    )
    parser.add_argument(
        "--patch-analysis-script",
        default=str(DEFAULT_PATCH_ANALYSIS_SCRIPT),
        help=f"patch_analysis.py 路径，默认 {DEFAULT_PATCH_ANALYSIS_SCRIPT}",
    )
    parser.add_argument(
        "--unknown-infer-script",
        default=str(DEFAULT_UNKNOWN_INFER_SCRIPT),
        help=f"unknown_infer.py 路径，默认 {DEFAULT_UNKNOWN_INFER_SCRIPT}",
    )
    parser.add_argument(
        "--result-analysis-script",
        default=str(DEFAULT_RESULT_ANALYSIS_SCRIPT),
        help=f"默认收尾模式使用的 result_analysis.py 路径，默认 {DEFAULT_RESULT_ANALYSIS_SCRIPT}",
    )
    parser.add_argument(
        "--full-coverage-result-analysis-script",
        default=str(DEFAULT_FULL_COVERAGE_RESULT_ANALYSIS_SCRIPT),
        help=(
            "full-coverage 收尾模式使用的脚本路径，默认 "
            f"{DEFAULT_FULL_COVERAGE_RESULT_ANALYSIS_SCRIPT}"
        ),
    )
    parser.add_argument(
        "--result-analysis-mode",
        choices=("default", "full-coverage"),
        default="default",
        help="收尾阶段采用的 result_analysis 模式：default 为原脚本，full-coverage 为上下游全覆盖传递版。",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="执行子脚本所用的 Python 解释器，默认是当前解释器。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只做输入校验和计划打印，不执行 refresh / patch / unknown / result，也不写 Excel。",
    )
    return parser.parse_args()


def normalize_text(value: object) -> str:
    if value is None:
        return ""
    if pd.isna(value):
        return ""
    return str(value).strip()


def normalize_cve(value: object) -> str:
    return normalize_text(value).upper()


def normalize_prediction(value: object) -> str:
    normalized = normalize_text(value).lower()
    return normalized if normalized in KNOWN_PREDICTIONS else UNKNOWN_LABEL


def truth_to_state(value: object) -> str:
    normalized = normalize_text(value).lower()
    if normalized == POSITIVE_LABEL:
        return POSITIVE_LABEL
    if normalized == NEGATIVE_LABEL:
        return NEGATIVE_LABEL
    return ""


def verdict_label_from_prediction(prediction: str) -> Optional[str]:
    if prediction == POSITIVE_LABEL:
        return INTRO_POSITIVE_VERDICT
    if prediction == NEGATIVE_LABEL:
        return INTRO_NEGATIVE_VERDICT
    return None


def collect_eval_candidates(search_root: pathlib.Path) -> List[pathlib.Path]:
    if not search_root.exists():
        return []
    return [path for path in search_root.rglob(EVAL_FILENAME) if path.is_file()]


def find_latest_eval_json(explicit_eval_json: Optional[str], batch_root: Optional[str]) -> pathlib.Path:
    if explicit_eval_json:
        path = pathlib.Path(explicit_eval_json).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"指定的 difftrace eval 文件不存在: {path}")
        return path

    candidates: List[pathlib.Path] = []
    searched_roots: List[pathlib.Path] = []

    if batch_root:
        batch_path = pathlib.Path(batch_root).expanduser().resolve()
        searched_roots.append(batch_path)
        if batch_path.is_file() and batch_path.name == EVAL_FILENAME:
            return batch_path
        candidates.extend(collect_eval_candidates(batch_path))

    for root in (DEFAULT_EXTERNAL_TARGET_ROOT, DEFAULT_WORKSPACE_TARGET_ROOT):
        resolved_root = root.expanduser().resolve()
        searched_roots.append(resolved_root)
        candidates.extend(collect_eval_candidates(resolved_root))

    dataset_eval = (DATASET_ROOT / EVAL_FILENAME).resolve()
    searched_roots.append(dataset_eval)
    if dataset_eval.is_file():
        candidates.append(dataset_eval)

    deduped = {candidate.resolve(): candidate.resolve() for candidate in candidates}
    if not deduped:
        searched = "\n  - ".join(str(path) for path in searched_roots)
        raise FileNotFoundError(
            "未找到 difftrace 最终评估文件 llm_vulnerability_presence_eval.json。已搜索:\n"
            f"  - {searched}"
        )

    return max(deduped.values(), key=lambda path: path.stat().st_mtime)


def load_eval_details(eval_json_path: pathlib.Path) -> List[dict]:
    with eval_json_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    details = payload.get("details")
    if not isinstance(details, list):
        raise ValueError(f"{eval_json_path} 中缺少合法的 details 列表")
    return details


def aggregate_difftrace_predictions(details: Iterable[dict]) -> Tuple[Dict[Tuple[str, str], str], Dict[str, object]]:
    grouped_predictions: Dict[Tuple[str, str], List[dict]] = defaultdict(list)

    for item in details:
        cve_id = normalize_cve(item.get("cve_id"))
        version = normalize_text(item.get("target_version"))
        if not cve_id or not version:
            continue
        grouped_predictions[(cve_id, version)].append(item)

    aggregated: Dict[Tuple[str, str], str] = {}
    conflicts: List[dict] = []
    raw_counter: Counter = Counter()

    for key, items in grouped_predictions.items():
        labels = [normalize_prediction(item.get("predicted_label")) for item in items]
        for label in labels:
            raw_counter[label] += 1

        label_set = set(labels)
        if POSITIVE_LABEL in label_set and NEGATIVE_LABEL in label_set:
            resolved = POSITIVE_LABEL
            conflicts.append(
                {
                    "cve_id": key[0],
                    "version": key[1],
                    "resolved": resolved,
                    "case_ids": [normalize_text(item.get("case_id")) for item in items],
                    "labels": labels,
                }
            )
        elif POSITIVE_LABEL in label_set:
            resolved = POSITIVE_LABEL
        elif NEGATIVE_LABEL in label_set:
            resolved = NEGATIVE_LABEL
        else:
            resolved = UNKNOWN_LABEL

        aggregated[key] = resolved

    stats = {
        "grouped_case_count": len(grouped_predictions),
        "raw_prediction_counts": dict(raw_counter),
        "resolved_prediction_counts": dict(Counter(aggregated.values())),
        "conflicts": conflicts,
    }
    return aggregated, stats


def ensure_excel_columns(df: pd.DataFrame) -> pd.DataFrame:
    if "LLM_Verdict" not in df.columns:
        df["LLM_Verdict"] = "No_Data"
    if "Aligned_llm" not in df.columns:
        df["Aligned_llm"] = "No_Data"
    return df


def apply_difftrace_predictions_to_excel(
    excel_path: pathlib.Path,
    aggregated_predictions: Dict[Tuple[str, str], str],
    dry_run: bool = False,
) -> Dict[str, object]:
    df = pd.read_excel(excel_path, engine="openpyxl")
    df = ensure_excel_columns(df)

    gt_col = next((column for column in df.columns if "true affected version" in column.lower()), "True Affected Version")
    if gt_col not in df.columns:
        raise KeyError("Excel 中缺少 True Affected Version 列，无法对 difftrace 回填结果做对齐统计")

    matched_rows = 0
    written_rows = 0
    unknown_rows = 0
    tp = tn = fp = fn = 0

    for idx, row in df.iterrows():
        key = (normalize_cve(row.get("CVE_ID")), normalize_text(row.get("Version")))
        if key not in aggregated_predictions:
            continue

        matched_rows += 1
        prediction = aggregated_predictions[key]
        verdict_label = verdict_label_from_prediction(prediction)
        if verdict_label is None:
            unknown_rows += 1
            continue

        written_rows += 1
        df.at[idx, "LLM_Verdict"] = verdict_label

        truth = truth_to_state(row.get(gt_col))
        if truth == prediction:
            df.at[idx, "Aligned_llm"] = "T"
            if truth == POSITIVE_LABEL:
                tp += 1
            elif truth == NEGATIVE_LABEL:
                tn += 1
        elif truth == POSITIVE_LABEL and prediction == NEGATIVE_LABEL:
            df.at[idx, "Aligned_llm"] = "FN"
            fn += 1
        elif truth == NEGATIVE_LABEL and prediction == POSITIVE_LABEL:
            df.at[idx, "Aligned_llm"] = "FP"
            fp += 1
        else:
            df.at[idx, "Aligned_llm"] = "No_Data"

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / written_rows if written_rows else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    if not dry_run:
        df.to_excel(excel_path, index=False, engine="openpyxl")

    return {
        "matched_rows": matched_rows,
        "written_rows": written_rows,
        "unknown_rows": unknown_rows,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def run_python_script(python_bin: str, script_path: pathlib.Path, dry_run: bool = False) -> None:
    command = [python_bin, str(script_path)]
    print(f"\n>>> {' '.join(command)}")
    if dry_run:
        print("[dry-run] 跳过实际执行")
        return
    subprocess.run(command, check=True)


def resolve_result_analysis_script(args: argparse.Namespace) -> pathlib.Path:
    if args.result_analysis_mode == "full-coverage":
        return pathlib.Path(args.full_coverage_result_analysis_script).expanduser().resolve()
    return pathlib.Path(args.result_analysis_script).expanduser().resolve()


def main() -> None:
    args = parse_args()

    excel_path = pathlib.Path(args.excel).expanduser().resolve()
    refresh_script = pathlib.Path(args.refresh_script).expanduser().resolve()
    patch_analysis_script = pathlib.Path(args.patch_analysis_script).expanduser().resolve()
    unknown_infer_script = pathlib.Path(args.unknown_infer_script).expanduser().resolve()
    result_analysis_script = resolve_result_analysis_script(args)

    for required_path in (
        excel_path,
        refresh_script,
        patch_analysis_script,
        unknown_infer_script,
        result_analysis_script,
    ):
        if not required_path.exists():
            raise FileNotFoundError(f"所需文件不存在: {required_path}")

    eval_json_path = find_latest_eval_json(args.difftrace_eval_json, args.difftrace_batch_root)
    details = load_eval_details(eval_json_path)
    aggregated_predictions, aggregation_stats = aggregate_difftrace_predictions(details)

    print("=" * 100)
    print("DiffTrace → Excel 全链路执行器")
    print("=" * 100)
    print(f"difftrace 评估文件: {eval_json_path}")
    print(f"execution_result.xlsx: {excel_path}")
    print(f"result_analysis_mode: {args.result_analysis_mode}")
    print(f"result_analysis_script: {result_analysis_script}")
    print(f"case 明细数: {len(details)}")
    print(f"聚合后的 (CVE, Version) 数: {aggregation_stats['grouped_case_count']}")
    print(f"原始 predicted_label 计数: {aggregation_stats['raw_prediction_counts']}")
    print(f"版本级聚合后的标签计数: {aggregation_stats['resolved_prediction_counts']}")
    if aggregation_stats["conflicts"]:
        print(f"⚠️ 发现 {len(aggregation_stats['conflicts'])} 个版本存在冲突标签，已按保守策略解析为 affected。")
        for item in aggregation_stats["conflicts"][:10]:
            print(
                f"  - {item['cve_id']} {item['version']} | labels={item['labels']} | cases={item['case_ids']}"
            )

    run_python_script(args.python, refresh_script, dry_run=args.dry_run)

    difftrace_stats = apply_difftrace_predictions_to_excel(
        excel_path=excel_path,
        aggregated_predictions=aggregated_predictions,
        dry_run=args.dry_run,
    )
    print("\n--- difftrace 回填结果（作为 intro 替代步骤） ---")
    print(f"matched_rows = {difftrace_stats['matched_rows']}")
    print(f"written_rows = {difftrace_stats['written_rows']}")
    print(f"unknown_rows = {difftrace_stats['unknown_rows']}")
    print(
        "TP={tp} TN={tn} FP={fp} FN={fn} | Accuracy={acc:.2%} Precision={prec:.2%} Recall={rec:.2%} F1={f1:.4f}".format(
            tp=difftrace_stats["tp"],
            tn=difftrace_stats["tn"],
            fp=difftrace_stats["fp"],
            fn=difftrace_stats["fn"],
            acc=difftrace_stats["accuracy"],
            prec=difftrace_stats["precision"],
            rec=difftrace_stats["recall"],
            f1=difftrace_stats["f1"],
        )
    )
    if args.dry_run:
        print("[dry-run] 已跳过 Excel 写入。")

    run_python_script(args.python, patch_analysis_script, dry_run=args.dry_run)
    # 根据当前策略，暂时取消 unknown_infer.py 这一步，由 result_analysis_full_coverage.py 统一完成上下游扩张
    run_python_script(args.python, result_analysis_script, dry_run=args.dry_run)

    print("\n✅ 流水线结束。")
    if args.dry_run:
        print("当前是 dry-run，仅完成输入校验、difftrace 聚合统计和执行计划打印。")


if __name__ == "__main__":
    main()
