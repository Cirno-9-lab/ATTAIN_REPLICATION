#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import shutil
import sys
from typing import Dict, Tuple

# Ensure we can import modules from the parent scripts directory
THIS_DIR = pathlib.Path(__file__).resolve().parent
PARENT_DIR = THIS_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

# Reuse helpers from the baseline Excel pipeline
from run_excel_pipeline_with_difftrace import (  # type: ignore
    REPO_ROOT,
    DATASET_ROOT,
    DEFAULT_EXCEL_PATH,
    aggregate_difftrace_predictions,
    apply_difftrace_predictions_to_excel,
)

# Ensure we can import top-level code modules like refresh/patch_analysis
CODE_ROOT = REPO_ROOT / "code"
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

# Reuse entry loading + label inference from the baseline evaluation script
from evaluate_llm_vulnerability_detection import (  # type: ignore
    load_llm_entries,
    infer_predicted_label,
)


DEFAULT_EVAL_JSON = DATASET_ROOT / "llm_vulnerability_presence_eval_ab1.json"
DEFAULT_INPUT_EXCEL = DEFAULT_EXCEL_PATH
DEFAULT_OUTPUT_EXCEL = DATASET_ROOT / "execution_result_ab1.xlsx"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "使用 ab1 消融实验的 llm_vulnerability_presence_eval_ab1.json 结果，"
            "在不修改原始 execution_result.xlsx 的前提下，生成带有 ab1 预测列的 execution_result_ab1.xlsx。"
        )
    )
    parser.add_argument(
        "--eval-json",
        default=str(DEFAULT_EVAL_JSON),
        help=f"ab1 版本的 llm_vulnerability_presence_eval_ab1.json 路径（默认 {DEFAULT_EVAL_JSON}）",
    )
    parser.add_argument(
        "--input-excel",
        default=str(DEFAULT_INPUT_EXCEL),
        help=f"作为模板的原始 execution_result.xlsx 路径（默认 {DEFAULT_INPUT_EXCEL}）",
    )
    parser.add_argument(
        "--output-excel",
        default=str(DEFAULT_OUTPUT_EXCEL),
        help=f"写入 ab1 结果的 Excel 路径（默认 {DEFAULT_OUTPUT_EXCEL}）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只做聚合与对齐统计，不实际写出 execution_result_ab1.xlsx。",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    eval_json_path = pathlib.Path(args.eval_json).expanduser().resolve()
    input_excel_path = pathlib.Path(args.input_excel).expanduser().resolve()
    output_excel_path = pathlib.Path(args.output_excel).expanduser().resolve()

    if not eval_json_path.is_file():
        raise FileNotFoundError(f"未找到 ab1 评估文件: {eval_json_path}")
    if not input_excel_path.is_file():
        raise FileNotFoundError(f"未找到输入 Excel 模板: {input_excel_path}")

    # ab1 的 eval JSON 只有整体统计信息，不包含 details 列表；
    # 这里先读取 eval_json 获取分析配置，再直接从 llm_hunk_analysis_ab1.json 里加载 entries 并推导 predicted_label。
    eval_payload = json.loads(eval_json_path.read_text(encoding="utf-8"))
    analysis_json_path = pathlib.Path(eval_payload["analysis_json"]).expanduser().resolve()
    score_no_threshold = int(eval_payload["score_no_threshold"])
    score_yes_threshold = int(eval_payload["score_yes_threshold"])

    _, entries = load_llm_entries(analysis_json_path)

    details = []
    for entry in entries:
        predicted_label = infer_predicted_label(
            entry,
            score_no_threshold=score_no_threshold,
            score_yes_threshold=score_yes_threshold,
        )
        details.append(
            {
                "case_id": entry.get("case_id"),
                "cve_id": entry.get("cve_id"),
                "target_version": entry.get("target_version"),
                "predicted_label": predicted_label,
            }
        )

    aggregated_predictions, aggregation_stats = aggregate_difftrace_predictions(details)

    print("=" * 100)
    print("ab1 → Excel 全集评估补充链路评估 (failure-only)")
    print("=" * 100)
    print(f"ab1 评估文件: {eval_json_path}")
    print(f"输入 Excel 模板: {input_excel_path}")
    print(f"输出 Excel (ab1): {output_excel_path}")
    print(f"case 明细数: {len(details)}")
    print(f"聚合后的 (CVE, Version) 数: {aggregation_stats['grouped_case_count']}")
    print(f"原始 predicted_label 计数: {aggregation_stats['raw_prediction_counts']}")
    print(f"版本级聚合后的标签计数: {aggregation_stats['resolved_prediction_counts']}")

    if args.dry_run:
        print("[dry-run] 仅做统计，不写 Excel。")
        return 0

    # 先从原始 execution_result.xlsx 拷贝一份到 output，再在副本上跑完整 Excel 全链路
    output_excel_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(input_excel_path, output_excel_path)

    # 将 ab1 副本绑定到各个下游脚本
    os.environ["EXCEL_FILE"] = str(output_excel_path)

    # 确保 refresh.py 使用 ab1 副本而不是原始 settings.EXCEL_FILE
    try:
        import settings  # type: ignore

        settings.EXCEL_FILE = str(output_excel_path)
    except Exception:
        settings = None  # type: ignore[assignment]

    # 1) refresh.py：重置 LLM_Verdict 列为 No_Data
    import refresh  # type: ignore

    refresh.update_excel_verdict()

    # 2) ab1 difftrace 回填（作为 intro 替代步骤）
    difftrace_stats: Dict[str, object] = apply_difftrace_predictions_to_excel(
        excel_path=output_excel_path,
        aggregated_predictions=aggregated_predictions,
        dry_run=False,
    )

    print("\n--- ab1 difftrace 回填结果（写入 execution_result_ab1.xlsx） ---")
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

    # 3) patch_analysis.py：在 ab1 Excel 上回填 patch-only 判定
    import patch_analysis  # type: ignore

    patch_analysis.main()

    # 4) result_analysis_full_coverage.py：按 full-coverage 逻辑进行上下游扩张并计算全集指标
    import result_analysis_full_coverage  # type: ignore

    result_analysis_full_coverage.main()

    print("\n✅ 已基于 ab1 规则跑完整 Excel 全链路，结果写入 execution_result_ab1.xlsx。")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
