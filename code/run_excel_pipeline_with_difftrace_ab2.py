#!/usr/bin/env python3

"""ab2 Excel pipeline: 用 ab2-B 评估结果回填 execution_result_ab2.xlsx，并执行 full-coverage 传递。

- 输入: dataset/llm_vulnerability_presence_eval_ab2_B.json
- Excel: dataset/execution_result_ab2.xlsx
- 步骤:
  1) 清理 / 初始化 LLM_Verdict / Aligned_llm 列;
  2) 按 (CVE_ID, Version) 聚合 ab2-B 的 predicted_label，回填为 not affected_intro / affected_intro；
  3) 调用 result_analysis_full_coverage_ab2.py，对版本链做前向/后向 full-coverage 传递与评估。
"""

import json
import pathlib
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "dataset"
EVAL_JSON_PATH = DATASET_ROOT / "llm_vulnerability_presence_eval_ab2_B.json"
EXCEL_PATH = DATASET_ROOT / "execution_result_ab2.xlsx"

KNOWN_PREDICTIONS = {"affected", "not affected", "unknown"}
POSITIVE_LABEL = "affected"
NEGATIVE_LABEL = "not affected"
UNKNOWN_LABEL = "unknown"
INTRO_POSITIVE_VERDICT = "affected_intro"
INTRO_NEGATIVE_VERDICT = "not affected_intro"


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


def load_eval_details(eval_json_path: pathlib.Path) -> List[dict]:
    payload = json.loads(eval_json_path.read_text(encoding="utf-8"))
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


def apply_predictions_to_execution_result_ab2(
    excel_path: pathlib.Path,
    aggregated_predictions: Dict[Tuple[str, str], str],
) -> Dict[str, object]:
    df = pd.read_excel(excel_path, engine="openpyxl")
    df = ensure_excel_columns(df)

    gt_col = next(
        (column for column in df.columns if "true affected version" in column.lower()),
        "True Affected Version",
    )
    if gt_col not in df.columns:
        raise KeyError("Excel 中缺少 True Affected Version 列，无法对 difftrace 回填结果做对齐统计")

    matched_rows = 0
    written_rows = 0
    unknown_rows = 0
    tp = tn = fp = fn = 0

    # 先清空旧的 LLM_Verdict / Aligned_llm
    df["LLM_Verdict"] = "No_Data"
    df["Aligned_llm"] = "No_Data"

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


def main() -> None:
    eval_path = EVAL_JSON_PATH
    excel_path = EXCEL_PATH

    if not eval_path.is_file():
        raise FileNotFoundError(f"找不到 ab2-B 评估文件: {eval_path}")
    if not excel_path.is_file():
        raise FileNotFoundError(f"找不到 execution_result_ab2.xlsx: {excel_path}")

    details = load_eval_details(eval_path)
    aggregated_predictions, aggregation_stats = aggregate_difftrace_predictions(details)

    print("=" * 100)
    print("DiffTrace ab2-B → execution_result_ab2.xlsx 回填 + full-coverage 流水线")
    print("=" * 100)
    print(f"ab2-B 评估文件: {eval_path}")
    print(f"Excel: {excel_path}")
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

    stats = apply_predictions_to_execution_result_ab2(excel_path, aggregated_predictions)

    print("\n--- ab2-B 回填结果 (execution_result_ab2.xlsx) ---")
    print(f"matched_rows = {stats['matched_rows']}")
    print(f"written_rows = {stats['written_rows']}")
    print(f"unknown_rows = {stats['unknown_rows']}")
    print(
        "TP={tp} TN={tn} FP={fp} FN={fn} | Accuracy={acc:.2%} Precision={prec:.2%} Recall={rec:.2%} F1={f1:.4f}".format(
            tp=stats["tp"],
            tn=stats["tn"],
            fp=stats["fp"],
            fn=stats["fn"],
            acc=stats["accuracy"],
            prec=stats["precision"],
            rec=stats["recall"],
            f1=stats["f1"],
        )
    )

    # 调用 ab2 full-coverage 版本链推理
    from result_analysis_full_coverage_ab2 import main as full_coverage_main

    print("\n>>> 继续执行 ab2 full-coverage 版本链传递与评估 ...")
    full_coverage_main()


if __name__ == "__main__":
    main()
