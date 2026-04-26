from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT / "dataset"
DEFAULT_EXCEL_PATH = DATASET_ROOT / "execution_result.xlsx"

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


def load_eval_details(eval_json_path: Path) -> List[dict]:
    with eval_json_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    details = payload.get("details")
    if not isinstance(details, list):
        raise ValueError(f"{eval_json_path} 中缺少合法的 details 列表")
    return details


def aggregate_difftrace_predictions(details: Iterable[dict]) -> Dict[Tuple[str, str], str]:
    grouped_predictions: Dict[Tuple[str, str], List[dict]] = defaultdict(list)

    for item in details:
        cve_id = normalize_cve(item.get("cve_id"))
        version = normalize_text(item.get("target_version"))
        if not cve_id or not version:
            continue
        grouped_predictions[(cve_id, version)].append(item)

    aggregated: Dict[Tuple[str, str], str] = {}
    for key, items in grouped_predictions.items():
        labels = [normalize_prediction(item.get("predicted_label")) for item in items]
        label_set = set(labels)
        if POSITIVE_LABEL in label_set and NEGATIVE_LABEL in label_set:
            resolved = POSITIVE_LABEL
        elif POSITIVE_LABEL in label_set:
            resolved = POSITIVE_LABEL
        elif NEGATIVE_LABEL in label_set:
            resolved = NEGATIVE_LABEL
        else:
            resolved = UNKNOWN_LABEL
        aggregated[key] = resolved

    return aggregated


def ensure_excel_columns(df: pd.DataFrame) -> pd.DataFrame:
    if "LLM_Verdict" not in df.columns:
        df["LLM_Verdict"] = "No_Data"
    if "Aligned_llm" not in df.columns:
        df["Aligned_llm"] = "No_Data"
    return df


def apply_single_cve_predictions_to_excel(
    excel_path: Path,
    aggregated_predictions: Dict[Tuple[str, str], str],
) -> Dict[str, object]:
    df = pd.read_excel(excel_path, engine="openpyxl")
    df = ensure_excel_columns(df)

    gt_col = next(
        (column for column in df.columns if "true affected version" in str(column).lower()),
        "True Affected Version",
    )
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

    df.to_excel(excel_path, index=False, engine="openpyxl")

    return {
        "matched_rows": matched_rows,
        "written_rows": written_rows,
        "unknown_rows": unknown_rows,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser("同步单个 llm_vulnerability_presence_eval.json 到 execution_result.xlsx")
    parser.add_argument("eval_json", help="单个 CVE 的 llm_vulnerability_presence_eval.json 路径")
    parser.add_argument(
        "--excel",
        default=str(DEFAULT_EXCEL_PATH),
        help=f"execution_result.xlsx 路径，默认 {DEFAULT_EXCEL_PATH}",
    )
    args = parser.parse_args()

    eval_path = Path(args.eval_json).expanduser().resolve()
    excel_path = Path(args.excel).expanduser().resolve()

    if not eval_path.is_file():
        raise FileNotFoundError(f"评估 JSON 不存在: {eval_path}")
    if not excel_path.is_file():
        raise FileNotFoundError(f"Excel 文件不存在: {excel_path}")

    details = load_eval_details(eval_path)
    aggregated = aggregate_difftrace_predictions(details)

    stats = apply_single_cve_predictions_to_excel(excel_path=excel_path, aggregated_predictions=aggregated)

    print("同步完成")
    print(f"eval_json: {eval_path}")
    print(f"excel: {excel_path}")
    print("matched_rows =", stats["matched_rows"])
    print("written_rows =", stats["written_rows"])
    print("unknown_rows =", stats["unknown_rows"])
    print("TP =", stats["tp"], "TN =", stats["tn"], "FP =", stats["fp"], "FN =", stats["fn"])


if __name__ == "__main__":
    main()
