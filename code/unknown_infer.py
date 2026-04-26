import sys
from collections import Counter

import pandas as pd

"""
unknown_infer.py（直接回填 Excel 版）：

不再输出 `unknown_only_results.json`，也不再依赖 `unknown_analysis.py`。
而是直接基于 Excel 中的 PoC 执行结果，对 unknown 边界版本回填 `LLM_Verdict`：

- 如果边界模式是漏洞引入（introduction）：
  - PoC 为 APPEARS      -> `affected_intro`
  - PoC 非 APPEARS      -> `not affected_intro`
- 否则视为补丁边界（patch）：
  - PoC 为 APPEARS      -> `affected_patch`
  - PoC 非 APPEARS      -> `not affected_patch`

说明：
- 仍然只处理当前 `LLM_Verdict == "No_Data"` 的边界行，避免覆盖前面 difftrace / patch_analysis 已写入的结果。
- 如果同一行同时命中 intro 和 patch 两种模式，则按“intro 优先”处理。
"""

try:
    import settings

    EXCEL_FILE = settings.EXCEL_FILE
except ImportError:
    print("❌ 错误：无法加载 settings.py，请检查文件路径。")
    sys.exit(1)


NO_DATA = "No_Data"
INTRO_MODE = "introduction"
PATCH_MODE = "patch"
INTRO_POSITIVE = "affected_intro"
INTRO_NEGATIVE = "not affected_intro"
PATCH_POSITIVE = "affected_patch"
PATCH_NEGATIVE = "not affected_patch"


def find_column(df: pd.DataFrame, target_name: str, fallback: str = "") -> str:
    target = target_name.lower().strip()
    for column in df.columns:
        if str(column).lower().strip() == target:
            return column
    if fallback:
        return fallback
    raise KeyError(f"Excel 中缺少必要列: {target_name}")


def find_column_contains(df: pd.DataFrame, keyword: str, fallback: str = "") -> str:
    keyword = keyword.lower().strip()
    for column in df.columns:
        if keyword in str(column).lower():
            return column
    if fallback:
        return fallback
    raise KeyError(f"Excel 中缺少包含关键字 {keyword!r} 的列")


def normalize_exec(value: object) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip().upper()


def is_appears(value: object) -> bool:
    return normalize_exec(value) == "APPEARS"


def normalize_text(value: object) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip()


def get_truth_state(value: object) -> str:
    normalized = normalize_text(value).lower()
    if normalized == "affected":
        return "affected"
    if normalized == "not affected":
        return "not affected"
    return ""


def get_pred_state(verdict: str) -> str:
    verdict = normalize_text(verdict).lower()
    if "affected" in verdict and not verdict.startswith("not "):
        return "affected"
    if verdict.startswith("not affected"):
        return "not affected"
    return ""


def build_verdict(mode: str, exec_result: object) -> str:
    positive = is_appears(exec_result)
    if mode == INTRO_MODE:
        return INTRO_POSITIVE if positive else INTRO_NEGATIVE
    return PATCH_POSITIVE if positive else PATCH_NEGATIVE


def choose_mode(existing_mode: str, new_mode: str) -> str:
    if existing_mode == INTRO_MODE or new_mode == INTRO_MODE:
        return INTRO_MODE
    return PATCH_MODE


def alignment_label(truth_state: str, pred_state: str) -> str:
    if not truth_state or not pred_state:
        return "No_Data"
    if truth_state == pred_state:
        return "T"
    if truth_state == "affected" and pred_state == "not affected":
        return "FN"
    if truth_state == "not affected" and pred_state == "affected":
        return "FP"
    return "No_Data"


def run_default_unknown_rule() -> None:
    print("=" * 72)
    print("🚀 Unknown Boundary 回填系统 (Direct Excel Write)")
    print("=" * 72)

    try:
        df = pd.read_excel(EXCEL_FILE, engine="openpyxl")
    except Exception as e:
        print(f"❌ Excel 读取失败: {e}")
        return

    try:
        cve_col = find_column(df, "cve_id", "CVE_ID")
        version_col = find_column(df, "version", "Version")
        exec_col = find_column_contains(df, "execution", "Execution Result")
        gt_col = find_column_contains(df, "true affected version", "True Affected Version")
    except KeyError as e:
        print(f"❌ {e}")
        return

    llm_col = find_column(df, "llm_verdict", "LLM_Verdict")
    aligned_col = find_column(df, "aligned_llm", "Aligned_llm")

    if llm_col not in df.columns:
        df[llm_col] = NO_DATA
    if aligned_col not in df.columns:
        df[aligned_col] = NO_DATA

    planned_updates = {}
    stats = Counter()

    grouped = df.groupby(cve_col, sort=False)

    for cve_id, group in grouped:
        indices = list(group.index)
        for i in range(1, len(indices)):
            prev_idx = indices[i - 1]
            curr_idx = indices[i]

            prev_exec = df.at[prev_idx, exec_col]
            curr_exec = df.at[curr_idx, exec_col]
            prev_is_appears = is_appears(prev_exec)
            curr_is_appears = is_appears(curr_exec)

            if prev_is_appears == curr_is_appears:
                continue

            target_idx = None
            mode = ""

            if prev_is_appears and not curr_is_appears:
                if normalize_text(df.at[curr_idx, llm_col]) == NO_DATA:
                    target_idx = curr_idx
                    mode = PATCH_MODE
            elif (not prev_is_appears) and curr_is_appears:
                if normalize_text(df.at[prev_idx, llm_col]) == NO_DATA:
                    target_idx = prev_idx
                    mode = INTRO_MODE

            if target_idx is None:
                continue

            verdict = build_verdict(mode, df.at[target_idx, exec_col])
            stats["total_boundary_hits"] += 1

            existing_plan = planned_updates.get(target_idx)
            if existing_plan is not None:
                chosen_mode = choose_mode(existing_plan["mode"], mode)
                if chosen_mode != existing_plan["mode"]:
                    planned_updates[target_idx] = {
                        "mode": chosen_mode,
                        "verdict": build_verdict(chosen_mode, df.at[target_idx, exec_col]),
                        "cve_id": normalize_text(cve_id),
                        "version": normalize_text(df.at[target_idx, version_col]),
                    }
                stats["multi_mode_rows"] += 1
                continue

            planned_updates[target_idx] = {
                "mode": mode,
                "verdict": verdict,
                "cve_id": normalize_text(cve_id),
                "version": normalize_text(df.at[target_idx, version_col]),
            }

    eval_stats = Counter()

    for row_idx, info in planned_updates.items():
        verdict = info["verdict"]
        df.at[row_idx, llm_col] = verdict
        stats[f"written_{info['mode']}"] += 1
        stats[f"written_{verdict}"] += 1

        truth_state = get_truth_state(df.at[row_idx, gt_col])
        pred_state = get_pred_state(verdict)
        aligned = alignment_label(truth_state, pred_state)
        df.at[row_idx, aligned_col] = aligned

        if aligned == "T":
            if pred_state == "affected":
                eval_stats["tp"] += 1
            elif pred_state == "not affected":
                eval_stats["tn"] += 1
        elif aligned == "FP":
            eval_stats["fp"] += 1
        elif aligned == "FN":
            eval_stats["fn"] += 1

    try:
        df.to_excel(EXCEL_FILE, index=False, engine="openpyxl")
    except Exception as e:
        print(f"❌ 写回 Excel 失败: {e}")
        return

    total_eval = eval_stats["tp"] + eval_stats["tn"] + eval_stats["fp"] + eval_stats["fn"]
    accuracy = (eval_stats["tp"] + eval_stats["tn"]) / total_eval if total_eval else 0.0

    print("\n" + "=" * 72)
    print("📊 Unknown 默认规则直写结果")
    print("=" * 72)
    print(f"Excel 文件: {EXCEL_FILE}")
    print(f"命中边界次数: {stats['total_boundary_hits']}")
    print(f"实际写回行数: {len(planned_updates)}")
    print(f"其中 intro 写回: {stats['written_introduction']}")
    print(f"其中 patch 写回: {stats['written_patch']}")
    print(f"同一行同时命中两种模式: {stats['multi_mode_rows']} (按 intro 优先)")
    print("-" * 72)
    print(
        "标签分布: "
        f"affected_intro={stats['written_affected_intro']}, "
        f"not affected_intro={stats['written_not affected_intro']}, "
        f"affected_patch={stats['written_affected_patch']}, "
        f"not affected_patch={stats['written_not affected_patch']}"
    )
    print("-" * 72)
    print(
        f"局部对齐统计: TP={eval_stats['tp']} TN={eval_stats['tn']} "
        f"FP={eval_stats['fp']} FN={eval_stats['fn']} | Accuracy={accuracy:.2%}"
    )
    print("✅ 已直接回填到 Excel。")
    print("=" * 72)


if __name__ == "__main__":
    run_default_unknown_rule()
