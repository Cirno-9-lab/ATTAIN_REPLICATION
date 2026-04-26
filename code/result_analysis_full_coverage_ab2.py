import os

import pandas as pd

# --- 路径配置（ab2 版本，使用 execution_result_ab2.xlsx） ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result_ab2.xlsx")


FORWARD_PROPAGATION_LABELS = {"not affected_patch", "affected_patch"}
BACKWARD_PROPAGATION_LABELS = {"not affected_intro", "affected_intro"}


def get_state(val):
    """判定一个单元格内容属于阳性还是阴性。"""
    s = str(val).strip().lower()
    if "affected" in s and not s.startswith("not"):
        return "POS"
    return "NEG"


def main():
    if not os.path.exists(EXCEL_PATH):
        print(f"❌ 找不到文件: {EXCEL_PATH}")
        return

    df = pd.read_excel(EXCEL_PATH)

    # 这里显式要求 Library、PoC 列存在，并且把 (CVE_ID, Library, Execution Result bucket, PoC) 视为最小区域
    required_cols = ["CVE_ID", "Library", "PoC", "LLM_Verdict", "Execution Result", "True Affected Version"]
    for col in required_cols:
        if col not in df.columns:
            print(f"❌ Excel 中缺少必要列: {col}")
            return

    def region_key(idx: int):
        """按 (CVE_ID, Library, Execution bucket, PoC) 划分区域。

        Execution bucket 只区分 APPEARS / 非 APPEARS 两种情况，
        不同区域之间禁止任何标签扩张。
        """

        cve = str(df.at[idx, "CVE_ID"]).strip()
        lib = str(df.at[idx, "Library"]).strip()
        poc = str(df.at[idx, "PoC"]).strip()
        exec_res = str(df.at[idx, "Execution Result"]).strip().upper()
        bucket = "APPEARS" if exec_res == "APPEARS" else "OTHER"
        return cve, lib, bucket, poc

    def same_region(i: int, j: int) -> bool:
        return region_key(i) == region_key(j)

    n = len(df)

    # 0. 基础规则：在 full-coverage 情景下，APPEARS + No_Data 直接视为 affected
    for i in range(n):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v == "No_Data":
            exec_res = str(df.at[i, "Execution Result"]).strip().upper()
            if exec_res == "APPEARS":
                df.at[i, "LLM_Verdict"] = "affected"

    # 1. not affected_* 扩张阶段
    # 1.1 not affected_patch 向下扩张（同一最小区域内）
    print("正在执行 not affected_patch 向下扩张 (按最小区域)...")
    for i in range(1, n):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        prev_v = str(df.at[i - 1, "LLM_Verdict"]).strip()
        if prev_v == "not affected_patch" and same_region(i, i - 1):
            df.at[i, "LLM_Verdict"] = "not affected_patch"

    # 1.2 not affected_intro 向上扩张（同一最小区域内）
    print("正在执行 not affected_intro 向上扩张 (按最小区域)...")
    for i in range(n - 2, -1, -1):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        next_v = str(df.at[i + 1, "LLM_Verdict"]).strip()
        if next_v == "not affected_intro" and same_region(i, i + 1):
            df.at[i, "LLM_Verdict"] = "not affected_intro"

    # 2. affected_* 扩张阶段
    # 2.1 affected_patch 在同一最小区域内向下、向上双向扩张
    print("正在执行 affected_patch 向下扩张 (按最小区域)...")
    for i in range(1, n):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        prev_v = str(df.at[i - 1, "LLM_Verdict"]).strip()
        if prev_v == "affected_patch" and same_region(i, i - 1):
            df.at[i, "LLM_Verdict"] = "affected_patch"

    print("正在执行 affected_patch 向上扩张 (按最小区域)...")
    for i in range(n - 2, -1, -1):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        next_v = str(df.at[i + 1, "LLM_Verdict"]).strip()
        if next_v == "affected_patch" and same_region(i, i + 1):
            df.at[i, "LLM_Verdict"] = "affected_patch"

    # 2.2 affected_intro 在同一最小区域内向上、向下双向扩张
    print("正在执行 affected_intro 向上扩张 (按最小区域)...")
    for i in range(n - 2, -1, -1):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        next_v = str(df.at[i + 1, "LLM_Verdict"]).strip()
        if next_v == "affected_intro" and same_region(i, i + 1):
            df.at[i, "LLM_Verdict"] = "affected_intro"

    print("正在执行 affected_intro 向下扩张 (按最小区域)...")
    for i in range(1, n):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        prev_v = str(df.at[i - 1, "LLM_Verdict"]).strip()
        if prev_v == "affected_intro" and same_region(i, i - 1):
            df.at[i, "LLM_Verdict"] = "affected_intro"

    # 3. 计算评估指标（保持原有逻辑）
    print("正在计算评估指标 (ab2 full-coverage)...")

    tp = fp = fn = tn = 0

    def process_alignment(row):
        nonlocal tp, fp, fn, tn
        true_s = get_state(row["True Affected Version"])
        llm_s = get_state(row["LLM_Verdict"])

        if true_s == "POS" and llm_s == "POS":
            tp += 1
            return "T"
        if true_s == "NEG" and llm_s == "NEG":
            tn += 1
            return "T"
        if true_s == "NEG" and llm_s == "POS":
            fp += 1
            return "FP"
        if true_s == "POS" and llm_s == "NEG":
            fn += 1
            return "FN"
        return ""

    df["Aligned_llm"] = df.apply(process_alignment, axis=1)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = (tp + tn) / len(df) if len(df) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    try:
        df.to_excel(EXCEL_PATH, index=False)
        print("\n" + "=" * 58)
        print("📊 最终评估报告 (ab2, 逻辑传递后, full-coverage)")
        print("=" * 58)
        print(f"TP (真正例): {tp:4d} | FP (误报): {fp:4d}")
        print(f"FN (漏报):   {fn:4d} | TN (真反例): {tn:4d}")
        print("-" * 58)
        print(f"准确率 (Accuracy):  {accuracy:.2%}")
        print(f"精确率 (Precision): {precision:.2%}")
        print(f"召回率 (Recall):    {recall:.2%}")
        print(f"F1 分数 (F1-Score):  {f1:.4f}")
        print("=" * 58)
        print(f"💾 结果已保存至: {EXCEL_PATH}")
    except Exception as e:
        print(f"❌ 写入 Excel 失败: {e}")


if __name__ == "__main__":
    main()
