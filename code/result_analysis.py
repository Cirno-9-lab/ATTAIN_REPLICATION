import pandas as pd
import os

# --- 路径配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

def get_state(val):
    """判定一个单元格内容属于阳性还是阴性"""
    s = str(val).strip().lower()
    # 阳性：包含 affected 且不是以 not 开头
    if "affected" in s and not s.startswith("not"):
        return "POS"
    return "NEG"

def main():
    if not os.path.exists(EXCEL_PATH):
        print(f"❌ 找不到文件: {EXCEL_PATH}")
        return

    # 1. 读取数据
    df = pd.read_excel(EXCEL_PATH)

    required_cols = ["CVE_ID", "LLM_Verdict", "Execution Result", "True Affected Version"]
    for col in required_cols:
        if col not in df.columns:
            print(f"❌ Excel 中缺少必要列: {col}")
            return

    # 2. 第一遍扫描：前向处理 (向下传递 not affected_patch)
    print("正在执行前向扫描 (向下传递)...")
    for i in range(len(df)):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        current_cve = str(df.at[i, "CVE_ID"]).strip()
        
        # 基础逻辑：No_Data 且 APPEARS 强制为 affected
        if current_v == "No_Data":
            exec_res = str(df.at[i, "Execution Result"]).strip().upper()
            if exec_res == "APPEARS":
                df.at[i, "LLM_Verdict"] = "affected"
            
            # 传递逻辑：继承同 CVE 上一行的 not affected_patch
            elif i > 0:
                prev_cve = str(df.at[i-1, "CVE_ID"]).strip()
                prev_v = str(df.at[i-1, "LLM_Verdict"]).strip()
                if current_cve == prev_cve and prev_v == "not affected_patch":
                    df.at[i, "LLM_Verdict"] = "not affected_patch"

    # 3. 第二遍扫描：后向处理 (向上传递 not affected_intro)
    print("正在执行后向扫描 (向上传递)...")
    for i in range(len(df) - 2, -1, -1):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v == "No_Data":
            current_cve = str(df.at[i, "CVE_ID"]).strip()
            current_lib = str(df.at[i, "Library"]).strip()
            next_cve = str(df.at[i+1, "CVE_ID"]).strip()
            next_lib = str(df.at[i+1, "Library"]).strip()
            next_v = str(df.at[i+1, "LLM_Verdict"]).strip()
            
            # 传递逻辑：仅在同 CVE 且同 Library 内，继承下一行的 not affected_intro
            if current_cve == next_cve and current_lib == next_lib and next_v == "not affected_intro":
                df.at[i, "LLM_Verdict"] = "not affected_intro"

    # 4. 计算 Aligned_llm 及混淆矩阵各项
    print("正在计算评估指标...")
    
    tp, fp, fn, tn = 0, 0, 0, 0

    def process_alignment(row):
        nonlocal tp, fp, fn, tn
        true_s = get_state(row["True Affected Version"])
        llm_s = get_state(row["LLM_Verdict"])

        if true_s == "POS" and llm_s == "POS":
            tp += 1
            return "T"
        elif true_s == "NEG" and llm_s == "NEG":
            tn += 1
            return "T"
        elif true_s == "NEG" and llm_s == "POS":
            fp += 1
            return "FP"
        elif true_s == "POS" and llm_s == "NEG":
            fn += 1
            return "FN"
        return ""

    df["Aligned_llm"] = df.apply(process_alignment, axis=1)

    # 5. 计算 Pre. Rec. Acc.
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = (tp + tn) / len(df) if len(df) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    # 6. 保存并输出报告
    try:
        df.to_excel(EXCEL_PATH, index=False)
        print("\n" + "="*50)
        print("📊 最终评估报告 (逻辑传递后)")
        print("="*50)
        print(f"TP (真正例): {tp:4d} | FP (误报): {fp:4d}")
        print(f"FN (漏报):   {fn:4d} | TN (真反例): {tn:4d}")
        print("-" * 50)
        print(f"准确率 (Accuracy):  {accuracy:.2%}")
        print(f"精确率 (Precision): {precision:.2%}")
        print(f"召回率 (Recall):    {recall:.2%}")
        print(f"F1 分数 (F1-Score):  {f1:.4f}")
        print("="*50)
        print(f"💾 结果已保存至: {EXCEL_PATH}")
    except Exception as e:
        print(f"❌ 写入 Excel 失败: {e}")

if __name__ == "__main__":
    main()