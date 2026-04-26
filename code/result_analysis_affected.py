import pandas as pd
import os

# --- 路径配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

def main():
    if not os.path.exists(EXCEL_PATH):
        print(f"❌ 找不到文件: {EXCEL_PATH}")
        return

    # 读取 Excel
    df = pd.read_excel(EXCEL_PATH)

    # 检查必要列
    required_cols = ["CVE_ID", "LLM_Verdict", "Execution Result", "True Affected Version"]
    for col in required_cols:
        if col not in df.columns:
            print(f"❌ Excel 中缺少必要列: {col}")
            return

    # --- 1. 前向扫描 (向下传递) ---
    print("正在进行第一遍扫描: 处理 APPEARS 以及向下传递 patch 状态...")
    for i in range(len(df)):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        current_cve = str(df.at[i, "CVE_ID"]).strip()
        
        # 逻辑 A: No_Data 且执行结果为 APPEARS，强制标记为 affected
        if current_v == "No_Data":
            exec_res = str(df.at[i, "Execution Result"]).strip().upper()
            if exec_res == "APPEARS":
                df.at[i, "LLM_Verdict"] = "affected"
                current_v = "affected" 
            
            # 逻辑 B: 同一个 CVE 内，继承上一行的状态 (新增 affected_patch 继承)
            elif i > 0:
                prev_cve = str(df.at[i-1, "CVE_ID"]).strip()
                prev_v = str(df.at[i-1, "LLM_Verdict"]).strip()
                if current_cve == prev_cve:
                    # 原有逻辑：继承 not affected_patch
                    # 新增逻辑：继承 affected_patch
                    if prev_v in ["not affected_patch", "affected_patch"]:
                        df.at[i, "LLM_Verdict"] = prev_v

    # --- 2. 后向扫描 (向上传递) ---
    print("正在进行第二遍扫描: 向上传递 intro 状态...")
    for i in range(len(df) - 2, -1, -1):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v == "No_Data":
            current_cve = str(df.at[i, "CVE_ID"]).strip()
            next_cve = str(df.at[i+1, "CVE_ID"]).strip()
            next_v = str(df.at[i+1, "LLM_Verdict"]).strip()
            
            # 逻辑 C: 同一个 CVE 内，继承下一行的状态 (新增 affected_intro 继承)
            if current_cve == next_cve:
                # 原有逻辑：继承 not affected_intro
                # 新增逻辑：继承 affected_intro
                if next_v in ["not affected_intro", "affected_intro"]:
                    df.at[i, "LLM_Verdict"] = next_v

    # --- 3. 统计逻辑 (修复后缀导致的 FN/FP 错误) ---
    print("正在重新计算对齐统计 (Aligned_llm)...")

    def get_pos_neg_state(val):
        """判定一个字符串代表的是阳性(Affected)还是阴性(Not Affected/No Data)"""
        s = str(val).strip().lower()
        if "affected" in s and not s.startswith("not"):
            return "POSITIVE"
        return "NEGATIVE"

    def calculate_alignment(row):
        true_state = get_pos_neg_state(row["True Affected Version"])
        llm_state = get_pos_neg_state(row["LLM_Verdict"])

        if true_state == llm_state:
            return "T"
        elif true_state == "NEGATIVE" and llm_state == "POSITIVE":
            return "FP"
        elif true_state == "POSITIVE" and llm_state == "NEGATIVE":
            return "FN"
        return ""

    df["Aligned_llm"] = df.apply(calculate_alignment, axis=1)

    # --- 4. 汇总报告与保存 ---
    total = len(df)
    t_num = (df["Aligned_llm"] == "T").sum()
    fp_num = (df["Aligned_llm"] == "FP").sum()
    fn_num = (df["Aligned_llm"] == "FN").sum()
    accuracy = (t_num / total) * 100 if total > 0 else 0

    try:
        df.to_excel(EXCEL_PATH, index=False)
        print("-" * 50)
        print(f"📊 最终统计报告 (继承模式更新):")
        print(f"✅ 总行数: {total}")
        print(f"✅ 正确 (T): {t_num}")
        print(f"❌ 误报 (FP): {fp_num}")
        print(f"❌ 漏报 (FN): {fn_num}")
        print(f"📈 综合准确率: {accuracy:.2f}%")
        print("-" * 50)
        print(f"💾 结果已成功更新至: {EXCEL_PATH}")
    except Exception as e:
        print(f"❌ 写入 Excel 失败: {e}")

if __name__ == "__main__":
    main()