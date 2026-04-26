import json
import os
import pandas as pd
import numpy as np

# --- 配置区 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_final.json") 
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

# 阈值扫描范围：用于终端打印对比（例如从 -0.4 到 0.4）
THRESHOLDS = [round(x, 2) for x in list(np.arange(-0.4, 0.45, 0.05))]
# 强制写入 Excel 的固定阈值
OUTPUT_THRESHOLD = 0

def main():
    # 1. 加载数据
    try:
        df_original = pd.read_excel(EXCEL_PATH, engine='openpyxl')
        with open(CVE_LIST_PATH, 'r') as f: cve_list = json.load(f)
        with open(ANALYSIS_JSON_PATH, 'r') as f: analysis_data = json.load(f)
    except Exception as e:
        print(f"❌ 加载失败: {e}"); return

    # 2. 建立真值映射 (CVE, Base_Tag) -> Version
    truth_map = {}
    for cve_id, content in cve_list.items():
        cid = cve_id.strip().upper()
        for pair in content.get("version_pair", []):
            b_tag = str(pair.get("BASE_TAG", "")).strip().lower()
            target_ver = str(pair.get("not appears", "")).strip()
            truth_map[(cid, b_tag)] = target_ver

    gt_col = next((c for c in df_original.columns if "true affected version" in c.lower()), "True Affected Version")
    
    results_per_threshold = []
    verdicts_at_zero = {} # 专门存储阈值为 0 时的判定结果

    # 3. 遍历所有阈值进行测试
    for t in THRESHOLDS:
        aggregated_verdicts = {}
        
        for cve_id, entries in analysis_data.items():
            cid = cve_id.strip().upper()
            if not isinstance(entries, list): continue
            
            for entry in entries:
                b_tag = str(entry.get("base_tag", "")).strip().lower()
                if (cid, b_tag) not in truth_map: continue
                
                target_ver = truth_map[(cid, b_tag)]
                agg_key = (cid, target_ver)

                # 递归检查 margin
                analysis_block = entry.get("analysis", {})
                any_intro_found = False
                
                def check_margin(obj):
                    nonlocal any_intro_found
                    if any_intro_found: return
                    if isinstance(obj, dict):
                        if "margin" in obj:
                            try:
                                if float(obj["margin"]) >= t:
                                    any_intro_found = True; return
                            except: pass
                        for v in obj.values(): check_margin(v)
                    elif isinstance(obj, list):
                        for item in obj: check_margin(item)

                check_margin(analysis_block)
                is_affected = not any_intro_found
                aggregated_verdicts[agg_key] = aggregated_verdicts.get(agg_key, False) or is_affected

        # 记录阈值为 0 时的判定数据
        if t == OUTPUT_THRESHOLD:
            verdicts_at_zero = aggregated_verdicts

        # 4. 统计本轮指标（用于终端打印）
        stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        for _, row in df_original.iterrows():
            cid = str(row['CVE_ID']).strip().upper()
            ver = str(row['Version']).strip()
            pred = aggregated_verdicts.get((cid, ver))
            if pred is not None:
                gt = str(row.get(gt_col, "")).strip().lower()
                pred_label = "affected" if pred else "not affected"
                if gt == "affected":
                    if pred_label == "affected": stats["TP"] += 1
                    else: stats["FN"] += 1
                else:
                    if pred_label == "not affected": stats["TN"] += 1
                    else: stats["FP"] += 1

        total = sum(stats.values())
        acc = (stats["TP"] + stats["TN"]) / total if total > 0 else 0
        results_per_threshold.append({"Threshold": t, "Accuracy": acc, "Stats": stats})

    # 5. 打印对比表（展示区间内所有步长的结果）
    print("\n" + "-"*75)
    print(f"{'Thr':<6} | {'TP':<4} | {'TN':<4} | {'FP':<4} | {'FN':<4} | {'Accuracy':<10}")
    print("-" * 75)
    for r in results_per_threshold:
        st = r["Stats"]
        focus = ">>" if r["Threshold"] == OUTPUT_THRESHOLD else "  "
        print(f"{r['Threshold']:<6.2f} | {st['TP']:<4} | {st['TN']:<4} | {st['FP']:<4} | {st['FN']:<4} | {focus} {r['Accuracy']:<10.2%}")
    print("-" * 75)

    # 6. 将阈值为 0 的判定结果回写 Excel
    print(f"写入 Excel 的固定阈值: {OUTPUT_THRESHOLD}")
    df_final = df_original.copy()
    df_final['LLM_Verdict'] = "No_Data"
    df_final['Aligned_llm'] = "No_Data"

    for idx, row in df_final.iterrows():
        cid = str(row['CVE_ID']).strip().upper()
        ver = str(row['Version']).strip()
        res = verdicts_at_zero.get((cid, ver))
        
        if res is not None:
            # --- 修改部分：添加 _intro 后缀 ---
            pred_simple = "affected" if res else "not affected"
            df_final.at[idx, 'LLM_Verdict'] = f"{pred_simple}_intro" 
            # -------------------------------
            
            gt = str(row.get(gt_col, "")).strip().lower()
            if pred_simple == gt:
                df_final.at[idx, 'Aligned_llm'] = "T"
            else:
                df_final.at[idx, 'Aligned_llm'] = "FP" if pred_simple == "affected" else "FN"

    df_final.to_excel(EXCEL_PATH, index=False, engine='openpyxl')
    print(f"✅ 已成功将阈值 {OUTPUT_THRESHOLD} 的数据（带 _intro 后缀）写入: {EXCEL_PATH}")

if __name__ == "__main__":
    main()