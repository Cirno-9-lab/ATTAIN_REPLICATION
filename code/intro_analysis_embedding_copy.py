import json
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# --- 配置区 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/intro_only_results.json") 
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

# 阈值：从 -0.3 到 0.3，步长 0.05
THRESHOLDS = [round(x, 2) for x in list(np.arange(-0.3, 0.35, 0.05))]

def main():
    # 1. 加载数据
    try:
        df_original = pd.read_excel(EXCEL_PATH, engine='openpyxl')
        with open(CVE_LIST_PATH, 'r') as f: cve_list = json.load(f)
        with open(ANALYSIS_JSON_PATH, 'r') as f: analysis_data = json.load(f)
    except Exception as e:
        print(f"❌ 加载失败: {e}"); return

    # 2. 建立真值映射 (CVE, Base, Head) -> Target_Version
    truth_map = {}
    for cve_id, content in cve_list.items():
        cid = cve_id.strip().upper()
        for pair in content.get("version_pair", []):
            b_tag = str(pair.get("BASE_TAG", "")).strip().lower()
            h_tag = str(pair.get("HEAD_TAG", "")).strip().lower()
            target_ver = str(pair.get("not appears", "")).strip()
            truth_map[(cid, b_tag, h_tag)] = target_ver

    gt_col = next((c for c in df_original.columns if "true affected version" in c.lower()), "True Affected Version")
    
    # 存储所有阈值下的详细判定，以便最后选出最好的存入 Excel
    all_threshold_results = []

    # 3. 遍历所有阈值进行测试
    for t in THRESHOLDS:
        aggregated_verdicts = {}
        
        for cve_id, entries in analysis_data.items():
            cid = cve_id.strip().upper()
            for entry in entries:
                b_tag = str(entry.get("base_tag", "")).strip().lower()
                h_tag = str(entry.get("head_tag", "")).strip().lower()
                
                key = (cid, b_tag, h_tag)
                if key not in truth_map: continue
                
                target_ver = truth_map[key]
                agg_key = (cid, target_ver)

                # Margin 判定逻辑
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
                
                # 聚合判定
                aggregated_verdicts[agg_key] = aggregated_verdicts.get(agg_key, False) or is_affected

        # 统计本轮指标
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
        acc = (stats["TP"] + stats["TN"]) / total * 100 if total > 0 else 0
        
        all_threshold_results.append({
            "Threshold": t,
            "Accuracy": acc,
            "Stats": stats,
            "Verdicts": aggregated_verdicts # 暂存判定结果
        })

    # 4. 寻找 Accuracy 最高的阈值
    # 如果有多个相同最高分，取第一个
    best_result = max(all_threshold_results, key=lambda x: x['Accuracy'])
    best_thr = best_result["Threshold"]
    best_acc = best_result["Accuracy"]
    best_verdicts = best_result["Verdicts"]
    best_stats = best_result["Stats"]

    print("\n" + "="*75)
    print(f"🏆 最优阈值发现: {best_thr}")
    print(f"📊 最高准确率: {best_acc:.2f}%")
    print(f"📈 详细指标: TP={best_stats['TP']}, TN={best_stats['TN']}, FP={best_stats['FP']}, FN={best_stats['FN']}")
    print("="*75)

    # 5. 将最优结果写入 Excel
    df_final = df_original.copy()
    df_final['LLM_Verdict'] = "No_Data"
    df_final['Aligned_llm'] = "No_Data"

    for idx, row in df_final.iterrows():
        cid = str(row['CVE_ID']).strip().upper()
        ver = str(row['Version']).strip()
        res = best_verdicts.get((cid, ver))
        
        if res is not None:
            df_final.at[idx, 'LLM_Verdict'] = "affected_intro" if res else "not affected_intro"
            gt = str(row.get(gt_col, "")).strip().lower()
            pred_simple = "affected" if res else "not affected"
            df_final.at[idx, 'Aligned_llm'] = "T" if pred_simple == gt else ("FP" if pred_simple == "affected" else "FN")

    df_final.to_excel(EXCEL_PATH, index=False, engine='openpyxl')
    print(f"✅ 已将最优阈值 ({best_thr}) 的判定结果保存至: {EXCEL_PATH}")

    # 6. 打印全量对比表
    print("\n" + "-"*75)
    print(f"{'Margin Thr':<10} | {'TP':<5} | {'TN':<5} | {'FP':<5} | {'FN':<5} | {'Accuracy':<10}")
    print("-" * 75)
    for r in all_threshold_results:
        s = r["Stats"]
        print(f"{r['Threshold']:<10.2f} | {s['TP']:<5} | {s['TN']:<5} | {s['FP']:<5} | {s['FN']:<5} | {r['Accuracy']:.2f}%")

if __name__ == "__main__":
    main()