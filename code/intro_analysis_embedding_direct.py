import json
import os
import pandas as pd

# --- 1. 配置路径 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/intro_reverse_timeout_audit.json") 
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

def main():
    # 数据加载
    try:
        df_original = pd.read_excel(EXCEL_PATH, engine='openpyxl')
        with open(CVE_LIST_PATH, 'r') as f: cve_list = json.load(f)
        with open(ANALYSIS_JSON_PATH, 'r') as f: analysis_data = json.load(f)
    except Exception as e:
        print(f"❌ 加载失败: {e}"); return

    # 2. 真值映射 (CVE, Base, Head) -> Target_Version
    truth_map = {}
    for cve_id, content in cve_list.items():
        cid = cve_id.strip().upper()
        for pair in content.get("version_pair", []):
            b_tag = str(pair.get("BASE_TAG", "")).strip().lower()
            h_tag = str(pair.get("HEAD_TAG", "")).strip().lower()
            target_ver = str(pair.get("not appears", "")).strip()
            truth_map[(cid, b_tag, h_tag)] = target_ver

    gt_col = next((c for c in df_original.columns if "true affected version" in c.lower()), "True Affected Version")
    
    # 3. 核心判定逻辑：直接读取 "verdict"
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

            # 遍历判定结果
            analysis_block = entry.get("analysis", {})
            any_yes_found = False
            
            def find_yes(obj):
                nonlocal any_yes_found
                if any_yes_found: return
                if isinstance(obj, dict):
                    # 💡 直接检测字符串
                    if str(obj.get("verdict", "")).lower() == "yes":
                        any_yes_found = True
                        return
                    for v in obj.values(): find_yes(v)
                elif isinstance(obj, list):
                    for item in obj: find_yes(item)

            find_yes(analysis_block)
            
            # 逻辑：如果没有任何一个 commit 被模型标记为 "yes"，则认为该版本受影响
            is_affected = not any_yes_found
            # 聚合：只要有一个 pair 支撑受影响结论，该版本即为 affected
            aggregated_verdicts[agg_key] = aggregated_verdicts.get(agg_key, False) or is_affected

    # 4. 统计 TP, TN, FP, FN
    stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    df_final = df_original.copy()
    
    for idx, row in df_final.iterrows():
        cid = str(row['CVE_ID']).strip().upper()
        ver = str(row['Version']).strip()
        
        pred = aggregated_verdicts.get((cid, ver))
        if pred is not None:
            gt = str(row.get(gt_col, "")).strip().lower()
            pred_label = "affected" if pred else "not affected"
            
            # 更新 Excel
            df_final.at[idx, 'LLM_Verdict'] = f"{pred_label}_raw"
            
            if gt == "affected":
                if pred_label == "affected":
                    stats["TP"] += 1
                    df_final.at[idx, 'Aligned_llm'] = "T"
                else:
                    stats["FN"] += 1
                    df_final.at[idx, 'Aligned_llm'] = "FN"
            else: # gt == "not affected"
                if pred_label == "not affected":
                    stats["TN"] += 1
                    df_final.at[idx, 'Aligned_llm'] = "T"
                else:
                    stats["FP"] += 1
                    df_final.at[idx, 'Aligned_llm'] = "FP"

    # 5. 计算并打印
    total = sum(stats.values())
    acc = (stats["TP"] + stats["TN"]) / total * 100 if total > 0 else 0

    print("\n" + "="*40)
    print(f"📊 基于原始 Verdict 的评估结果")
    print("-" * 40)
    print(f"TP (受影响且判对): {stats['TP']}")
    print(f"TN (安全且判对):   {stats['TN']}")
    print(f"FP (安全判受影响): {stats['FP']}")
    print(f"FN (受影响判安全): {stats['FN']}")
    print("-" * 40)
    print(f"✅ 最终准确率: {acc:.2f}%")
    print("="*40)

    # 保存文件
    df_final.to_excel(EXCEL_PATH, index=False, engine='openpyxl')
    print(f"🚀 结果已保存至: {EXCEL_PATH}")

if __name__ == "__main__":
    main()