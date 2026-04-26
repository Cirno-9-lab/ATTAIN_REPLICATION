import json
import os
import pandas as pd

BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_v6_improved.json")
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

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
    
    aggregated_verdicts = {}
    
    # 判断逻辑:有intro_commits = 版本不存在漏洞(not affected),没有 = 版本存在漏洞(affected)
    for cve_id, entries in analysis_data.items():
        cid = cve_id.strip().upper()
        if not isinstance(entries, list): continue
        
        for entry in entries:
            b_tag = str(entry.get("base_tag", "")).strip().lower()
            if (cid, b_tag) not in truth_map: continue
            
            target_ver = truth_map[(cid, b_tag)]
            agg_key = (cid, target_ver)

            analysis_block = entry.get("analysis", {})
            intro_commits = analysis_block.get("intro_commits", [])
            
            # 有intro_commits且不为空 = 版本不存在漏洞
            has_intro_commits = bool(intro_commits and len(intro_commits) > 0)
            is_affected = not has_intro_commits
            
            aggregated_verdicts[agg_key] = aggregated_verdicts.get(agg_key, False) or is_affected

    # 统计指标
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

    # 打印结果
    print("\n" + "="*75)
    print("基于 intro_commits 字段的判定结果 (v6_improved):")
    print("规则: 有intro_commits = 版本不存在漏洞, 无intro_commits = 版本存在漏洞")
    print("="*75)
    print(f"TP: {stats['TP']} | TN: {stats['TN']} | FP: {stats['FP']} | FN: {stats['FN']}")
    print(f"准确率 (ACC): {acc:.2%}")
    print("="*75)

    # 写入 Excel
    df_final = df_original.copy()
    df_final['v6_improved_Verdict'] = "No_Data"
    df_final['Aligned_v6'] = "No_Data"

    for idx, row in df_final.iterrows():
        cid = str(row['CVE_ID']).strip().upper()
        ver = str(row['Version']).strip()
        res = aggregated_verdicts.get((cid, ver))
        
        if res is not None:
            pred_simple = "affected" if res else "not affected"
            df_final.at[idx, 'v6_improved_Verdict'] = pred_simple
            
            gt = str(row.get(gt_col, "")).strip().lower()
            if pred_simple == gt:
                df_final.at[idx, 'Aligned_v6'] = "T"
            else:
                df_final.at[idx, 'Aligned_v6'] = "FP" if pred_simple == "affected" else "FN"

    df_final.to_excel(EXCEL_PATH, index=False, engine='openpyxl')
    print(f"✅ 已成功将判定结果写入: {EXCEL_PATH}")

if __name__ == "__main__":
    main()
