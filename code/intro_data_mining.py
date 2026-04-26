import json
import os
import pandas as pd
import numpy as np

# --- 配置区 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_final.json") 
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")
MINING_REPORT_PATH = os.path.join(BASE_PATH, "full_mining_report.xlsx")

# 阈值设置
THRESHOLDS = [round(x, 2) for x in list(np.arange(-0.4, 0.45, 0.05))]
OUTPUT_THRESHOLD = 0

def main():
    try:
        df_original = pd.read_excel(EXCEL_PATH, engine='openpyxl')
        with open(CVE_LIST_PATH, 'r') as f: cve_list = json.load(f)
        with open(ANALYSIS_JSON_PATH, 'r') as f: analysis_data = json.load(f)
        print(f"📊 数据加载成功。正在关联 CWE 并执行全量挖掘...")
    except Exception as e:
        print(f"❌ 加载失败: {e}"); return

    # 1. 建立真值映射 & CWE 映射
    truth_map = {}
    cwe_map = {}
    for cve_id, content in cve_list.items():
        cid = cve_id.strip().upper()
        # 提取 CWE 信息
        cwes = content.get("cwe", [])
        cwe_map[cid] = ", ".join(cwes) if isinstance(cwes, list) else str(cwes)
        
        # 提取版本真值
        for pair in content.get("version_pair", []):
            b_tag = str(pair.get("BASE_TAG", "")).strip().lower()
            target_ver = str(pair.get("not appears", "")).strip()
            truth_map[(cid, b_tag)] = target_ver

    gt_col = next((c for c in df_original.columns if "true affected version" in c.lower()), "True Affected Version")
    
    # 2. 遍历阈值并捕获证据
    results_per_threshold = []
    detailed_trace_at_zero = {} 

    for t in THRESHOLDS:
        aggregated_verdicts = {}
        for cve_id, entries in analysis_data.items():
            cid = cve_id.strip().upper()
            for entry in entries:
                b_tag = str(entry.get("base_tag", "")).strip().lower()
                if (cid, b_tag) not in truth_map: continue
                target_ver = truth_map[(cid, b_tag)]
                agg_key = (cid, target_ver)

                # 寻找该 Entry 中最具代表性的证据
                best_evidence = {"margin": -999.0, "file": "N/A", "commit": "N/A", "evidence": "N/A", "vule": 0.0, "safe": 0.0}
                analysis_block = entry.get("analysis", {})
                
                if isinstance(analysis_block, dict):
                    for commit_id, files in analysis_block.items():
                        for file_path, info in files.items():
                            try:
                                m = float(info.get("margin", -1.0))
                                if m > best_evidence["margin"]:
                                    best_evidence.update({
                                        "margin": m, "file": file_path, "commit": commit_id,
                                        "evidence": info.get("evidence", "No Evidence Found"),
                                        "vule": info.get("vule_score", 0.0), "safe": info.get("safe_score", 0.0)
                                    })
                            except: pass

                is_affected = best_evidence["margin"] < t
                if agg_key not in aggregated_verdicts or not is_affected:
                    aggregated_verdicts[agg_key] = is_affected
                    if t == OUTPUT_THRESHOLD: detailed_trace_at_zero[agg_key] = best_evidence

        # 统计简报
        stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        for _, row in df_original.iterrows():
            cid, ver = str(row['CVE_ID']).strip().upper(), str(row['Version']).strip()
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
        
        acc = (stats["TP"] + stats["TN"])/sum(stats.values()) if sum(stats.values()) > 0 else 0
        results_per_threshold.append({"Threshold": t, "Accuracy": acc, "Stats": stats})

    # 3. 输出控制台概览
    print("\n" + "-"*80)
    print(f"{'Thr':<6} | {'TP':<4} | {'TN':<4} | {'FP':<4} | {'FN':<4} | {'Accuracy'}")
    print("-" * 80)
    for r in results_per_threshold:
        st = r["Stats"]
        mark = ">>" if r["Threshold"] == OUTPUT_THRESHOLD else "  "
        print(f"{r['Threshold']:<6.2f} | {st['TP']:<4} | {st['TN']:<4} | {st['FP']:<4} | {st['FN']:<4} | {mark} {r['Accuracy']:.2%}")

    # 4. 生成挖掘数据 & 关联 CWE
    mining_data = []
    df_final = df_original.copy()

    for idx, row in df_final.iterrows():
        cid, ver = str(row['CVE_ID']).strip().upper(), str(row['Version']).strip()
        key = (cid, ver)
        res = detailed_trace_at_zero.get(key)
        
        # 为主表添加 CWE
        df_final.at[idx, 'CWE'] = cwe_map.get(cid, "Unknown")
        
        if res:
            gt = str(row.get(gt_col, "")).strip().lower()
            pred_simple = "affected" if res["margin"] < OUTPUT_THRESHOLD else "not affected"
            
            # 记录判定类型
            if gt == "affected":
                aligned_type = "TP" if pred_simple == "affected" else "FN"
            else:
                aligned_type = "TN" if pred_simple == "not affected" else "FP"
            
            df_final.at[idx, 'LLM_Verdict'] = pred_simple
            df_final.at[idx, 'Aligned_llm'] = "T" if aligned_type in ["TP", "TN"] else aligned_type

            # 收集详细挖掘信息
            mining_data.append({
                "CVE_ID": cid,
                "CWE": cwe_map.get(cid, "Unknown"), # 这里也加上 CWE
                "Version": ver,
                "Result_Type": aligned_type,
                "Ground_Truth": gt,
                "LLM_Verdict": pred_simple,
                "Margin": res["margin"],
                "Vule_Score": res["vule"],
                "Safe_Score": res["safe"],
                "Key_File": res["file"],
                "Key_Commit": res["commit"],
                "Evidence": res["evidence"]
            })

    # 5. 保存结果
    df_final.to_excel(EXCEL_PATH, index=False)
    pd.DataFrame(mining_data).to_excel(MINING_REPORT_PATH, index=False)
    
    print(f"\n✅ 主表已更新 (含CWE列): {EXCEL_PATH}")
    print(f"🔍 全量挖掘报告已生成: {MINING_REPORT_PATH}")

if __name__ == "__main__":
    main()