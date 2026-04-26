import json
import os
import pandas as pd

# --- 配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/patch_only_results.json")
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

# 锁定阈值为 0.3
FIXED_THRESHOLD = 0.3

def main():
    # 1. 加载数据
    if not all(os.path.exists(p) for p in [CVE_LIST_PATH, ANALYSIS_JSON_PATH, EXCEL_PATH]):
        print("❌ 错误：请检查路径是否正确。")
        return

    with open(CVE_LIST_PATH, 'r') as f: 
        cve_list = json.load(f)
    with open(ANALYSIS_JSON_PATH, 'r') as f: 
        analysis_data = json.load(f)
    
    df = pd.read_excel(EXCEL_PATH)

    # 2. 构建 Truth Map
    truth_map = {}
    for cve_id, content in cve_list.items():
        for pair in content.get("version_pair", []):
            key = (cve_id.upper().strip(), 
                   str(pair.get("BASE_TAG", "")).strip().lower(), 
                   str(pair.get("HEAD_TAG", "")).strip().lower())
            truth_map[key] = str(pair.get("not appears", "")).strip()

    # 3. 聚合判定结果 (Threshold = 0.3)
    aggregated_verdicts = {}
    for cve_id, entries in analysis_data.items():
        for entry in entries:
            key = (cve_id.upper().strip(), 
                   str(entry.get("base_tag", "")).strip().lower(), 
                   str(entry.get("head_tag", "")).strip().lower())
            
            if key not in truth_map:
                continue
            
            target_ver = truth_map[key]
            agg_key = (cve_id.upper().strip(), str(target_ver).strip())

            is_passed = False
            analysis_section = entry.get("analysis", {})
            for commit_id, files_dict in analysis_section.items():
                for f_path, f_info in files_dict.items():
                    if isinstance(f_info, dict):
                        # 读取得分并比较
                        score = float(f_info.get("score", f_info.get("msg_score", 0)))
                        if score >= FIXED_THRESHOLD:
                            is_passed = True
                            break
                if is_passed: break
            
            # 记录判定：只要有一个 patch 匹配成功，该版本即为 not affected
            aggregated_verdicts[agg_key] = aggregated_verdicts.get(agg_key, False) or is_passed

    # 4. 准备回填 Excel
    exec_col = next((c for c in df.columns if "execution" in c.lower()), "Execution Result")
    gt_col = next((c for c in df.columns if "true affected version" in c.lower()), "True Affected Version")
    
    # 清洗：只针对能够编译的行进行操作，确保逻辑严谨
    df_clean_mask = df[exec_col].str.upper().str.contains("BUILD_SUCCESS|BUILD_FAILURE_OTHER", na=False)

    stats = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}

    # 5. 执行覆盖写入
    for idx, row in df[df_clean_mask].iterrows():
        c_id = str(row['CVE_ID']).upper().strip()
        v_id = str(row['Version']).strip()
        
        is_passed = aggregated_verdicts.get((c_id, v_id))
        
        if is_passed is not None:
            # 判定标签输出
            pred_label = "not affected_patch" if is_passed else "affected_patch"
            gt = str(row.get(gt_col, "")).strip().lower()
            
            df.at[idx, 'LLM_Verdict'] = pred_label
            
            # 统计与 Aligned_llm 标记
            if not is_passed: # 判定为受影响
                if gt == "affected":
                    df.at[idx, 'Aligned_llm'] = "T"
                    stats["tp"] += 1
                else:
                    df.at[idx, 'Aligned_llm'] = "FP"
                    stats["fp"] += 1
            else: # 判定为不受影响
                if gt == "not affected":
                    df.at[idx, 'Aligned_llm'] = "T"
                    stats["tn"] += 1
                else:
                    df.at[idx, 'Aligned_llm'] = "FN"
                    stats["fn"] += 1

    # 6. 最终结果汇总
    total = sum(stats.values())
    acc = (stats['tp'] + stats['tn']) / total if total > 0 else 0
    
    print("\n" + "═"*45)
    print(f"🚀 最终评估 (固定阈值: {FIXED_THRESHOLD})")
    print("─" * 45)
    print(f"Accuracy: {acc:.4f}  |  Total Matched: {total}")
    print(f"✅ TP: {stats['tp']} | TN: {stats['tn']}")
    print(f"❌ FP: {stats['fp']} | FN: {stats['fn']}")
    print("═"*45 + "\n")

    # 7. 保存
    df.to_excel(EXCEL_PATH, index=False)
    print(f"✅ 判定结果 (Threshold=0.3) 已成功覆盖至 Excel。")

if __name__ == "__main__":
    main()