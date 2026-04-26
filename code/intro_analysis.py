import json
import os
import pandas as pd

# --- 配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/intro_only_results.json") 
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

def main():
    # 1. 检查并读取数据
    if not all(os.path.exists(p) for p in [CVE_LIST_PATH, ANALYSIS_JSON_PATH, EXCEL_PATH]):
        print("❌ 错误：请确认输入文件路径。")
        return

    with open(CVE_LIST_PATH, 'r') as f:
        cve_list = json.load(f)
    with open(ANALYSIS_JSON_PATH, 'r') as f:
        analysis_data_json = json.load(f)
    
    # 读取原始 Excel
    df = pd.read_excel(EXCEL_PATH)

    # 2. 覆盖初始化列
    df['LLM_Verdict'] = "No_Data"
    df['Aligned_llm'] = "No_Data"

    # 3. 映射真值对 (CVE + Tags -> Target Version)
    truth_map = {}
    for cve_id, content in cve_list.items():
        for pair in content.get("version_pair", []):
            key = (cve_id.upper(), 
                    str(pair.get("BASE_TAG", "")).strip().lower(), 
                    str(pair.get("HEAD_TAG", "")).strip().lower())
            truth_map[key] = str(pair.get("not appears", "")).strip()

    # 4. 执行判定聚合
    aggregated_verdicts = {}
    for cve_id, entries in analysis_data_json.items():
        for entry in entries:
            # 仅处理 intro 模式
            if str(entry.get("mode", "")).lower() != "intro":
                continue

            key = (cve_id.upper(), 
                   str(entry.get("base_tag", "")).strip().lower(), 
                   str(entry.get("head_tag", "")).strip().lower())
            
            if key not in truth_map: continue
            
            target_ver = truth_map[key]
            agg_key = (cve_id.upper(), target_ver)

            analysis_block = entry.get("analysis", {})
            
            # --- 核心逻辑：扫描所有 verdict ---
            any_yes_found = False
            
            # 递归检查 analysis_block 中的所有 verdict
            def check_for_yes(obj):
                nonlocal any_yes_found
                if any_yes_found: return
                
                if isinstance(obj, dict):
                    # 如果当前层级有 verdict 键
                    if "verdict" in obj:
                        if str(obj["verdict"]).lower() == "yes":
                            any_yes_found = True
                            return
                    # 否则继续往下挖
                    for val in obj.values():
                        check_for_yes(val)
                elif isinstance(obj, list):
                    for item in obj:
                        check_for_yes(item)

            check_for_yes(analysis_block)

            # 逻辑转换：
            # 有 YES -> 观察到引入 -> a 没漏洞 -> not affected_intro
            # 无 YES (全是 NO) -> 未见引入 -> a 早就受影响了 -> affected_intro
            is_affected = not any_yes_found
            
            # 聚合：针对同一个 CVE+Version，只要有一个 Pair 判定为 affected，最终即为 affected
            aggregated_verdicts[agg_key] = aggregated_verdicts.get(agg_key, False) or is_affected

    # 5. 更新 DataFrame 并对比
    gt_col = next((c for c in df.columns if "true affected version" in c.lower()), "True Affected Version")
    
    for idx, row in df.iterrows():
        cve_id = str(row['CVE_ID']).upper().strip()
        version = str(row['Version']).strip()
        
        res_is_affected = aggregated_verdicts.get((cve_id, version))
        
        if res_is_affected is not None:
            # 写入 LLM_Verdict
            pred_str = "affected_intro" if res_is_affected else "not affected_intro"
            df.at[idx, 'LLM_Verdict'] = pred_str
            
            # 写入比较结果 Aligned_llm
            gt = str(row.get(gt_col, "")).strip().lower()
            pred_simple = "affected" if res_is_affected else "not affected"
            
            if pred_simple == gt:
                df.at[idx, 'Aligned_llm'] = "T"
            else:
                df.at[idx, 'Aligned_llm'] = "FP" if pred_simple == "affected" else "FN"

    # 6. 保存并覆盖原文件
    df.to_excel(EXCEL_PATH, index=False)
    print(f"✅ 处理完成并覆盖原文件: {EXCEL_PATH}")
    
    # 打印简要概览
    counts = df['Aligned_llm'].value_counts()
    print("\n--- 评估统计 ---")
    for label in ['T', 'FP', 'FN', 'No_Data']:
        print(f"{label}: {counts.get(label, 0)}")

if __name__ == "__main__":
    main()