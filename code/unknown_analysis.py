import json
import os
import pandas as pd
import numpy as np

# --- 配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
UNKNOWN_JSON_PATH = os.path.join(BASE_PATH, "result/unknown_only_results.json")
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

def main():
    if not os.path.exists(UNKNOWN_JSON_PATH) or not os.path.exists(EXCEL_PATH):
        print("❌ 错误：路径不存在。")
        return

    with open(UNKNOWN_JSON_PATH, 'r') as f: 
        unknown_data = json.load(f)
    df_original = pd.read_excel(EXCEL_PATH)
    
    exec_col = next((c for c in df_original.columns if "execution" in c.lower()), "Execution Result")
    gt_col = next((c for c in df_original.columns if "true affected version" in c.lower()), "True Affected Version")
    df_clean = df_original[df_original[exec_col].str.upper().str.contains("BUILD_SUCCESS|BUILD_FAILURE_OTHER", na=False)].copy()

    thresholds = np.arange(0, 1.05, 0.05)
    
    # 打印表头
    header = f"{'Threshold':<10} | {'Patch Acc':<12} | {'Intro Acc':<12} | {'Total Acc':<10}"
    print("\n" + header)
    print("-" * len(header))

    best_total_acc = -1
    best_df = None

    for t in thresholds:
        t = round(t, 2)
        
        # 1. 聚合判定 (按 CVE+Version+Mode 聚合)
        # key: (CVE, Version, Mode), value: is_na (bool)
        aggregated = {}
        for cve_id, entries in unknown_data.items():
            cve_upper = cve_id.upper().strip()
            for entry in entries:
                mode = entry.get("mode", "").lower().strip()
                analysis_section = entry.get("analysis", {})
                
                for ver_key, ver_info in analysis_section.items():
                    if not isinstance(ver_info, dict): continue
                    
                    score = float(ver_info.get("score", 0))
                    is_yes = score >= t
                    
                    agg_key = (cve_upper, str(ver_key).strip(), mode)
                    if is_yes:
                        aggregated[agg_key] = True
                    elif agg_key not in aggregated:
                        aggregated[agg_key] = False

        # 2. 分类统计
        # 每个模式的统计：{ "tp": 0, "tn": 0, "fp": 0, "fn": 0 }
        stats_patch = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        stats_intro = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        
        temp_df = df_original.copy()

        for idx, row in df_clean.iterrows():
            c_id = str(row['CVE_ID']).upper().strip()
            v_id = str(row['Version']).strip()
            gt = str(row.get(gt_col, "")).strip().lower()

            # 分别检查该版本在 patch 和 intro 模式下的表现
            for mode in ["patch", "introduction"]:
                res_is_na = aggregated.get((c_id, v_id, mode))
                
                if res_is_na is not None:
                    # 确定当前的统计字典
                    curr_stats = stats_patch if mode == "patch" else stats_intro
                    suffix = "patch" if mode == "patch" else "intro"
                    
                    # 记录回填标签 (如果同一个版本有两个 mode，后者会覆盖前者在 Excel 的显示，但统计是分开的)
                    temp_df.at[idx, 'LLM_Verdict'] = f"{'not ' if res_is_na else ''}affected_{suffix}"

                    # 性能计算
                    if not res_is_na: # 判定为受影响 (No)
                        if gt == "affected":
                            curr_stats["tp"] += 1
                            temp_df.at[idx, 'Aligned_llm'] = "T"
                        else:
                            curr_stats["fp"] += 1
                            temp_df.at[idx, 'Aligned_llm'] = "FP"
                    else: # 判定为不受影响 (Yes)
                        if gt == "not affected":
                            curr_stats["tn"] += 1
                            temp_df.at[idx, 'Aligned_llm'] = "T"
                        else:
                            curr_stats["fn"] += 1
                            temp_df.at[idx, 'Aligned_llm'] = "FN"

        # 3. 计算各项准确率
        def get_acc(s):
            total = sum(s.values())
            return (s['tp'] + s['tn']) / total if total > 0 else 0

        acc_patch = get_acc(stats_patch)
        acc_intro = get_acc(stats_intro)
        
        # 总准确率 (所有判定点的加权平均)
        all_tp = stats_patch['tp'] + stats_intro['tp']
        all_tn = stats_patch['tn'] + stats_intro['tn']
        all_total = sum(stats_patch.values()) + sum(stats_intro.values())
        acc_total = (all_tp + all_tn) / all_total if all_total > 0 else 0

        print(f"{t:<10} | {acc_patch:<12.4f} | {acc_intro:<12.4f} | {acc_total:<10.4f}")

        if acc_total >= best_total_acc:
            best_total_acc = acc_total
            best_df = temp_df

    # 4. 保存
    if best_df is not None:
        best_df.to_excel(EXCEL_PATH, index=False)
        print(f"\n✅ 已将总准确率最高 ({best_total_acc:.4f}) 的判定结果保存至 Excel。")

if __name__ == "__main__":
    main()