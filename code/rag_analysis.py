import json
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# --- 配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/cve_rag_filtered.json")
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

# 阈值范围：0.2 到 0.6，间隔 0.05
THRESHOLDS = np.arange(0.2, 0.65, 0.05)

def run_evaluation(threshold, cve_list_data, analysis_data, df_original):
    df = df_original.copy()
    
    # 1. 构建映射 (锁定 target_version 为 not appears)
    truth_map = {}
    for cve_id, content in cve_list_data.items():
        for pair in content.get("version_pair", []):
            key = (cve_id.upper(), str(pair.get("BASE_TAG", "")).strip().lower(), 
                   str(pair.get("HEAD_TAG", "")).strip().lower())
            truth_map[key] = {"target_version": str(pair.get("not appears", "")).strip()}

    # 2. 聚合判定结果
    aggregated_verdicts = {}
    for cve_id, entries in analysis_data.items():
        for entry in entries:
            key = (cve_id.upper(), str(entry.get("base_tag", "")).strip().lower(), 
                   str(entry.get("head_tag", "")).strip().lower())
            if key not in truth_map: continue
            
            mode = str(entry.get("mode", "patch")).lower()
            agg_key = (cve_id.upper(), truth_map[key]["target_version"], mode)

            is_passed = False
            for files_dict in entry.get("analysis", {}).values():
                for f_info in files_dict.values():
                    if isinstance(f_info, dict) and float(f_info.get("score", 0)) >= threshold:
                        is_passed = True; break
                if is_passed: break
            aggregated_verdicts[agg_key] = aggregated_verdicts.get(agg_key, False) or is_passed

    # 3. 优先级覆盖 (Patch > Intro)
    excel_fill_map = {}
    for (cve, ver, mode), is_yes in aggregated_verdicts.items():
        fill_key = (cve, ver)
        status = ("not affected" if is_yes else "affected") if mode == "patch" else ("affected" if is_yes else "not affected")
        if fill_key not in excel_fill_map or mode == "patch":
            excel_fill_map[fill_key] = {"status": status, "mode": mode}

    # 4. 统计指标
    exec_col = next((c for c in df.columns if c.lower() in ["execution result", "execution_result"]), "Execution Result")
    gt_col = next((c for c in df.columns if "true affected version" in c.lower()), "True Affected Version")
    stats = {"patch": {"tp":0, "tn":0, "fp":0, "fn":0}, "intro": {"tp":0, "tn":0, "fp":0, "fn":0}}

    for _, row in df.iterrows():
        exec_status = str(row.get(exec_col, "")).upper()
        if "BUILD_SUCCESS" in exec_status or "BUILD_FAILURE_OTHER" in exec_status:
            res = excel_fill_map.get((str(row['CVE_ID']).upper().strip(), str(row['Version']).strip()))
            if not res: continue
            pred, mode, gt = res["status"], res["mode"], str(row.get(gt_col, "")).strip().lower()
            if pred == "affected":
                if gt == "affected": stats[mode]["tp"] += 1
                else: stats[mode]["fp"] += 1
            else:
                if gt == "not affected": stats[mode]["tn"] += 1
                else: stats[mode]["fn"] += 1
    return stats

def plot_results(results, mode_name):
    x = [r['threshold'] for r in results]
    acc = [r['acc'] for r in results]
    fp = [r['fp'] for r in results]
    fn = [r['fn'] for r in results]

    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    # 绘制正确率 (左轴)
    color_acc = 'tab:blue'
    ax1.set_xlabel('Score Threshold')
    ax1.set_ylabel('Accuracy', color=color_acc)
    ax1.plot(x, acc, color=color_acc, marker='o', label='Accuracy')
    ax1.tick_params(axis='y', labelcolor=color_acc)
    ax1.set_ylim(0, 1.1)

    # 绘制 FP/FN (右轴)
    ax2 = ax1.twinx()
    ax2.set_ylabel('Count (FP / FN)', color='tab:red')
    ax2.plot(x, fp, color='tab:red', linestyle='--', marker='s', label='FP (False Positive)')
    ax2.plot(x, fn, color='tab:green', linestyle=':', marker='^', label='FN (False Negative)')
    ax2.tick_params(axis='y', labelcolor='tab:red')

    plt.title(f'Evaluation Metrics for [{mode_name.upper()}] at Different Thresholds')
    fig.tight_layout()
    plt.grid(True, alpha=0.3)
    
    # 合并图例
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines + lines2, labels + labels2, loc='upper left')
    
    plt.savefig(f"metrics_{mode_name}.png")
    print(f"📈 已生成图表: metrics_{mode_name}.png")

def main():
    with open(CVE_LIST_PATH, 'r') as f: cve_list = json.load(f)
    with open(ANALYSIS_JSON_PATH, 'r') as f: analysis = json.load(f)
    df = pd.read_excel(EXCEL_PATH)

    summary = {"patch": [], "intro": []}

    for t in THRESHOLDS:
        print(f"正在跑阈值: {t:.2f}...")
        stats = run_evaluation(t, cve_list, analysis, df)
        for m in ["patch", "intro"]:
            s = stats[m]
            total = s['tp'] + s['tn'] + s['fp'] + s['fn']
            if total > 0:
                summary[m].append({
                    'threshold': round(t, 2),
                    'acc': (s['tp'] + s['tn']) / total,
                    'fp': s['fp'],
                    'fn': s['fn']
                })

    plot_results(summary["patch"], "patch")
    plot_results(summary["intro"], "intro")

if __name__ == "__main__":
    main()