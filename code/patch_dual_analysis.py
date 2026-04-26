import json
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# --- 配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/patch_only_results.json")
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

# 阈值范围设定
MSG_THRESHOLDS = np.arange(0.0, 1.05, 0.05)   
MARGIN_THRESHOLDS = np.arange(-1.0, 1.1, 0.5) 

def run_evaluation_2d(t_msg, t_margin, truth_map, analysis_data, df_clean):
    """
    逻辑：只要在任何一个 commit 的任何一个文件中，
    同时满足 msg_score >= t_msg 且 margin >= t_margin，则判定该版本已修复 (is_passed = True)
    """
    aggregated_verdicts = {}
    
    for cve_id, entries in analysis_data.items():
        cve_upper = cve_id.upper().strip()
        for entry in entries:
            # 严格匹配模式
            if str(entry.get("mode", "")).lower() != "patch":
                continue

            # 构造匹配 Key: (CVE, BASE, HEAD)
            base = str(entry.get("base_tag", "")).strip().lower()
            head = str(entry.get("head_tag", "")).strip().lower()
            key = (cve_upper, base, head)
            
            if key not in truth_map:
                continue
            
            target_ver = truth_map[key]
            agg_key = (cve_upper, target_ver)

            # 判定逻辑开始
            is_passed = False
            analysis_section = entry.get("analysis", {})
            
            # 穿透 Commit Hash 层 (e.g., "a6e412bd...")
            for commit_hash, files_dict in analysis_section.items():
                for file_path, f_info in files_dict.items():
                    if isinstance(f_info, dict):
                        # 获取分数并处理空值
                        m_score = float(f_info.get("msg_score", 0) or 0)
                        margin = float(f_info.get("margin", 0) or 0)
                        
                        if m_score >= t_msg and margin >= t_margin:
                            is_passed = True
                            break
                if is_passed: break
            
            # 如果该 (CVE, Version) 之前已经是 True，保持 True
            aggregated_verdicts[agg_key] = aggregated_verdicts.get(agg_key, False) or is_passed

    # 统计指标
    stats = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    matched_count = 0

    for _, row in df_clean.iterrows():
        cve_id = str(row['CVE_ID']).upper().strip()
        version = str(row['Version']).strip()
        lookup_key = (cve_id, version)
        
        if lookup_key not in aggregated_verdicts:
            continue
            
        matched_count += 1
        is_passed = aggregated_verdicts[lookup_key]
        gt = str(row.get("True Affected Version", "")).strip().lower()
        
        # 核心逻辑：
        # is_passed = True  => LLM认为补丁存在 => 判定为 "not affected"
        # is_passed = False => LLM认为补丁不存在 => 判定为 "affected"
        
        if not is_passed: # 预测为受影响 (Patch absent)
            if gt == "affected": stats["tp"] += 1
            else: stats["fp"] += 1
        else: # 预测为不受影响 (Patch present)
            if gt == "not affected": stats["tn"] += 1
            else: stats["fn"] += 1
            
    total = sum(stats.values())
    acc = (stats['tp'] + stats['tn']) / total if total > 0 else 0
    return acc, stats['fn'], stats['fp'], matched_count

def plot_3d(X, Y, Z, title, z_label):
    if np.all(Z == 0):
        print(f"⚠️ 跳过绘图: {title} 的数据全为 0")
        return
    fig = plt.figure(figsize=(10, 7))
    ax = fig.add_subplot(111, projection='3d')
    surf = ax.plot_surface(X, Y, Z, cmap='coolwarm', edgecolor='none', alpha=0.8)
    ax.set_xlabel('msg_score Threshold')
    ax.set_ylabel('margin Threshold')
    ax.set_zlabel(z_label)
    ax.set_title(title)
    fig.colorbar(surf, ax=ax, shrink=0.5, aspect=5)
    plt.show()

def main():
    # 1. 加载数据
    try:
        with open(CVE_LIST_PATH, 'r') as f: cve_list = json.load(f)
        with open(ANALYSIS_JSON_PATH, 'r') as f: analysis = json.load(f)
        df = pd.read_excel(EXCEL_PATH)
    except Exception as e:
        print(f"❌ 文件读取失败: {e}")
        return

    # 预处理 Truth Map
    truth_map = {}
    for cve_id, content in cve_list.items():
        for pair in content.get("version_pair", []):
            b = str(pair.get("BASE_TAG", "")).strip().lower()
            h = str(pair.get("HEAD_TAG", "")).strip().lower()
            # 记录这组 tag 对应的实际 Version 字符串
            truth_map[(cve_id.upper().strip(), b, h)] = str(pair.get("not appears", "")).strip()

    # 清洗 Excel 数据
    exec_col = next((c for c in df.columns if c.lower() in ["execution result", "execution_result"]), "Execution Result")
    df_clean = df[df[exec_col].str.upper().str.contains("BUILD_SUCCESS|BUILD_FAILURE_OTHER", na=False)].copy()

    # 2. 网格搜索
    X, Y = np.meshgrid(MSG_THRESHOLDS, MARGIN_THRESHOLDS)
    Z_acc, Z_fn, Z_fp = np.zeros(X.shape), np.zeros(X.shape), np.zeros(X.shape)

    print(f"🔍 正在扫描网格组合...")
    
    last_matched = 0
    for i in range(len(MARGIN_THRESHOLDS)):
        for j in range(len(MSG_THRESHOLDS)):
            acc, fn, fp, matched = run_evaluation_2d(MSG_THRESHOLDS[j], MARGIN_THRESHOLDS[i], truth_map, analysis, df_clean)
            Z_acc[i, j], Z_fn[i, j], Z_fp[i, j] = acc, fn, fp
            last_matched = matched

    print(f"📊 评估完成。Excel 匹配成功的样本数: {last_matched}")
    if last_matched == 0:
        print("🚨 警告: 匹配样本数为 0！请检查 Excel 的 'Version' 列和 cve_list.json 中的 'not appears' 是否一致。")
        return

    # 3. 可视化
    plot_3d(X, Y, Z_acc, "Accuracy Distribution", "Accuracy")
    plot_3d(X, Y, Z_fn, "False Negatives (FN)", "Count")
    plot_3d(X, Y, Z_fp, "False Positives (FP)", "Count")

    # 输出最优解
    max_idx = np.unravel_index(np.argmax(Z_acc, axis=None), Z_acc.shape)
    print(f"\n🏆 最佳组合发现:")
    print(f"- msg_score >= {MSG_THRESHOLDS[max_idx[1]]:.2f}")
    print(f"- margin >= {MARGIN_THRESHOLDS[max_idx[0]]:.2f}")
    print(f"- 最高准确率: {Z_acc[max_idx]:.4f}")

if __name__ == "__main__":
    main()