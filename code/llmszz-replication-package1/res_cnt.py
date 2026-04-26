import os
import json
import pandas as pd

# --- 目录配置 ---
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)           # .../llmszz-replication-package1/
code_dir = os.path.dirname(script_dir)             
workspace_dir = os.path.dirname(code_dir)          

# --- 输入/输出文件路径 ---
commit_file_path = os.path.join(workspace_dir, "dataset", "execution_result.xlsx")
input_json_path = os.path.join(script_dir, "log", "output.json")
output_json_path = os.path.join(script_dir, "log", "stats.json")

def calculate_accuracy():
    # 1. 加载数据
    if not os.path.exists(input_json_path) or not os.path.exists(commit_file_path):
        return

    with open(input_json_path, 'r', encoding='utf-8') as f:
        predictions = json.load(f)

    df = pd.read_excel(commit_file_path)
    # 统一列名为小写以忽略大小写
    df.columns = [str(col).lower() for col in df.columns]
    
    # 2. 以 CVE 为单位整理预测数据
    # 有些 output.json 可能是列表，每个元素是一个 CVE 的预测结果
    pred_map = {}
    for item in predictions:
        cve_id = str(item.get("cve_id", "")).strip()
        vul_version = str(item.get("vul_version", "")).strip()
        if cve_id not in pred_map:
            pred_map[cve_id] = []
        pred_map[cve_id].append(vul_version)

    # 3. 核心统计逻辑
    correct_cve_count = 0
    total_cve_count = len(pred_map)
    results_detail = {}

    for cve_id, pred_versions in pred_map.items():
        # 获取 Excel 中该 CVE 对应的所有行
        matched_rows = df[df['cve_id'].astype(str).str.strip() == cve_id]
        
        is_cve_correct = False
        
        if not matched_rows.empty:
            # 只要预测的任一版本能在该 CVE 的 Excel 记录中找到命中且为 affected，则该 CVE 正确
            for p_ver in pred_versions:
                for _, row in matched_rows.iterrows():
                    excel_version = str(row.get('version', ""))
                    true_status = str(row.get('true affected version', "")).lower().strip()
                    
                    # 子串匹配且状态为 affected
                    if (p_ver in excel_version or excel_version in p_ver) and (true_status == "affected"):
                        is_cve_correct = True
                        break
                if is_cve_correct:
                    break
        
        if is_cve_correct:
            correct_cve_count += 1
        
        results_detail[cve_id] = {
            "predicted_versions": pred_versions,
            "is_correct": is_cve_correct
        }

    # 4. 计算并保存结果
    accuracy = correct_cve_count / total_cve_count if total_cve_count > 0 else 0
    
    stats = {
        "summary": {
            "total_cve": total_cve_count,
            "correct_cve": correct_cve_count,
            "accuracy": f"{accuracy:.2%}"
        },
        "details": results_detail
    }

    os.makedirs(os.path.dirname(output_json_path), exist_ok=True)
    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=4, ensure_ascii=False)

    # 5. 控制台打印
    print(f"Accuracy: {accuracy:.2%}")

if __name__ == "__main__":
    calculate_accuracy()