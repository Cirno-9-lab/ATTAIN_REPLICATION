import pandas as pd
import json
import os

def get_paths():
    # --- 目录配置 ---
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path) 
    code_dir = os.path.dirname(script_dir) 
    workspace_dir = os.path.dirname(code_dir) 

    excel_file_path = os.path.join(workspace_dir, "dataset", "execution_result.xlsx")
    ghrepo_json_path = os.path.join(workspace_dir, "dataset", "cve_ghrepo.json")
    output_json_path = os.path.join(workspace_dir, "dataset", "cve_critical_version.json")
    
    return excel_file_path, ghrepo_json_path, output_json_path

def load_repo_mapping(json_path):
    """解析字典格式的 cve_ghrepo.json"""
    mapping = {}
    if not os.path.exists(json_path):
        return mapping
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for cve_id, info in data.items():
                mapping[cve_id] = {
                    "owner": info.get("owner", "unknown"),
                    "repo_name": info.get("repo", "unknown")
                }
    except Exception as e:
        print(f"读取映射文件出错: {e}")
    return mapping

def is_poc_success(status):
    """判断是否为 APPEARS"""
    return str(status).strip().upper() == "APPEARS"

def is_poc_fail(status):
    """判断是否为触发失败的状态"""
    s = str(status).strip().upper()
    return s in ["BUILD_SUCCESS", "BUILD_FAILURE_OTHER"]

def get_compile_status(status):
    """判断编译是否成功"""
    s = str(status).strip().upper()
    if s == "BUILD_FAILURE_OTHER":
        return False
    if s == "BUILD_SUCCESS" or s == "APPEARS":
        return True
    return False

def version_verify():
    excel_path, ghrepo_path, json_path = get_paths()

    if not os.path.exists(excel_path):
        print(f"错误: 找不到输入文件 {excel_path}")
        return

    repo_map = load_repo_mapping(ghrepo_path)
    df = pd.read_excel(excel_path)
    df.columns = [col.lower() for col in df.columns]

    # 定义列名映射
    col_cve = "cve_id"
    col_ver = "version"
    col_result = "execution result"
    col_cause = "cause"  # 新增 Cause 列

    results = []
    df = df.dropna(subset=[col_cve])
    grouped = df.groupby(col_cve, sort=False)

    for cve_id, group in grouped:
        repo_info = repo_map.get(cve_id, {})
        owner = repo_info.get("owner", "unknown")
        repo_name = repo_info.get("repo_name", "unknown")

        version_pairs = []
        rows = group.to_dict('records')

        for i in range(len(rows) - 1):
            curr_row = rows[i]
            next_row = rows[i+1]

            base_ver = str(curr_row[col_ver])
            head_ver = str(next_row[col_ver])
            res_base = curr_row[col_result]
            res_head = next_row[col_result]
            
            # 获取 Cause 内容 (如果列不存在则返回空字符串)
            cause_base = str(curr_row.get(col_cause, "")) if not pd.isna(curr_row.get(col_cause)) else ""
            cause_head = str(next_row.get(col_cause, "")) if not pd.isna(next_row.get(col_cause)) else ""

            pair_entry = {}

            # 情况 A: 上方触发，下方不触发 -> 检查下方的编译状态
            if is_poc_success(res_base) and is_poc_fail(res_head):
                is_compile = get_compile_status(res_head)
                pair_entry = {
                    "appears": base_ver,
                    "not appears": head_ver,
                    "BASE_TAG": base_ver,
                    "HEAD_TAG": head_ver,
                    "seek_patch": True,
                    "compile": is_compile
                }
                if not is_compile:
                    pair_entry["cause"] = cause_head

            # 情况 B: 上方不触发，下方触发 -> 检查上方的编译状态
            elif is_poc_fail(res_base) and is_poc_success(res_head):
                is_compile = get_compile_status(res_base)
                pair_entry = {
                    "appears": head_ver,
                    "not appears": base_ver,
                    "BASE_TAG": base_ver,
                    "HEAD_TAG": head_ver,
                    "seek_patch": False,
                    "compile": is_compile
                }
                if not is_compile:
                    pair_entry["cause"] = cause_base

            if pair_entry:
                version_pairs.append(pair_entry)

        if version_pairs:
            results.append({
                "CVE_ID": cve_id,
                "owner": owner,
                "repo_name": repo_name,
                "version_pair": version_pairs
            })

    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"处理完成！当 compile 为 false 时，已自动添加 cause 字段。")

if __name__ == "__main__":
    version_verify()