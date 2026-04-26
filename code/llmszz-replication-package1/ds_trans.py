import os
import pandas as pd
import json
import requests
import re

# --- 目录配置 ---
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)           # .../llmszz-replication-package1/
code_dir = os.path.dirname(script_dir)             
workspace_dir = os.path.dirname(code_dir)          

# --- 输入/输出文件路径 ---
commit_file_path = os.path.join(workspace_dir, "dataset", "commit.xlsx")
output_dir = os.path.join(script_dir, "dataset")
output_json_path = os.path.join(output_dir, "dataset_o.json")

# 重要：result 文件夹的绝对路径
result_base_dir = os.path.join(script_dir, "result")

# --- GitHub API 配置 ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

def get_repo_folder_map(base_path):
    """
    1. 获取 result 目录下的一级子目录。
    2. 建立不区分大小写的映射。
    3. 如果文件夹为空，在控制台打印错误。
    """
    mapping = {}
    if not os.path.exists(base_path):
        print(f"错误: 找不到 result 根目录: {base_path}")
        return mapping

    for entry in os.listdir(base_path):
        full_path = os.path.join(base_path, entry)
        if os.path.isdir(full_path):
            # 检查文件夹是否为空
            if not os.listdir(full_path):
                print(f"错误: 文件夹为空 -> {full_path}")
            
            # 记录映射：小写键 -> 磁盘实际原始文件夹名
            mapping[entry.lower()] = entry
    return mapping

def parse_github_url(url, repo_mapping):
    """解析 URL，匹配 result 下的目录名，并获取 Commit SHA"""
    if pd.isna(url) or not isinstance(url, str):
        return None, []
    
    url = url.strip().split('?')[0].rstrip('/')
    # 提取 owner (group1) 和 repo_name (group2)
    match = re.search(r"github\.com/([^/]+)/([^/]+)", url)
    if not match:
        return None, []
    
    owner, raw_repo_name = match.groups()
    
    # 大小写不敏感匹配文件夹
    repo_lower = raw_repo_name.lower()
    if repo_lower in repo_mapping:
        final_repo_name = repo_mapping[repo_lower]
    else:
        print(f"提示: 未在 result 目录下找到匹配文件夹: {raw_repo_name}")
        return None, []

    commit_shas = []
    # A. 处理 Pull Request 情况
    if "/pull/" in url:
        pr_match = re.search(r"/pull/(\d+)", url)
        if pr_match:
            pr_num = pr_match.group(1)
            api_url = f"https://api.github.com/repos/{owner}/{raw_repo_name}/pulls/{pr_num}/commits"
            try:
                response = requests.get(api_url, headers=headers, timeout=15)
                if response.status_code == 200:
                    commit_shas = [c['sha'] for c in response.json()]
            except Exception as e:
                print(f"API 请求异常 ({url}): {e}")

    # B. 处理标准 Commit 情况
    elif "/commit/" in url:
        sha = url.split('/')[-1]
        if sha:
            commit_shas = [sha]

    return final_repo_name, commit_shas

def transform_data():
    os.makedirs(output_dir, exist_ok=True)
    repo_mapping = get_repo_folder_map(result_base_dir)
    
    fixed_inducing_commit = "ac1307abfe63ac93a9289e773116bb0de07c335b"
    dataset = []

    try:
        print(f"正在读取 Excel: {commit_file_path}")
        df_commit = pd.read_excel(commit_file_path)

        cols = df_commit.columns.tolist()
        cols_lower = [str(c).lower() for c in cols]
        target_col = "all_patch_urls"

        if target_col not in cols_lower:
            print(f"错误: commit.xlsx 中缺少 '{target_col}' 列")
            return
        
        start_idx = cols_lower.index(target_col)

        for _, row in df_commit.iterrows():
            cve_id = str(row['CVE_ID']).strip() if 'CVE_ID' in row else "Unknown"
            
            # 遍历从 All_patch_urls 开始的所有链接列
            for col_name in cols[start_idx:]:
                url_val = row[col_name]
                if pd.isna(url_val): continue
                
                repo_name, shas = parse_github_url(url_val, repo_mapping)
                
                if repo_name and shas:
                    for sha in shas:
                        dataset.append({
                            "cve_id": cve_id,  # 新增 CVE_ID 字段
                            "repo_name": repo_name,
                            "bug_fixing_commit": sha,
                            "bug_inducing_commit": fixed_inducing_commit
                        })

        # 写入 JSON
        with open(output_json_path, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=4, ensure_ascii=False)
        
        print("-" * 30)
        print(f"执行完毕！结果保存至: {output_json_path}")
        print(f"成功提取记录数: {len(dataset)}")

    except Exception as e:
        print(f"处理过程中出错: {e}")

if __name__ == "__main__":
    transform_data()