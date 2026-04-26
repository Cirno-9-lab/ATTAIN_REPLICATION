import json
import os
import subprocess

def get_git_describe(repo_path, commit_id):
    """切换到仓库目录执行 git describe --contains"""
    if not os.path.exists(repo_path):
        return f"Error: Repository path not found: {repo_path}"
    
    try:
        # 执行 git describe --contains {commit_id}
        result = subprocess.check_output(
            ['git', 'describe', '--contains', commit_id],
            cwd=repo_path,
            stderr=subprocess.STDOUT,
            text=True
        ).strip()
        return result
    except subprocess.CalledProcessError:
        # 如果 commit 没被包含在任何 tag 中
        return "no_tag_found"
    except Exception as e:
        return f"Error: {str(e)}"

def fetch_results():
    # 路径定义
    base_dir = os.getcwd()
    input_path = os.path.join(base_dir, 'dataset', 'dataset_o.json')
    logs_dir = os.path.join(base_dir, 'save_logs')
    repos_root = os.path.join(base_dir, 'result')
    output_path = os.path.join(base_dir, 'log', 'output.json')
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if not os.path.exists(input_path):
        print(f"Error: 找不到输入文件 {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        dataset = json.load(f)

    results = []

    for entry in dataset:
        repo_name = entry.get('repo_name')
        fixing_commit = entry.get('bug_fixing_commit')
        cve_id = entry.get('cve_id', 'N/A')  # 从 dataset_o.json 获取 cve_id
        repo_path = os.path.join(repos_root, repo_name)
        
        extracted_cids = []
        
        # 遍历 llm4szz0.json, llm4szz1.json, llm4szz2.json
        for i in range(3):
            file_name = f'llm4szz{i}.json'
            log_file_path = os.path.join(logs_dir, repo_name, fixing_commit, file_name)
            
            if os.path.exists(log_file_path):
                try:
                    with open(log_file_path, 'r', encoding='utf-8') as lf:
                        log_data = json.load(lf)
                        if not isinstance(log_data, list): continue
                        
                        file_cids = []
                        
                        # 1. 优先获取 s2_final_cid
                        found_s2 = False
                        for item in log_data:
                            if isinstance(item, dict) and 's2_final_cid' in item:
                                val = item.get('s2_final_cid')
                                if isinstance(val, list): file_cids.extend(val)
                                elif val: file_cids.append(val)
                                found_s2 = True
                        
                        # 2. 如果 s2 为空，则获取 s1_llm_file_final_cids
                        if not found_s2:
                            for item in log_data:
                                if isinstance(item, dict) and 's1_llm_file_final_cids' in item:
                                    val = item.get('s1_llm_file_final_cids')
                                    if isinstance(val, list): file_cids.extend(val)
                                    elif val: file_cids.append(val)
                        
                        extracted_cids.extend(file_cids)
                except Exception:
                    pass

        # 整理 CID：去重并过滤空内容
        unique_cids = list(dict.fromkeys([c for c in extracted_cids if c]))

        # 获取对应的 Git 版本信息
        vul_versions = []
        for cid in unique_cids:
            vul_versions.append(get_git_describe(repo_path, cid))

        # 构造最终输出条目，包含 cve_id
        results.append({
            "cve_id": cve_id,
            "repo_name": repo_name,
            "bug_fixing_commit": fixing_commit,
            "s2_final_cid": unique_cids,
            "vul_version": vul_versions
        })

    # 写入结果文件
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"任务处理完毕！")
    print(f"输入文件: {input_path}")
    print(f"已包含 CVE ID 并输出至: {output_path}")

if __name__ == "__main__":
    fetch_results()