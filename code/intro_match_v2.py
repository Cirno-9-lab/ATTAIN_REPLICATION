import os
import json
import subprocess

# --- 路径配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
PATCH_RESULTS_PATH = os.path.join(BASE_PATH, "result/patch_only_results.json")
REPOS_ROOT = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/llmszz-replication-package1/result"
OUTPUT_PATH = os.path.join(BASE_PATH, "intro_url.json")

def get_git_commits(repo_path, base_tag, head_tag, files, owner, repo_name):
    """通过 Git Log 筛选受影响的 commits - 基于文件名匹配"""
    if not os.path.exists(repo_path):
        return []

    # 提取所有目标文件名
    target_filenames = set()
    for file_path in files:
        filename = os.path.basename(file_path)
        target_filenames.add(filename)
    
    if not target_filenames:
        return []

    unique_commits = {}
    commit_matched_files = {}  # 记录每个commit匹配的文件名
    try:
        # 获取所有commits及其修改的文件列表
        cmd = [
            "git", "-C", repo_path, "log", 
            f"{base_tag}..{head_tag}", 
            "--pretty=format:%H",
            "--name-only"
        ]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8')
        
        current_sha = None
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            
            # 如果是SHA（40个字符的十六进制字符串）
            if len(line) == 40 and all(c in '0123456789abcdef' for c in line.lower()):
                current_sha = line
            # 如果是文件路径
            elif current_sha and line:
                # 检查文件名是否匹配
                filename = os.path.basename(line)
                if filename in target_filenames:
                    if current_sha not in unique_commits:
                        unique_commits[current_sha] = {
                            "sha": current_sha,
                            "url": f"https://api.github.com/repos/{owner}/{repo_name}/commits/{current_sha}"
                        }
                        commit_matched_files[current_sha] = set()
                    commit_matched_files[current_sha].add(filename)
    except Exception:
        pass
    
    # 添加匹配的文件名字段
    result = []
    for sha, commit_info in unique_commits.items():
        commit_info["matched_files"] = sorted(list(commit_matched_files.get(sha, [])))
        result.append(commit_info)
            
    return result

def main():
    # 1. 加载配置数据
    with open(CVE_LIST_PATH, 'r') as f:
        cve_list = json.load(f)
    with open(PATCH_RESULTS_PATH, 'r') as f:
        patch_results = json.load(f)

    final_output = {}

    # 2. 遍历所有 CVE
    for cve_id, cve_info in cve_list.items():
        owner = cve_info.get("OWNER")
        repo_name = cve_info.get("REPO")
        repo_path = os.path.join(REPOS_ROOT, repo_name)
        
        cve_results = []

        # 3. 提取版本对并过滤
        for vp in cve_info.get("version_pair", []):
            base_tag = vp.get("BASE_TAG")
            head_tag = vp.get("HEAD_TAG")

            # 过滤逻辑：seek_patch 必须为 False，且 tag 不能为 unknown
            if vp.get("seek_patch") is not False:
                continue
            if not base_tag or not head_tag or "unknown" in base_tag.lower() or "unknown" in head_tag.lower():
                continue

            # 4. 获取锚点文件 (verdict: yes)
            anchor_files = []
            if cve_id in patch_results:
                for patch_entry in patch_results[cve_id]:
                    analysis = patch_entry.get("analysis", {})
                    for p_sha, files_info in analysis.items():
                        for f_path, f_info in files_info.items():
                            if f_info.get("verdict") == "yes":
                                anchor_files.append(f_path)
            
            anchor_files = list(set(anchor_files))

            # 5. 跨版本 Git 比对
            commits = []
            if anchor_files:
                commits = get_git_commits(repo_path, base_tag, head_tag, anchor_files, owner, repo_name)

            # 6. 构造输出
            cve_results.append({
                "base_tag": base_tag,
                "head_tag": head_tag,
                "seek_patch": False,
                "commit": commits
            })

        if cve_results:
            final_output[cve_id.lower()] = cve_results

    # 7. 写入最终文件
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)
    
    print(f"处理完成。结果已保存至: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()