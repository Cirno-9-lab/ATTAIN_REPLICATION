import json
import os
import glob
import requests
from collections import Counter
from settings import BASIC_INFO_DIR, CVE_LIST_FILE

# GitHub API 配置
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else "",
    "Accept": "application/vnd.github.v3+json"
}

# --- 优化后的过滤配置 ---
# 不再区分后缀和全名，统一对文件名进行直接匹配
# 包含：.md, .adoc, .gitignore, .gitattributes, .classpath, .x, VERSION, CREDITS
IGNORE_SET = {
    '.md', '.adoc', '.gitignore', '.gitattributes', 
    '.classpath', '.x', 'VERSION', 'CREDITS','.gradle', '.html', '.xml', '.yml', '.yaml', '.properties', '.vm', 'bazel'
}

# 加载 CVE 仓库映射关系
if os.path.exists(CVE_LIST_FILE):
    with open(CVE_LIST_FILE, 'r', encoding='utf-8') as f:
        CVE_MAP = json.load(f)
else:
    CVE_MAP = {}

def get_commit_files_via_api(owner, repo, sha):
    """通过 GitHub API 获取提交关联的所有文件列表"""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=15)
        if res.status_code == 200:
            data = res.json()
            # 返回的是完整路径，如 "src/main/java/com/Example.java"
            return [f['filename'] for f in data.get('files', [])]
    except Exception as e:
        print(f"      [!] API Error for {sha}: {e}")
    return []

def main():
    suffix_stats = Counter()
    
    json_files = glob.glob(os.path.join(BASIC_INFO_DIR, "*.json"))
    print(f"[*] Starting batch processing for {len(json_files)} CVE files...")

    for file_path in json_files:
        cve_id = os.path.basename(file_path).replace(".json", "")
        repo_info = CVE_MAP.get(cve_id, {})
        owner, repo_name = repo_info.get("OWNER"), repo_info.get("REPO")

        if not owner or not repo_name:
            continue

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        findings = data.get("findings", [])
        is_updated = False

        print(f"[*] Processing {cve_id}...")
        for entry in findings:
            sha = entry.get("hash")
            if not sha:
                continue

            # 1. 获取原始文件完整路径列表
            raw_files = get_commit_files_via_api(owner, repo_name, sha)
            
            # 2. 执行过滤逻辑
            filtered_files = []
            for f in raw_files:
                filename = os.path.basename(f)
                
                # 筛选条件 A：路径不包含 test 或 Test
                if "test" in f.lower():
                    continue
                
                # 筛选条件 B：文件名不在忽略名单中 (解决 .gitignore 等解析问题)
                if filename in IGNORE_SET:
                    continue
                
                # 筛选条件 C：检查标准后缀（可选，作为双重保障）
                ext = os.path.splitext(f)[1].lower()
                if ext in IGNORE_SET:
                    continue
                
                filtered_files.append(f)
            
            # 3. 更新 entry (存储过滤后的文件名，非完整路径)
            entry["modified_files"] = [os.path.basename(f) for f in filtered_files]
            is_updated = True

            # 4. 统计分析
            for f in filtered_files:
                ext_stat = os.path.splitext(f)[1].lower() or "no_extension"
                suffix_stats[ext_stat] += 1

        # 5. 原地保存修改后的 JSON
        if is_updated:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

    # --- 统计分析结果输出 ---
    print("\n" + "="*45)
    print("FINAL FILE EXTENSION ANALYSIS")
    print(f"Excluded Patterns: {IGNORE_SET}")
    print("Keyword Filter   : 'test' (case-insensitive)")
    print("="*45)
    
    if not suffix_stats:
        print("No files matched the criteria.")
    else:
        for ext, count in suffix_stats.most_common():
            label = ext if ext != 'no_extension' else "[No Extension]"
            print(f"{label:<25} : {count}")
    print("="*45)

if __name__ == "__main__":
    main()