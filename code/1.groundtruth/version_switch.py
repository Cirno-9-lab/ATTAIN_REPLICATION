import json
import os
import requests
import re
import time

# --- 全局缓存，优化 API 效率 ---
TAGS_CACHE = {}

def get_repo_info_from_url(url):
    """解析仓库 URL"""
    if not url or "github.com" not in url or "unknown" in url.lower():
        return "unknown", "unknown"
    parts = url.strip("/").split("/")
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return "unknown", "unknown"

def get_github_tags(owner, repo, token):
    """调用 GitHub API 抓取 Tags"""
    if owner == "unknown" or repo == "unknown":
        return []
    
    cache_key = f"{owner}/{repo}"
    if cache_key in TAGS_CACHE:
        return TAGS_CACHE[cache_key]

    headers = {
        "Authorization": f"Bearer {token.strip()}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CVE-Link-Generator"
    }

    all_tags = []
    # 抓取多页以覆盖历史版本
    for page in range(1, 6):
        api_url = f"https://api.github.com/repos/{owner}/{repo}/tags"
        try:
            response = requests.get(api_url, headers=headers, params={"per_page": 100, "page": page}, timeout=10)
            if response.status_code != 200: break
            data = response.json()
            if not data: break
            all_tags.extend([tag['name'] for tag in data])
        except: break

    TAGS_CACHE[cache_key] = all_tags
    return all_tags

def match_best_tag(version_str, available_tags):
    """多格式兼容匹配逻辑：支持前缀补全、点号转下划线、严格边界匹配"""
    if not version_str or str(version_str).lower() == "unknown": return "unknown"
    
    dot_v = str(version_str)
    under_v = dot_v.replace(".", "_")
    # 针对不同库的常用前缀池
    prefixes = ["", "v", "REL", "release-", "wicket-", "XSTREAM_", "xstream-", "v_", "r"]
    
    for p in prefixes:
        if f"{p}{dot_v}" in available_tags: return f"{p}{dot_v}"
        if f"{p}{under_v}" in available_tags: return f"{p}{under_v}"

    # 严格边界正则匹配
    p_dot = re.compile(rf"{re.escape(dot_v)}(?![.\d_])")
    p_under = re.compile(rf"{re.escape(under_v)}(?![.\d_])")

    for tag in available_tags:
        if p_dot.search(tag) or p_under.search(tag):
            return tag
            
    return "unknown"

def main():
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("Error: GITHUB_TOKEN environment variable not found.")
        return

    script_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_dir = os.path.dirname(os.path.dirname(script_dir))
    
    ghrepo_path = os.path.join(workspace_dir, "dataset", "cve_ghrepo.json")
    critical_path = os.path.join(workspace_dir, "dataset", "cve_critical_version.json")
    output_path = os.path.join(workspace_dir, "dataset", "list", "cve_list.json")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(ghrepo_path, 'r', encoding='utf-8') as f:
        ghrepo_data = json.load(f)
    with open(critical_path, 'r', encoding='utf-8') as f:
        critical_data = json.load(f)

    results = {}

    for entry in critical_data:
        cve_id = entry.get("CVE_ID")
        repo_meta = ghrepo_data.get(cve_id, {})
        
        owner, repo = get_repo_info_from_url(repo_meta.get("github_url"))
        description = repo_meta.get("description") or entry.get("DESCRIPTION") or ""
        cwe_info = repo_meta.get("cwe") or []

        results[cve_id] = {
            "OWNER": owner,
            "REPO": repo,
            "description": description,
            "cwe": cwe_info,
            "version_pair": []
        }

        tags = get_github_tags(owner, repo, github_token)
        
        for pair in entry.get("version_pair", []):
            # 获取输入版本标签
            input_base = pair.get("BASE_TAG")
            input_head = pair.get("HEAD_TAG")
            
            # 标签匹配
            matched_base = match_best_tag(input_base, tags)
            matched_head = match_best_tag(input_head, tags)
            
            # 生成 Compare URL
            if matched_base != "unknown" and matched_head != "unknown" and owner != "unknown":
                url = f"https://github.com/{owner}/{repo}/compare/{matched_base}...{matched_head}"
            else:
                url = "unknown"

            # 组织 version_pair 输出内容，包含新增的 cause 字段
            results[cve_id]["version_pair"].append({
                "appears": pair.get("appears"),
                "not appears": pair.get("not appears"),
                "BASE_TAG": matched_base,
                "HEAD_TAG": matched_head,
                "COMPARE_URL": url,
                "seek_patch": pair.get("seek_patch"),
                "compile": pair.get("compile"),
                "cause": pair.get("cause", "")  # 获取 cause，缺省为空字符串
            })
        print(f"✓ Processed {cve_id}")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(f"\nCompleted! Generated cve_list.json in: {output_path}")

if __name__ == "__main__":
    main()