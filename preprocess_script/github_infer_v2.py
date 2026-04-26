import json
import os
import re
import subprocess
import pandas as pd
import glob
import requests
from datetime import datetime
from llm import Client
from utils import get_release_history, normalize_version
from settings import EXCEL_FILE, PATCH_INFO_DIR, BASIC_INFO_DIR, CVE_LIST_FILE, REPO_DIR

# --- 配置 ---
DISCLOSED_VERSION_FILE = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/PoCEmpirical/reproduce/disclosed-version.txt"

IGNORE_SET = {
    '.md', '.adoc', '.gitignore', '.gitattributes', 
    '.classpath', '.x', 'VERSION', 'CREDITS', '.gradle', 
    '.html', '.xml', '.yml', '.yaml', '.properties', '.vm', 'bazel'
}

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else "",
    "Accept": "application/vnd.github.v3+json"
}

os.makedirs(BASIC_INFO_DIR, exist_ok=True)

if os.path.exists(CVE_LIST_FILE):
    with open(CVE_LIST_FILE, 'r', encoding='utf-8') as f:
        CVE_MAP = json.load(f)
else:
    CVE_MAP = {}

# --- 辅助函数 ---

def get_maven_coords(cve_id):
    if not os.path.exists(DISCLOSED_VERSION_FILE): return None, None
    try:
        with open(DISCLOSED_VERSION_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                parts = line.strip().split('\t')
                if len(parts) >= 2 and parts[1] == cve_id:
                    coords = parts[0]
                    if ':' in coords:
                        g, a = coords.split(':', 1)
                        return g.strip(), a.strip()
    except Exception: pass
    return None, None

def get_commits_from_pr(owner, repo, pull_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/commits"
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        if res.status_code == 200: return res.json()
    except Exception: pass
    return []

def get_issue_details_via_api(owner, repo, number, is_pr=False):
    endpoint = "pulls" if is_pr else "issues"
    url = f"https://api.github.com/repos/{owner}/{repo}/{endpoint}/{number}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        if res.status_code == 200:
            data = res.json()
            milestone_v = data.get('milestone', {}).get('title') if data.get('milestone') else None
            labels = [l.get('name') for l in data.get('labels', [])]
            body = data.get('body', '') or ""
            ts = data.get('created_at')
            return milestone_v, labels, body, ts
    except Exception: pass
    return None, [], "", None

def get_commit_details_via_api(owner, repo, sha):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=15)
        if res.status_code == 200:
            data = res.json()
            files = []
            for f in data.get('files', []):
                fname = f['filename']
                if any(it in fname for it in IGNORE_SET): continue
                files.append(fname)
            patch = "\n".join([f.get('patch', '') for f in data.get('files', []) if 'patch' in f])
            return files, patch
    except Exception: pass
    return [], ""

def get_first_tag_from_git(repo_name, commit_sha):
    if not repo_name or not commit_sha: return None
    repo_path = os.path.join(REPO_DIR, repo_name)
    if not os.path.exists(repo_path): return None
    try:
        cmd = ["git", "tag", "--contains", commit_sha]
        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, check=True)
        tags = [t.strip() for t in result.stdout.split('\n') if t.strip()]
        if not tags: return None
        def v_sort(t):
            n = re.findall(r'\d+', t)
            return [int(x) for x in n] if n else [0]
        return sorted(tags, key=v_sort)[0]
    except Exception: return None

def build_flexible_regex(raw_v):
    if not raw_v or raw_v == "Unknown": return None
    seg = re.findall(r'\d+', str(raw_v))
    if not seg: return None
    inner = r"[._-]".join(seg[:3])
    return rf"{inner}(?!\d)"

# --- 核心逻辑 ---

def process_single_cve(cve_id, df, llm_client):
    # if cve_id != "CVE-2022-25914": return
    print(f"[*] Processing {cve_id}...")
    json_path = os.path.join(PATCH_INFO_DIR, f"{cve_id}.json")
    if not os.path.exists(json_path): return

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    findings = data.get("results", data.get("findings", []))
    repo_info = CVE_MAP.get(cve_id, {})
    repo_name, owner = repo_info.get("REPO"), repo_info.get("OWNER")
    group_id, artifact_id = get_maven_coords(cve_id)
    
    output_results = []

    for item in findings:
        url = item.get("url", "")
        initial_content = item.get("content", "")
        
        # 恢复过滤：跳过 advisories 链接
        if not url or "advisories" in url: continue

        sha_list = []
        base_v = None
        issue_labels, issue_body, api_ts = [], "", None
        is_pure_issue = False
        is_pr = False

        # 1. 链接类型识别
        sha_m = re.search(r"commit/([a-f0-9]{7,40})", url)
        if sha_m:
            sha_list = [sha_m.group(1)]
        elif "issues/" in url:
            m = re.search(r"issues/(\d+)", url)
            if m and owner and repo_name:
                base_v, issue_labels, issue_body, api_ts = get_issue_details_via_api(owner, repo_name, m.group(1))
                sha_list = [None]; is_pure_issue = True
        elif "pull/" in url:
            m = re.search(r"pull/(\d+)", url)
            if m and owner and repo_name:
                base_v, issue_labels, issue_body, api_ts = get_issue_details_via_api(owner, repo_name, m.group(1), is_pr=True)
                sha_list = [c.get('sha') for c in get_commits_from_pr(owner, repo_name, m.group(1)) if c.get('sha')]
                is_pr = True
        else:
            # 类似 releases/tag 的通用链接
            sha_list = [None]

        # 2. 版本匹配逻辑
        for current_sha in sha_list:
            raw_v = base_v
            
            # API 时间对比逻辑
            if not raw_v and api_ts and group_id and artifact_id:
                history = get_release_history(group_id, artifact_id)
                try:
                    target_dt = datetime.strptime(api_ts, '%Y-%m-%dT%H:%M:%SZ')
                    if is_pure_issue:
                        earlier = [h for h in history if h['release_date'].replace(tzinfo=None) < target_dt]
                        if earlier: raw_v = earlier[-1]['version']
                    elif is_pr:
                        later = [h for h in history if h['release_date'].replace(tzinfo=None) > target_dt]
                        if later: raw_v = later[0]['version']
                except: pass
            
            # Git Tag 兜底
            if not raw_v and current_sha and repo_name:
                raw_v = get_first_tag_from_git(repo_name, current_sha)
            
            # 通用链接版本识别：优先从 URL 提取（处理 releases/tag 情况）
            if not raw_v:
                url_ver_match = re.search(r"(?:tags?/|releases/tag/|archive/)([\d.]+)", url)
                if url_ver_match:
                    raw_v = url_ver_match.group(1).rstrip('.')
                else:
                    # 改进正则：排除 OID 干扰，只取 3-4 段数字
                    ver_cands = [v for v in re.findall(r"(?<![\d.])(\d+\.\d+\.\d+(?:\.\d+)?)(?![\d.])", initial_content) if v != "1.1.1"]
                    raw_v = max(ver_cands, key=len) if ver_cands else "Unknown"

            # 3. 类型判定
            type_found = "unmatched"
            clean_v = normalize_version(raw_v) if raw_v and raw_v != "Unknown" else raw_v
            flex_reg = build_flexible_regex(clean_v)
            
            if flex_reg:
                m_idx = df[(df['CVE_ID'] == cve_id) & (df['Version'].astype(str).str.contains(flex_reg, regex=True, na=False))].index
                if not m_idx.empty:
                    idx = m_idx[0]
                    res_val = str(df.loc[idx, 'Execution Result']).upper()
                    # 对于 Issue 或 Generic Release Link
                    if is_pure_issue or (not sha_m and not is_pr): 
                        if "APPEARS" in res_val: type_found = "vulnerability_exists"
                    else:
                        if "APPEARS" in res_val:
                            type_found = "vulnerability_introduction" if (idx == 0 or "APPEARS" not in str(df.loc[idx-1, 'Execution Result']).upper()) else "patch"
                        else: type_found = "patch"

            result_entry = {
                "url": url,
                "hash": current_sha,
                "detected_version": raw_v,
                "type": type_found,
                "labels": issue_labels,
                "body": issue_body,
                "modified_files": [],
                "analysis": ""
            }

            # 4. 内容总结与分析 (强制执行)
            content_to_analyze = initial_content
            if current_sha:
                api_fs, api_p = get_commit_details_via_api(owner, repo_name, current_sha)
                java_fs = [os.path.basename(f) for f in api_fs if f.endswith('.java') and "test" not in f.lower()]
                result_entry["modified_files"] = sorted(list(set(java_fs)))
                if api_p: content_to_analyze = api_p
            
            if content_to_analyze:
                prompt = f"Summarize security info for {cve_id} from this content ({url}). Content: {content_to_analyze[:3000]}"
                result_entry["analysis"] = llm_client.call_llm(prompt)

            output_results.append(result_entry)

    out_file = os.path.join(BASIC_INFO_DIR, f"{cve_id}.json")
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump({"cve_id": cve_id, "findings": output_results}, f, indent=4, ensure_ascii=False)

def main():
    if not os.path.exists(EXCEL_FILE): return
    df = pd.read_excel(EXCEL_FILE)
    df['Version'] = df['Version'].astype(str).str.strip()
    df['CVE_ID'] = df['CVE_ID'].astype(str).str.strip()
    llm_client = Client()
    json_files = sorted(glob.glob(os.path.join(PATCH_INFO_DIR, "*.json")))
    for f_path in json_files:
        cve_id = os.path.basename(f_path).replace(".json", "")
        try:
            process_single_cve(cve_id, df, llm_client)
        except Exception: pass

if __name__ == "__main__":
    main()