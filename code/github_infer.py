import json
import os
import re
import subprocess
import pandas as pd
import glob
import requests
from llm import Client
# 从 settings 加载路径配置
from settings import EXCEL_FILE, PATCH_INFO_DIR, BASIC_INFO_DIR, CVE_LIST_FILE, REPO_DIR

# GitHub API 配置：使用环境变量，提高安全性
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else "",
    "Accept": "application/vnd.github.v3+json"
}

os.makedirs(BASIC_INFO_DIR, exist_ok=True)

# 加载 CVE 仓库映射关系 (包含 OWNER 和 REPO)
if os.path.exists(CVE_LIST_FILE):
    with open(CVE_LIST_FILE, 'r', encoding='utf-8') as f:
        CVE_MAP = json.load(f)
else:
    CVE_MAP = {}
    print(f"[!] Warning: CVE mapping file not found at {CVE_LIST_FILE}")

def get_commits_from_pr(owner, repo, pull_number):
    """Fetch the latest commit SHA from a GitHub Pull Request"""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/commits"
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        if res.status_code == 200:
            commits = res.json()
            if commits: return commits[-1].get('sha')
    except Exception: pass
    return None

def get_issue_details_via_api(owner, repo, issue_number):
    """Fetch version (from milestone), labels, and body from a GitHub Issue"""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        if res.status_code == 200:
            data = res.json()
            milestone_version = data.get('milestone', {}).get('title') if data.get('milestone') else None
            labels = [l.get('name') for l in data.get('labels', [])]
            body = data.get('body', '')
            return milestone_version, labels, body
    except Exception: pass
    return None, [], ""

def get_commit_details_via_api(owner, repo, sha):
    """Fetch commit details including modified files and patch content"""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=15)
        if res.status_code == 200:
            data = res.json()
            files = [f['filename'] for f in data.get('files', [])]
            patch_content = "\n".join([f.get('patch', '') for f in data.get('files', []) if 'patch' in f])
            return files, patch_content
    except Exception: pass
    return [], ""

def get_first_tag_from_git(repo_name, commit_sha):
    """Find the earliest git tag that contains the specified commit"""
    if not repo_name or not commit_sha: return None
    repo_path = os.path.join(REPO_DIR, repo_name)
    if not os.path.exists(repo_path): return None
    try:
        cmd = ["git", "tag", "--contains", commit_sha]
        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, check=True)
        tags = [t.strip() for t in result.stdout.split('\n') if t.strip()]
        if not tags: return None
        def version_sorter(tag):
            nums = re.findall(r'\d+', tag)
            return [int(n) for n in nums] if nums else [0]
        return sorted(tags, key=version_sorter)[0]
    except Exception: return None

def build_flexible_regex(raw_version):
    """Convert version string into a flexible regex for Excel matching"""
    if not raw_version or raw_version == "Unknown": return None
    segments = re.findall(r'\d+', str(raw_version))
    if not segments: return None
    inner_pattern = r"[._-]".join(segments[:3])
    return rf"{inner_pattern}(?!\d)"

def process_single_cve(cve_id, df, llm_client):
    json_path = os.path.join(PATCH_INFO_DIR, f"{cve_id}.json")
    if not os.path.exists(json_path): return

    repo_info = CVE_MAP.get(cve_id, {})
    repo_name, owner = repo_info.get("REPO"), repo_info.get("OWNER")
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    items = data.get("results", data.get("findings", []))
    output_results = []

    print(f"[*] Processing {cve_id}...")

    for item in items:
        url = item.get("url", "")
        initial_content = item.get("content", "")
        if not url or "advisories" in url: continue

        commit_sha = None
        raw_version = None
        issue_labels = []
        issue_body = ""

        # 1. Identify URL Type and Extract Data
        sha_match = re.search(r"commit/([a-f0-9]{7,40})", url)
        if sha_match:
            commit_sha = sha_match.group(1)
        elif "issues/" in url:
            issue_match = re.search(r"issues/(\d+)", url)
            if issue_match and owner and repo_name:
                raw_version, issue_labels, issue_body = get_issue_details_via_api(owner, repo_name, issue_match.group(1))
        else:
            pr_match = re.search(r"pull/(\d+)", url)
            if pr_match and owner and repo_name:
                commit_sha = get_commits_from_pr(owner, repo_name, pr_match.group(1))

        # 2. Version Identification (Milestone > Git Tag > Regex)
        if not raw_version and commit_sha and repo_name:
            raw_version = get_first_tag_from_git(repo_name, commit_sha)
        
        if not raw_version:
            ver_candidates = [v for v in re.findall(r"(\d+\.\d+\.\d+(?:\.[\w\d]+)?)", initial_content) if v != "1.1.1"]
            raw_version = max(ver_candidates, key=len) if ver_candidates else "Unknown"

        # 3. Decision Logic (Vulnerability Introduction vs Patch)
        type_found = "unmatched"
        flexible_regex = build_flexible_regex(raw_version)
        if flexible_regex:
            match_indices = df[(df['CVE_ID'] == cve_id) & (df['Version'].str.contains(flexible_regex, regex=True, na=False))].index
            if not match_indices.empty:
                idx = match_indices[0]
                curr_status = str(df.loc[idx, 'Execution Result']).upper()
                if "APPEARS" in curr_status:
                    # Maintain 'patch' if the previous status was also 'APPEARS'
                    if idx > 0 and "APPEARS" not in str(df.loc[idx - 1, 'Execution Result']).upper():
                        type_found = "vulnerability_introduction"
                    elif idx == 0:
                        type_found = "vulnerability_introduction"
                    else:
                        type_found = "patch"
                else:
                    type_found = "patch"

        result_entry = {
            "url": url,
            "hash": commit_sha,
            "detected_version": raw_version,
            "type": type_found,
            "modified_files": [],
            "analysis": ""
        }

        # 4. LLM Analysis & File Extraction
        if type_found == "patch" or "issues/" in url:
            api_files, api_patch = ([], "")
            if commit_sha and owner and repo_name:
                api_files, api_patch = get_commit_details_via_api(owner, repo_name, commit_sha)

            # Filter files: .java only, no 'test', strip path prefix
            java_files = [os.path.basename(f) for f in api_files if f.endswith('.java') and "test" not in f.lower()]
            result_entry["modified_files"] = sorted(list(set(java_files)))
            
            # Construct English Prompt with < 100 words constraint
            if "issues/" in url:
                prompt = (
                    "Analyze the following GitHub issue and provide a concise summary within 100 words. "
                    "Focus on the vulnerability root cause or the fix logic.\n"
                    f"Labels: {issue_labels}\nBody: {issue_body[:3000]}"
                )
            else:
                analysis_text = api_patch if api_patch else initial_content
                prompt = (
                    f"Analyze the patch logic for these files: {result_entry['modified_files']}. "
                    "Provide a concise summary within 100 words focusing on what was fixed.\n"
                    f"Content snippet: {analysis_text[:2000]}"
                )
            
            result_entry["analysis"] = llm_client.call_llm(prompt)

        output_results.append(result_entry)
        print(f"    - Version: {raw_version} | Type: {type_found} | Files: {len(result_entry['modified_files'])}")

    # Save to BASIC_INFO_DIR
    out_file = os.path.join(BASIC_INFO_DIR, f"{cve_id}.json")
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump({"cve_id": cve_id, "findings": output_results}, f, indent=4, ensure_ascii=False)

def main():
    if not os.path.exists(EXCEL_FILE):
        print(f"[-] Error: Excel file {EXCEL_FILE} not found.")
        return
    
    # Pre-load Excel Data
    df = pd.read_excel(EXCEL_FILE)
    df['Version'] = df['Version'].astype(str).str.strip()
    df['CVE_ID'] = df['CVE_ID'].astype(str).str.strip()
    
    llm_client = Client()

    # Full batch processing of all JSON files in PATCH_INFO_DIR
    json_files = glob.glob(os.path.join(PATCH_INFO_DIR, "*.json"))
    print(f"[*] Starting batch processing for {len(json_files)} CVEs...")

    for file_path in json_files:
        cve_id = os.path.basename(file_path).replace(".json", "")
        try:
            process_single_cve(cve_id, df, llm_client)
        except Exception as e:
            print(f"    [!] Error processing {cve_id}: {e}")

if __name__ == "__main__":
    main()