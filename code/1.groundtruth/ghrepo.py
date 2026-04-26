import os
import re
import time
import json
import pandas as pd
import requests
from bs4 import BeautifulSoup

# --- 目录配置 ---
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path) 
code_dir = os.path.dirname(script_dir) 
workspace_dir = os.path.dirname(code_dir) 

# --- 输入/输出文件路径 ---
excel_file_path = os.path.join(workspace_dir, "dataset", "commit.xlsx")
output_json_path = os.path.join(workspace_dir, "dataset", "cve_ghrepo.json")

def validate_and_format_github_link(url):
    """验证并格式化 GitHub 链接"""
    if not isinstance(url, str) or not url.startswith("https://github.com"):
        return None, None, None

    pattern_format1 = re.compile(r"https://github\.com/([^/]+)/([^/]+)/(.+)")
    pattern_format2 = re.compile(r"https://github\.com/([^/]+)/([a-zA-Z0-9]+)$")

    m1 = pattern_format1.match(url)
    if m1:
        owner, repo = m1.group(1), m1.group(2)
        return f"https://github.com/{owner}/{repo}", owner, repo

    m2 = pattern_format2.match(url)
    if m2:
        owner, repo = m2.group(1), m2.group(2)
        return f"https://github.com/{owner}/{repo}", owner, repo

    return None, None, None

def get_nvd_data(cve_id):
    """从 NVD 获取 Description, GitHub 链接以及 CWE 信息"""
    cve_id_upper = cve_id.upper()
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id_upper}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    data = {
        "description": "unknown",
        "cwe": [],
        "github_info": None
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. 抓取 Description
            desc_tag = soup.find('p', {'data-testid': 'vuln-description'})
            if desc_tag:
                data["description"] = desc_tag.get_text().strip()

            # 2. 抓取 CWE (通常在 vulnTechnicalDetailsPanel 下的表格中)
            cwe_table = soup.find('table', {'data-testid': 'vuln-technical-details-table'})
            if cwe_table:
                # 寻找所有包含 CWE- 的链接或文本
                cwe_links = cwe_table.find_all('a', href=re.compile(r'cwe/detail/'))
                cwe_list = list(set([link.get_text().strip() for link in cwe_links if "CWE-" in link.get_text()]))
                data["cwe"] = cwe_list

            # 3. 抓取 GitHub 链接
            ref_div = soup.find('div', id='vulnHyperlinksPanel')
            if ref_div:
                links = ref_div.find_all('a', href=True)
                for link_tag in links:
                    raw_url = link_tag['href']
                    if "google/security-research" in raw_url.lower():
                        continue
                    if "github.com" in raw_url.lower():
                        fmt_url, owner, repo = validate_and_format_github_link(raw_url)
                        if fmt_url:
                            data["github_info"] = {"github_url": fmt_url, "owner": owner, "repo": repo}
                            break
    except Exception:
        pass
    
    return data

def main():
    if not os.path.exists(excel_file_path):
        return

    try:
        df = pd.read_excel(excel_file_path)
    except Exception:
        return

    cve_col = next((c for c in df.columns if c.lower() == 'cve_id'), df.columns[0])
    url_col = next((c for c in df.columns if c.lower() == 'all_patch_urls'), df.columns[1])

    results_json = {}
    
    for _, row in df.iterrows():
        cve_id = str(row[cve_col]).strip()
        raw_content = str(row[url_col]).strip()
        
        if not cve_id or cve_id.lower() == 'nan' or not raw_content.lower().startswith("http"):
            continue

        final_entry = {
            "description": "unknown",
            "cwe": [],
            "github_url": "unknown",
            "owner": "unknown",
            "repo": "unknown"
        }

        # 获取 NVD 核心数据（Description + CWE + GitHub 保底）
        nvd_res = get_nvd_data(cve_id)
        final_entry["description"] = nvd_res["description"]
        final_entry["cwe"] = nvd_res["cwe"]

        # 处理 GitHub 链接逻辑
        if raw_content.startswith("https://bitbucket.org"):
            if nvd_res["github_info"]:
                final_entry.update(nvd_res["github_info"])
        else:
            potential_urls = re.split(r'[\n,\s]+', raw_content)
            found_local_gh = False
            for url in potential_urls:
                url = url.strip()
                fmt_url, owner, repo = validate_and_format_github_link(url)
                if fmt_url:
                    final_entry.update({"github_url": fmt_url, "owner": owner, "repo": repo})
                    found_local_gh = True
                    break
            
            # 如果本地没找到，用 NVD 的保底
            if not found_local_gh and nvd_res["github_info"]:
                final_entry.update(nvd_res["github_info"])

        results_json[cve_id] = final_entry
        time.sleep(2) # 统一延迟，遵守 NVD 速率限制

    try:
        with open(output_json_path, 'w', encoding='utf-8') as f:
            json.dump(results_json, f, indent=4, ensure_ascii=False)
        print(f"Success. File saved to: {output_json_path}")
    except Exception as e:
        print(f"Error saving file: {e}")

if __name__ == "__main__":
    main()