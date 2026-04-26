import json
import requests
from bs4 import BeautifulSoup
import time
import os

def get_cwe_from_nvd(cve_id):
    """
    根据你提供的逻辑：通过 href 包含 'cwe.mitre.org' 定位 CWE
    并在控制台即时输出结果
    """
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 定位所有指向 mitre 的 CWE 链接
        cwe_links = soup.find_all('a', href=lambda href: href and "cwe.mitre.org" in href)
        
        for link in cwe_links:
            text = link.get_text(strip=True)
            if text.startswith("CWE-"):
                # 找到第一个符合格式的即返回
                print(f"  [√] {cve_id} -> {text}")
                return text
        
        print(f"  [-] {cve_id} -> 未发现有效 CWE")
        return "Unknown"

    except Exception as e:
        print(f"  [!] {cve_id} 请求失败: {str(e)}")
        return "Unknown"

def main():
    # 文件路径
    input_path = 'data/dataset_o.json'
    output_path = 'data/label.json'
    
    # 1. 读取原始数据
    if not os.path.exists(input_path):
        print(f"错误：找不到文件 {input_path}")
        return

    with open(input_path, 'r', encoding='utf-8') as f:
        dataset_o = json.load(f)

    # 2. 处理数据
    label_data = {}
    cwe_cache = {} # 缓存已爬取的 CVE，避免重复请求

    print(f"开始爬取 NVD 数据 (共 {len(dataset_o)} 条记录)...")
    print("-" * 50)

    for item in dataset_o:
        cve_id = item['cve_id']
        repo_name = item['repo_name']
        fix_commit = item['bug_fixing_commit']

        # 获取 CWE 信息
        if cve_id not in cwe_cache:
            cwe_cache[cve_id] = get_cwe_from_nvd(cve_id)
            # 延时 2 秒，保护 IP 不被封
            time.sleep(2)
        
        cwe_val = cwe_cache[cve_id]

        # 3. 构建嵌套字典结构
        # 结构: { repo_name: { cve_id: { cwe: "", fixing_commits: [] } } }
        if repo_name not in label_data:
            label_data[repo_name] = {}
        
        if cve_id not in label_data[repo_name]:
            label_data[repo_name][cve_id] = {
                "cwe": cwe_val,
                "fixing_commits": []
            }
        
        # 添加 commit 并去重
        if fix_commit not in label_data[repo_name][cve_id]["fixing_commits"]:
            label_data[repo_name][cve_id]["fixing_commits"].append(fix_commit)

    # 4. 写入 label.json
    os.makedirs('data', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(label_data, f, indent=4, ensure_ascii=False)

    print("-" * 50)
    print(f"处理完成！结果已保存至 {output_path}")

if __name__ == "__main__":
    main()