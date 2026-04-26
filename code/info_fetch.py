import os
import json
import requests
import re
from glob import glob
import time
from threading import Thread

# ----------------------------------------------------------------------
# 1. 路径设置
# ----------------------------------------------------------------------
script_dir = os.path.dirname(os.path.abspath(__file__))
workspace_dir = os.path.dirname(script_dir)

INPUT_DIR = os.path.join(workspace_dir, "dataset", "commit_url")
OUTPUT_DIR = os.path.join(workspace_dir, "dataset", "commit_info")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ----------------------------------------------------------------------
# 2. GitHub API 配置
# ----------------------------------------------------------------------
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {"Accept": "application/vnd.github.v3+json"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

# ----------------------------------------------------------------------
# 3. V7 终极过滤正则表达式
# ----------------------------------------------------------------------
EXCLUDE_PATTERN = re.compile(
    # 关键字排除：包含 test, release, version 等关键词的路径或文件名
    r'test|mock|stub|release|version|changelog|readme|' 
    # 后缀排除：资源文件、XML、文档、IDE配置、静态资源、脚本
    r'\.(md|txt|css|js|html|xml|png|jpg|jpeg|gif|svg|ico|woff|'
    r'woff2|ttf|eot|iml|project|classpath|settings|ds_store|bak|'
    r'properties|yml|yaml|sh|bat|lock)$|'
    # 特定文件排除：构建配置、授权文件、隐藏文件
    r'^pom\.xml$|^mvnw|^gradlew|^license|^notice|^\..*', 
    re.IGNORECASE
)

# ----------------------------------------------------------------------
# 4. 核心功能函数
# ----------------------------------------------------------------------
def fetch_commit_info(url):
    """带频率限制的 API 抓取"""
    time.sleep(0.1) 
    try:
        response = requests.get(url, headers=HEADERS, timeout=30)
        if response.status_code == 403: return None
        response.raise_for_status()
        return response.json()
    except Exception:
        return None

def filter_files(files_list):
    """过滤逻辑"""
    if not files_list: return []
    return [f for f in files_list if not EXCLUDE_PATTERN.search(f.get("filename", ""))]

def process_group(file_list, thread_id):
    """线程执行函数，带详细进度打印"""
    total_in_group = len(file_list)
    
    for idx, input_filepath in enumerate(file_list):
        filename = os.path.basename(input_filepath)
        match = re.match(r'(cve-\d{4}-\d+)\.json', filename)
        if not match: continue
        
        cve_id = match.group(1).lower()
        output_filepath = os.path.join(OUTPUT_DIR, filename)
        
        # --- 打印实时进度 ---
        print(f"[线程-{thread_id}] [{idx+1}/{total_in_group}] 正在处理: {cve_id}")
        
        try:
            with open(input_filepath, 'r', encoding='utf-8') as f:
                input_data = json.load(f)
            
            version_ranges = input_data.get(cve_id, []) or input_data.get(cve_id.upper(), [])
            if not isinstance(version_ranges, list): continue

            results_list = []
            for entry in version_ranges:
                base_tag = entry.get("base_tag")
                head_tag = entry.get("head_tag")
                commits = entry.get("commit", [])
                
                valid_commit_info = {}
                for c_item in commits:
                    sha = c_item.get("sha")
                    url = c_item.get("url")
                    
                    raw_info = fetch_commit_info(url)
                    if not raw_info: continue
                    
                    msg = raw_info.get("commit", {}).get("message", "")
                    files = raw_info.get("files", [])
                    filtered_files = filter_files(files)
                    
                    if filtered_files:
                        valid_commit_info[sha] = {
                            "message": msg,
                            "files": filtered_files
                        }

                if valid_commit_info:
                    results_list.append({
                        "base_tag": base_tag,
                        "head_tag": head_tag,
                        "commit_info": valid_commit_info
                    })

            if results_list:
                with open(output_filepath, 'w', encoding='utf-8') as f:
                    json.dump({cve_id: results_list}, f, ensure_ascii=False, indent=4)

        except Exception as e:
            print(f"[线程-{thread_id}] 错误 {cve_id}: {e}")

# ----------------------------------------------------------------------
# 5. 主程序：负载均衡与多线程调度
# ----------------------------------------------------------------------
def main():
    all_files = sorted(glob(os.path.join(INPUT_DIR, 'cve-*-*.json')))
    if not all_files:
        print("未找到输入文件。")
        return

    num_threads = 5
    avg = len(all_files) // num_threads
    
    threads = []
    print(f">>> 准备启动 {num_threads} 个线程处理共 {len(all_files)} 个 CVE 文件...\n")
    
    for i in range(num_threads):
        start = i * avg
        end = None if i == num_threads - 1 else (i + 1) * avg
        group = all_files[start:end]
        
        t = Thread(target=process_group, args=(group, i))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("\n>>> [所有任务处理完毕] 过滤后的数据已保存至 dataset/commit_info/")

if __name__ == '__main__':
    main()