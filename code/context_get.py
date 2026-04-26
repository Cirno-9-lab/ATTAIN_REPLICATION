import requests
import os
import json
import base64
import re
import concurrent.futures
from typing import Optional, Dict, List, Any

# --- 全局配置 ---
TOKEN = os.getenv("GITHUB_TOKEN")
CONTEXT_LINES = 10
MAX_SEARCH_RADIUS = 50  # 限制上下文搜索最大行数，防止跨度过大
NUM_THREADS = 5         # 线程数

# 路径配置
try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    script_dir = os.getcwd()

workspace_dir = os.path.dirname(script_dir)
input_base_dir_asset = os.path.join(workspace_dir, "dataset", "commit_info")
output_base_dir = os.path.join(workspace_dir, "dataset", "commit_context")
CVE_LIST_PATH = os.path.join(workspace_dir, "dataset", "list", "cve_list.json")

os.makedirs(output_base_dir, exist_ok=True)

# --- 1. 极致精简：过滤与清洗工具 ---

def clean_code_line(line: str) -> str:
    """
    单词级（行内）剪枝：
    1. 移除行内块注释 /*...*/
    2. 移除行尾单行注释 //
    3. 严格保留左侧原始缩进
    """
    if not line.strip():
        return ""
        
    original_indent = len(line) - len(line.lstrip())
    indent_str = line[:original_indent]
    content = line.strip()
    
    # 移除行内的 /* ... */ (非贪婪匹配)
    content = re.sub(r'/\*.*?\*/', '', content)
    
    # 移除行尾的 // 注释 (保守策略：不破坏包含 URL 的字符串)
    if '//' in content and '"' not in content and "'" not in content:
        content = content.split('//')[0]
        
    content = content.strip()
    if content:
        return indent_str + content
    return ""

def is_code_line(content: str) -> bool:
    """
    行级（语法级）剪枝：
    过滤空行、纯注释行、import、package、孤立符号、日志等无效信息
    """
    stripped = content.strip()
    
    # 1. 过滤空行和多行注释延续符
    if not stripped or stripped.startswith(('//', '#', '/*', '*/', '*')):
        return False
        
    # 2. 过滤包声明和导入 (已按要求精简)
    if stripped.startswith(('import ', 'package ')):
        return False
        
    # 3. 过滤无意义的孤立语法符号和基础注解
    if stripped in ('{', '}', '};', '();', '@Override'):
        return False
        
    # 4. 过滤日志打印和调试输出
    if stripped.startswith(('logger.', 'log.', 'System.out.', 'System.err.', 
                            'trace(', 'debug(', 'info(', 'warn(', 'error(')):
        return False
        
    return True

# --- 2. 差异解析与 GitHub 交互 ---

def parse_all_hunks(patch: str) -> List[Dict[str, Any]]:
    """解析 Patch 中的所有 Hunk 块"""
    hunks = []
    pattern = re.compile(r"@@\s*-(\d+)(?:,(\d+))?\s*\+(\d+)(?:,(\d+))?\s*@@")
    parts = pattern.split(patch)
    for i in range(1, len(parts), 5):
        try:
            hunks.append({
                "base_start": int(parts[i]),
                "base_len": int(parts[i+1]) if parts[i+1] else 1,
                "head_start": int(parts[i+2]),
                "head_len": int(parts[i+3]) if parts[i+3] else 1,
                "body": parts[i+4]
            })
        except: continue
    return hunks

def get_smart_context(file_lines: List[str], target_line: int, direction: str) -> List[str]:
    """带有搜索半径限制的智能上下文提取，绝不使用注释填充"""
    if not file_lines: return []
    idx = max(0, min(target_line - 1, len(file_lines)))
    context = []
    
    if direction == "before":
        curr, searched = idx - 1, 0
        while curr >= 0 and len(context) < CONTEXT_LINES and searched < MAX_SEARCH_RADIUS:
            cleaned = clean_code_line(file_lines[curr])
            if is_code_line(cleaned):
                context.insert(0, f"  {curr+1:4}: {cleaned}")
            curr -= 1; searched += 1
    else: # after
        curr, searched = idx, 0
        while curr < len(file_lines) and len(context) < CONTEXT_LINES and searched < MAX_SEARCH_RADIUS:
            cleaned = clean_code_line(file_lines[curr])
            if is_code_line(cleaned):
                context.append(f"  {curr+1:4}: {cleaned}")
            curr += 1; searched += 1
    return context

def get_github_file(owner: str, repo: str, path: str, sha: str) -> List[str]:
    """从 GitHub 获取文件内容"""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={sha}"
    headers = {"Authorization": f"token {TOKEN}"} if TOKEN else {}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404: return []
        resp.raise_for_status()
        content = base64.b64decode(resp.json().get('content', '')).decode('utf-8', errors='replace')
        return content.splitlines()
    except: return []

def process_file_diff(owner: str, repo: str, f_info: Dict, sha: str) -> Optional[Dict]:
    """处理单个文件的 diff，执行双重剪枝"""
    path, patch = f_info.get('filename'), f_info.get('patch')
    if not path or not patch: return None
    
    # 过滤测试文件 (文件名过滤已在外部或此处执行)
    path_lower = path.lower()
    if '/test/' in path_lower or path_lower.endswith(('test.java', 'tests.java')):
        return None

    hunks = parse_all_hunks(patch)
    if not hunks: return None

    file_base = get_github_file(owner, repo, path, f"{sha}^")
    file_head = get_github_file(owner, repo, path, sha)

    deleted, added = [], []
    curr_base, curr_head = hunks[0]["base_start"], hunks[0]["head_start"]

    for line in patch.splitlines():
        if line.startswith('@@'):
            m = re.search(r"@@\s*-(\d+).*\+(\d+).*@@", line)
            if m: curr_base, curr_head = int(m.group(1)), int(m.group(2))
            continue
        if line.startswith(' '): curr_base += 1; curr_head += 1
        elif line.startswith('-'):
            cleaned = clean_code_line(line[1:])
            if is_code_line(cleaned): deleted.append(f"  {curr_base:4}: {cleaned}")
            curr_base += 1
        elif line.startswith('+'):
            cleaned = clean_code_line(line[1:])
            if is_code_line(cleaned): added.append(f"  {curr_head:4}: {cleaned}")
            curr_head += 1

    ctx_before = get_smart_context(file_base, hunks[0]["base_start"], "before")
    ctx_after = get_smart_context(file_head, hunks[-1]["head_start"] + hunks[-1]["head_len"], "after")
    
    # 针对被删除文件的补偿
    if not ctx_after and file_base:
        ctx_after = get_smart_context(file_base, hunks[-1]["base_start"] + hunks[-1]["base_len"], "after")

    # 如果过滤后内容为空，直接抛弃该文件数据
    if not deleted and not added and not ctx_before and not ctx_after: 
        return None
        
    return {"context_before": ctx_before, "modified_deleted_content": deleted, 
            "modified_added_content": added, "context_after": ctx_after}

# --- 3. 多线程任务分发 ---

def process_cve_group(thread_id: int, files_chunk: List[str], cve_meta: Dict):
    """线程执行函数"""
    for filename in files_chunk:
        cve_id = filename.replace(".json", "")
        meta = cve_meta.get(cve_id.upper()) or cve_meta.get(cve_id.lower())
        if not meta: continue

        owner, repo = meta["OWNER"], meta["REPO"]
        info_path = os.path.join(input_base_dir_asset, filename)
        
        try:
            with open(info_path, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)

            ranges = raw_data.get(cve_id, [])
            cve_combined_results = []

            for r_item in ranges:
                b_tag, h_tag = r_item.get('base_tag'), r_item.get('head_tag')
                range_sha_map = {}
                
                for sha, info in r_item.get('commit_info', {}).items():
                    file_map = {}
                    for f_info in info.get('files', []):
                        res = process_file_diff(owner, repo, f_info, sha)
                        if res: file_map[f_info['filename']] = res
                    if file_map: range_sha_map[sha] = file_map
                
                if range_sha_map:
                    cve_combined_results.append({"base_tag": b_tag, "head_tag": h_tag, "results": range_sha_map})

            if cve_combined_results:
                out_path = os.path.join(output_base_dir, f"{cve_id}.json")
                with open(out_path, 'w', encoding='utf-8') as f_out:
                    json.dump({cve_id: cve_combined_results}, f_out, indent=4, ensure_ascii=False)
                print(f"[Thread-{thread_id:02d}] Completed: {cve_id}")
        except Exception as e:
            print(f"[Thread-{thread_id:02d}] Error processing {cve_id}: {e}")

def main():
    if not os.path.exists(CVE_LIST_PATH):
        print(f"Error: {CVE_LIST_PATH} not found.")
        return

    with open(CVE_LIST_PATH, 'r', encoding='utf-8') as f:
        cve_meta = json.load(f)

    all_files = [f for f in os.listdir(input_base_dir_asset) if f.endswith(".json")]
    if not all_files:
        print("No input files found.")
        return

    # 均匀分配任务到 5 个线程
    k, m = divmod(len(all_files), NUM_THREADS)
    file_chunks = [all_files[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(NUM_THREADS)]

    print(f"Starting total processing ({len(all_files)} CVEs) with {NUM_THREADS} threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(process_cve_group, i+1, chunk, cve_meta) 
                   for i, chunk in enumerate(file_chunks) if chunk]
        concurrent.futures.wait(futures)
                
    print("=== All Tasks Finished ===")

if __name__ == "__main__":
    main()