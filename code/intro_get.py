import os
import json
import re
import concurrent.futures
from git import Repo
from typing import Optional, Dict, List, Any

# --- 路径配置 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
INTRO_URL_PATH = os.path.join(BASE_PATH, "intro_url.json")
# 输出到 dataset/intro_context.json
OUTPUT_PATH = os.path.join(BASE_PATH, "intro_context.json")
# 本地仓库根目录
REPOS_ROOT = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/llmszz-replication-package1/result"

# --- 提取参数 ---
CONTEXT_LINES = 10
MAX_SEARCH_RADIUS = 50
NUM_THREADS = 8

# --- 1. 核心过滤与编码清洗工具 ---

def clean_surrogates(text: str) -> str:
    """清理 Python 无法处理的代理项字符，防止 JSON 导出报错"""
    return text.encode('utf-8', 'ignore').decode('utf-8', 'ignore')

def clean_code_line(line: str) -> str:
    """行内剪枝：移除注释并保留原始缩进"""
    if not line.strip(): return ""
    # 保留缩进
    original_indent = len(line) - len(line.lstrip())
    indent_str = line[:original_indent]
    content = line.strip()
    
    # 移除块注释 /*...*/ 
    content = re.sub(r'/\*.*?\*/', '', content)
    # 移除行尾单行注释 // (简单处理，不破坏字符串内的 //)
    if '//' in content and not any(q in content for q in ['"', "'"]):
        content = content.split('//')[0]
    
    content = content.strip()
    return indent_str + content if content else ""

def is_code_line(content: str) -> bool:
    """行级剪枝：过滤掉无业务逻辑意义的行"""
    stripped = content.strip()
    # 过滤空行和纯注释行
    if not stripped or stripped.startswith(('//', '#', '/*', '*/', '*')): 
        return False
    # 过滤包和导入
    if stripped.startswith(('import ', 'package ')): 
        return False
    # 过滤孤立的语法符号和基础注解
    if stripped in ('{', '}', '};', '();', '@Override'): 
        return False
    # 过滤日志
    if any(stripped.startswith(log) for log in ['logger.', 'log.', 'System.out.', 'debug(', 'info(', 'warn(']):
        return False
    return True

# --- 2. Git 操作与上下文提取 ---

def get_local_file_content(repo: Repo, path: str, commit_sha: str) -> List[str]:
    """从本地仓库读取特定版本的文件内容"""
    try:
        content = repo.git.show(f"{commit_sha}:{path}")
        return content.splitlines()
    except Exception:
        return []

def get_smart_context(file_lines: List[str], target_line: int, direction: str) -> List[str]:
    """智能搜索非注释的有效代码行作为上下文"""
    if not file_lines: return []
    idx = max(0, min(target_line - 1, len(file_lines)))
    context = []
    
    curr = (idx - 1 if direction == "before" else idx)
    searched = 0
    
    while 0 <= curr < len(file_lines) and len(context) < CONTEXT_LINES and searched < MAX_SEARCH_RADIUS:
        raw_line = file_lines[curr]
        cleaned = clean_code_line(raw_line)
        if is_code_line(cleaned):
            # 格式化输出，带行号
            formatted = f"   {curr+1:4}: {cleaned}"
            if direction == "before":
                context.insert(0, formatted)
            else:
                context.append(formatted)
        curr = (curr - 1 if direction == "before" else curr + 1)
        searched += 1
    return context

def process_single_commit(repo: Repo, sha: str) -> Optional[Dict]:
    """处理单个 SHA，提取 message 和所有文件的变更详情"""
    try:
        commit_obj = repo.commit(sha)
        # 获取首行 message 并清洗非法字符
        raw_msg = commit_obj.message.strip().split('\n')[0]
        message = clean_surrogates(raw_msg)
        
        # 获取与父节点的差异
        parent = commit_obj.parents[0] if commit_obj.parents else None
        if not parent: return None
        
        diffs = parent.diff(commit_obj, create_patch=True)
        files_data = {}

        for d in diffs:
            path = d.b_path
            # 过滤测试和非代码文件
            if not path or any(k in path.lower() for k in ['test', 'benchmark', 'example']):
                continue
            
            # 检查后缀
            if not path.endswith(('.java', '.c', '.cpp', '.h', '.py', '.js')):
                continue

            patch_text = d.diff.decode('utf-8', errors='ignore')
            file_base = get_local_file_content(repo, path, f"{sha}^")
            file_head = get_local_file_content(repo, path, sha)
            
            deleted, added = [], []
            curr_base, curr_head = 0, 0
            first_hunk_start = None

            for line in patch_text.splitlines():
                if line.startswith('@@'):
                    m = re.search(r"-(\d+).*\+(\d+)", line)
                    if m: 
                        curr_base, curr_head = int(m.group(1)), int(m.group(2))
                        if first_hunk_start is None: first_hunk_start = curr_base
                    continue
                
                if line.startswith(' '):
                    curr_base += 1
                    curr_head += 1
                elif line.startswith('-'):
                    cleaned = clean_code_line(line[1:])
                    if is_code_line(cleaned):
                        deleted.append(f"   {curr_base:4}: {cleaned}")
                    curr_base += 1
                elif line.startswith('+'):
                    cleaned = clean_code_line(line[1:])
                    if is_code_line(cleaned):
                        added.append(f"   {curr_head:4}: {cleaned}")
                    curr_head += 1

            if deleted or added:
                files_data[path] = {
                    "context_before": get_smart_context(file_base, first_hunk_start or 1, "before"),
                    "modified_deleted_content": [clean_surrogates(l) for l in deleted],
                    "modified_added_content": [clean_surrogates(l) for l in added],
                    "context_after": get_smart_context(file_head, curr_head, "after")
                }
        
        return {"message": message, "files": files_data} if files_data else None
    except Exception:
        return None

# --- 3. 任务分发主逻辑 ---

def process_cve_task(cve_id: str, entries: List[Dict]) -> (str, List[Dict]):
    """处理单个 CVE 编号下的所有 entries"""
    try:
        # 从第一个 commit URL 解析 repo 文件夹名
        sample_url = entries[0]['commit'][0]['url']
        repo_name = sample_url.split('/')[-3]
        repo_path = os.path.join(REPOS_ROOT, repo_name)
        
        if not os.path.exists(repo_path):
            return cve_id, []
            
        repo = Repo(repo_path)
    except:
        return cve_id, []

    processed_entries = []
    for entry in entries:
        new_entry = {
            "base_tag": entry.get("base_tag"),
            "head_tag": entry.get("head_tag"),
            "results": {}
        }
        for c_obj in entry.get("commit", []):
            sha = c_obj['sha']
            res = process_single_commit(repo, sha)
            if res:
                new_entry["results"][sha] = res
        
        if new_entry["results"]:
            processed_entries.append(new_entry)
            
    return cve_id, processed_entries

def main():
    if not os.path.exists(INTRO_URL_PATH):
        print(f"Error: 找不到输入文件 {INTRO_URL_PATH}")
        return

    with open(INTRO_URL_PATH, 'r', encoding='utf-8') as f:
        url_data = json.load(f)

    final_context = {}
    print(f"开始处理 {len(url_data)} 个 CVE 条目...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        future_to_cve = {executor.submit(process_cve_task, cid, ent): cid for cid, ent in url_data.items()}
        for future in concurrent.futures.as_completed(future_to_cve):
            cid, result = future.result()
            if result:
                final_context[cid] = result
                print(f"  [OK] {cid}")

    # 关键修复：增加 errors='replace' 防止 UnicodeEncodeError
    with open(OUTPUT_PATH, 'w', encoding='utf-8', errors='replace') as f:
        json.dump(final_context, f, indent=4, ensure_ascii=False)
    
    print(f"\n全部处理完成！\n结果已保存至: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()