import os
import json
import re
import concurrent.futures
from git import Repo
from typing import Optional, Dict, List, Any, Tuple

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

# --- 筛选关键词配置 ---
# 这些关键词用于从commit消息中筛选相关的commits
MESSAGE_KEYWORDS = [
    "resources", "static", "handler", "mvc", "resource", 
    "security", "vulnerability", "fix", "bug", "patch",
    "validation", "sanitize", "check", "verify",
    # 新增关键词：数字处理、转换、解析相关
    "number", "decimal", "convert", "parse", "math",
    "overflow", "precision", "计算", "转换", "解析"
]

# 目标文件关键词（用于筛选修改的文件）
TARGET_FILE_KEYWORDS = [
    "Resource", "Handler", "Config", "Parser", "Resolver",
    "Security", "Validator", "Filter", "Interceptor",
    # 新增关键词：工具类、数字处理相关
    "Util", "Number", "Decimal", "Convert", "Math", "Calc"
]

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

def extract_commit_metadata(repo: Repo, sha: str) -> Optional[Dict]:
    """提取commit的基础信息（消息和修改文件列表）"""
    try:
        commit_obj = repo.commit(sha)
        raw_msg = commit_obj.message.strip().split('\n')[0]
        message = clean_surrogates(raw_msg)
        
        # 获取修改的文件列表
        parent = commit_obj.parents[0] if commit_obj.parents else None
        if not parent:
            return None
        
        diffs = parent.diff(commit_obj)
        modified_files = [d.b_path for d in diffs if d.b_path]
        
        return {
            "sha": sha,
            "message": message,
            "modified_files": modified_files
        }
    except Exception:
        return None

def calculate_relevance_score(commit_meta: Dict) -> Tuple[int, List[str], List[str]]:
    """
    计算commit的相关性分数
    
    返回: (分数, 匹配的消息关键词, 匹配的文件关键词)
    """
    message = commit_meta.get("message", "").lower()
    files = commit_meta.get("modified_files", [])
    
    score = 0
    matched_msg_keywords = []
    matched_file_keywords = []
    
    # 1. 根据commit消息关键词评分
    for keyword in MESSAGE_KEYWORDS:
        if keyword.lower() in message:
            score += 1
            matched_msg_keywords.append(keyword)
    
    # 2. 根据修改的文件评分
    for file_path in files:
        file_lower = file_path.lower()
        # 过滤测试文件
        if any(k in file_lower for k in ['test', 'benchmark', 'example']):
            continue
        # 检查文件名是否包含目标关键词
        for keyword in TARGET_FILE_KEYWORDS:
            if keyword.lower() in file_lower:
                if keyword not in matched_file_keywords:
                    score += 2  # 文件匹配权重更高
                    matched_file_keywords.append(keyword)
    
    return score, matched_msg_keywords, matched_file_keywords

def filter_commits(repo: Repo, sha_list: List[str]) -> List[Dict]:
    """
    筛选相关commits
    
    返回: 筛选后的commits列表（按相关性排序），包含每个commit的相关性分析
    """
    print(f"    开始筛选 {len(sha_list)} 个 commits...")
    
    candidates = []
    
    # 提取所有commit的元数据
    for sha in sha_list:
        meta = extract_commit_metadata(repo, sha)
        if not meta:
            continue
        
        score, msg_keywords, file_keywords = calculate_relevance_score(meta)
        
        # 只保留有一定相关性的commits（分数 > 0）
        if score > 0:
            candidates.append({
                "sha": sha,
                "message": meta["message"],
                "modified_files": meta["modified_files"],
                "relevance_score": score,
                "matched_message_keywords": msg_keywords,
                "matched_file_keywords": file_keywords
            })
    
    # 按相关性分数排序（降序）
    candidates.sort(key=lambda x: x["relevance_score"], reverse=True)
    
    print(f"    筛选完成：找到 {len(candidates)} 个候选 commits")
    for i, c in enumerate(candidates[:5], 1):  # 显示前5个
        print(f"      [{i}] {c['sha'][:8]} - 分数:{c['relevance_score']} - {c['message'][:50]}")
    
    return candidates

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
        # 步骤1: 收集所有SHAs
        all_shas = [c_obj['sha'] for c_obj in entry.get("commit", [])]
        
        if not all_shas:
            continue
        
        print(f"\n处理 {cve_id}:")
        print(f"  总共 {len(all_shas)} 个 commits")
        
        # 步骤2: 筛选相关commits
        filtered_commits = filter_commits(repo, all_shas)
        
        if not filtered_commits:
            print(f"  未找到相关的 commits，跳过")
            continue
        
        # 步骤3: 只对筛选后的commits提取详细上下文
        new_entry = {
            "base_tag": entry.get("base_tag"),
            "head_tag": entry.get("head_tag"),
            "total_commits": len(all_shas),
            "filtered_commits_count": len(filtered_commits),
            "filter_summary": [
                {
                    "sha": c["sha"],
                    "message": c["message"],
                    "relevance_score": c["relevance_score"],
                    "matched_message_keywords": c["matched_message_keywords"],
                    "matched_file_keywords": c["matched_file_keywords"]
                }
                for c in filtered_commits
            ],
            "results": {}
        }
        
        # 提取筛选后commits的详细上下文
        for c in filtered_commits:
            sha = c["sha"]
            res = process_single_commit(repo, sha)
            if res:
                # 添加筛选信息到结果中
                res["filter_info"] = {
                    "relevance_score": c["relevance_score"],
                    "matched_message_keywords": c["matched_message_keywords"],
                    "matched_file_keywords": c["matched_file_keywords"]
                }
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