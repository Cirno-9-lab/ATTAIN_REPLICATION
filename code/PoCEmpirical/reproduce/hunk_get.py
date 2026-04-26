import os
import json
import re
import importlib.util
import threading
import concurrent.futures
# 从 settings.py 导入路径配置
from settings import REPO_DIR, MVN_RESULT_DIR, CVE_LIST_FILE, INFER_RESULT_DIR, LLM_FILE

def load_llm_client(file_path):
    spec = importlib.util.spec_from_file_location("llm_module", file_path)
    llm_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(llm_module)
    return llm_module.Client()

class FailureJudge:
    def __init__(self):
        os.makedirs(INFER_RESULT_DIR, exist_ok=True)
        self.llm_client = load_llm_client(LLM_FILE)
        self.summary_output_path = os.path.join(INFER_RESULT_DIR, "intro_diff_results.json")
        self.data_lock = threading.Lock()
        self.all_results = {}

    def extract_trace_locations(self, trace, limit=5):
        """仅提取前 limit 条堆栈位置，减少文件读取量"""
        lines = trace.split('\n')[:10] # 只看前10行堆栈
        short_trace = "\n".join(lines)
        locations = re.findall(r"\((.*\.java):(\d+)\)", short_trace)
        return locations[:limit], short_trace

    def read_source_code(self, repo_path, file_name, line_num):
        """精简版：只取前后 10 行上下文"""
        # 过滤掉非功能性文件或测试文件以节省Token
        if "Test" in file_name or file_name.endswith(('.md', '.xml', 'pom.xml')):
            return None, None

        for root, _, files in os.walk(repo_path):
            if file_name in files:
                full_path = os.path.join(root, file_name)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                        lines = f.readlines()
                        ln = int(line_num)
                        # 窗口由 30 缩减为 10
                        start = max(0, ln - 11)
                        end = min(len(lines), ln + 10)
                        content = "".join(lines[start:end])
                        return content, os.path.relpath(full_path, repo_path)
                except:
                    continue
        return None, None

    def parse_verdict(self, llm_text):
        text_upper = llm_text.upper()
        if re.search(r"VERDICT:\s*YES", text_upper): return "yes"
        if re.search(r"VERDICT:\s*NO", text_upper): return "no"
        return "yes" if "INTRODUCED" in text_upper and "NOT INTRODUCED" not in text_upper else "no"

    def process_cve_group(self, cve_tasks):
        local_results = {}
        for cve_id, info in cve_tasks:
            repo_path = os.path.join(REPO_DIR, info.get("REPO", ""))
            target_pairs = [p for p in info.get("version_pair", []) if p.get("seek_patch") is False 
                            and str(p.get("BASE_TAG")).lower() != "unknown"]

            input_file = os.path.join(MVN_RESULT_DIR, f"{cve_id}.json")
            if not os.path.exists(input_file): continue
            with open(input_file, 'r') as f: mvn_data = json.load(f)

            cve_summary_list = []
            for pair in target_pairs:
                commit_analysis = {}
                for res in mvn_data.get("results", []):
                    sha = res.get("sha", "unknown")
                    # 1. 堆栈剪枝
                    locations, short_trace = self.extract_trace_locations(res.get("trace_snippet", ""))
                    
                    # 2. 上下文与 Hunk 剪枝
                    context_data = {}
                    primary_file = "unknown"
                    for f_name, l_num in locations:
                        code, rel_p = self.read_source_code(repo_path, f_name, l_num)
                        if code:
                            context_data[rel_p] = code
                            if primary_file == "unknown": primary_file = rel_p
                    
                    # 只保留 Hunk 的 diff 内容，不传整个对象
                    mini_hunks = [h.get("diff", "")[:500] for h in res.get("hunks", [])] 

                    # 3. 极简 Prompt
                    prompt = (
                        f"Target: {cve_id}\n"
                        f"Trace: {short_trace}\n"
                        f"Diff: {json.dumps(mini_hunks)}\n"
                        f"Code: {json.dumps(context_data)}\n\n"
                        f"Verdict 'yes' if this code introduces a vulnerability, else 'no'.\n"
                        f"Output: VERDICT: <yes/no> | REASON: <concise>"
                    )

                    llm_response = self.llm_client.call_llm(prompt)
                    if llm_response == "STOP_SIGNAL": return
                    
                    verdict = self.parse_verdict(llm_response)
                    if sha not in commit_analysis: commit_analysis[sha] = {}
                    commit_analysis[sha][primary_file] = {"verdict": verdict, "reason": llm_response}

                cve_summary_list.append({
                    "base_tag": pair.get("BASE_TAG"), "head_tag": pair.get("HEAD_TAG"),
                    "mode": "intro", "analysis": commit_analysis
                })
            if cve_summary_list: local_results[cve_id] = cve_summary_list

        with self.data_lock: self.all_results.update(local_results)

    def analyze_all(self):
        with open(CVE_LIST_FILE, 'r') as f:
            cve_data_map = json.load(f)

        # 按 Repo 分组并分配到 5 个线程
        repos = {}
        for cid, info in cve_data_map.items():
            r = info.get("REPO", "default")
            if r not in repos: repos[r] = []
            repos[r].append((cid, info))
        
        repo_list = list(repos.values())
        groups = [[] for _ in range(5)]
        for i, tasks in enumerate(repo_list): groups[i % 5].extend(tasks)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(self.process_cve_group, groups)

        with open(self.summary_output_path, 'w', encoding='utf-8') as f:
            json.dump(self.all_results, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    FailureJudge().analyze_all()