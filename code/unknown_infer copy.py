import json
import os
import sys
import glob
import pandas as pd
import importlib.util

# 1. 环境配置加载
try:
    import settings
    EXCEL_FILE = settings.EXCEL_FILE
    RESULT_DIR = settings.RESULT_DIR
    CVE_LIST_FILE = settings.CVE_LIST_FILE
    LLM_FILE_PATH = settings.LLM_FILE
    EXPLOITS_ROOT = settings.EXPLOITS_ROOT 
except ImportError:
    print("❌ 错误：无法加载 settings.py，请检查文件路径。")
    sys.exit(1)

def get_poc_context(cve_id):
    """提取 PoC 断言作为 LLM 判定依据"""
    pattern = os.path.join(EXPLOITS_ROOT, cve_id, "**", "*Test.java")
    test_files = glob.glob(pattern, recursive=True)
    if not test_files: return "No *Test.java found for context."
    
    assertions = []
    try:
        with open(test_files[0], 'r', encoding='utf-8') as f:
            for line in f:
                if "assert" in line.lower():
                    assertions.append(line.strip())
    except Exception as e:
        return f"Error reading PoC file: {str(e)}"
    return "\n".join(assertions[:15]) if assertions else "No 'assert' keywords found."

def init_llm():
    spec = importlib.util.spec_from_file_location("llm_mod", LLM_FILE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Client()

def run_expert_audit():
    print("="*60)
    print("🚀 边界审计系统 (Strict Excel Native Order Mode)")
    print("="*60)

    try:
        with open(CVE_LIST_FILE, 'r', encoding='utf-8') as f:
            cve_meta = json.load(f)
        df = pd.read_excel(EXCEL_FILE)
        df.columns = [col.lower().strip() for col in df.columns]
    except Exception as e:
        print(f"❌ 数据加载失败: {e}"); return

    # ⚠️ 核心改变：删除全部 sort_values 逻辑，直接沿用 Excel 原始顺序！
    
    llm_client = init_llm()
    final_results = {}
    stats = {"total": 0, "processed": 0, "skipped": 0}

    # sort=False 保证 groupby 后的数据完全维持在原 Excel 中的出现顺序
    grouped = df.groupby('cve_id', sort=False)

    for cve_id, group in grouped:
        
        rows = group.to_dict('records')
        version_pairs = []
        cwe = cve_meta.get(cve_id, {}).get("cwe", ["Unknown"])
        poc_context = get_poc_context(cve_id)

        # 严格按照 Excel 顺序从上到下两两比对
        for i in range(1, len(rows)):
            prev, curr = rows[i-1], rows[i]

            is_prev_appears = (str(prev.get('execution result', '')).strip().upper() == "APPEARS")
            is_curr_appears = (str(curr.get('execution result', '')).strip().upper() == "APPEARS")

            # 状态未改变 (比如连续的 BUILD_FAILURE_OTHER)，静默跳过
            if is_prev_appears == is_curr_appears:
                continue 

            target_row = None
            mode = ""

            # 判定 A：APPEARS -> NOT APPEARS (寻补丁)
            if is_prev_appears and not is_curr_appears:
                if str(curr.get('llm_verdict', '')).strip() == "No_Data":
                    target_row, mode = curr, "patch"
            
            # 判定 B：NOT APPEARS -> APPEARS (寻引入)
            elif not is_prev_appears and is_curr_appears:
                if str(prev.get('llm_verdict', '')).strip() == "No_Data":
                    target_row, mode = prev, "introduction"

            if target_row:
                stats["total"] += 1
                t_ver = str(target_row['version'])
                cause = str(target_row.get('cause', "")).strip()

                if not cause or cause.lower() == "nan":
                    stats["skipped"] += 1
                    continue

                print(f"🔍 触发审计: {cve_id} | 边界版本: {t_ver:10} | 模式: {mode}")

                prompt = f"""
                CVE ID: {cve_id} | CWE: {cwe} | Analysis Mode: {mode.upper()}
                [PoC Logic (Test Assertions)]:
                {poc_context}
                
                [Error Log]:
                "{cause}"

                [Instruction]:
                Does the log suggest an environmental build/setup failure (verdict: yes) 
                or a legitimate code logic change/fix (verdict: no)? 
                Return JSON only: {{"verdict": "yes/no", "score": 0.0-1.0, "reason": "..."}}
                """
                
                raw_res = llm_client.call_llm(prompt)
                if raw_res == "STOP_SIGNAL":
                    save_json(final_results, stats)
                    print("⚠️ 任务终止。")
                    return

                try:
                    clean_json = raw_res.replace("```json", "").replace("```", "").strip()
                    analysis_json = json.loads(clean_json)
                    stats["processed"] += 1
                except:
                    analysis_json = {"verdict": "unknown", "score": 0.0, "reason": "JSON Parse Error"}

                version_pairs.append({
                    "base_tag": str(prev['version']),
                    "head_tag": str(curr['version']),
                    "appears": str(prev['version'] if mode == "patch" else curr['version']),
                    "not appears": str(curr['version'] if mode == "patch" else prev['version']),
                    "mode": mode,
                    "analysis": { t_ver: analysis_json }
                })

        if version_pairs:
            final_results[cve_id] = version_pairs

    save_json(final_results, stats)

def save_json(data, stats):
    os.makedirs(RESULT_DIR, exist_ok=True)
    out_path = os.path.join(RESULT_DIR, "unknown_only_results.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print("\n" + "="*60)
    print(f"📊 命中翻转边界总数: {stats['total']} | 成功审计: {stats['processed']} | 空日志跳过: {stats['skipped']}")
    print("="*60)

if __name__ == "__main__":
    run_expert_audit()