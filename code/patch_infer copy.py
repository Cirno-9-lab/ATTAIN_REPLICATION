import os
# 锁定 GPU 5
os.environ["CUDA_VISIBLE_DEVICES"] = "1"

import json
import torch
import re
from sentence_transformers import SentenceTransformer, util
from llm import Client  # 确保 llm.py 在当前目录

# --- 核心配置 ---
BI_MODEL_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/all-MiniLM-L6-v2/my_model"
DATASET_DIR = "../dataset"
OUTPUT_FILE = f"{DATASET_DIR}/result/patch_fast_recovery.json"

# 海选阈值
BI_THRESHOLD = 0.45 

class FastAuditEngine:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"🚀 Loading Bi-Encoder on {self.device} (GPU 5)...")
        self.bi_model = SentenceTransformer(BI_MODEL_PATH, device=self.device)
        
        print(f"🤖 Initializing LLM Auditor (DeepSeek-V3)...")
        self.llm_client = Client()

    def is_noise_file(self, f_path):
        noise_patterns = ['test', 'sample', 'doc', 'pom.xml', '.md', 'readme', 'example', 'testcase']
        return any(p in f_path.lower() for p in noise_patterns)

    def get_bi_score(self, raw_desc, msg, f_path, diff_text):
        if self.is_noise_file(f_path) or not diff_text.strip():
            return 0.0
        query = f"Vulnerability: {raw_desc}"
        candidate = f"Commit Message: {msg}\nFile: {f_path}\nCode Change:\n{diff_text}"
        with torch.no_grad():
            emb_q = self.bi_model.encode(query, convert_to_tensor=True)
            emb_c = self.bi_model.encode(candidate, convert_to_tensor=True)
            return util.cos_sim(emb_q, emb_c).item()

    def get_llm_verdict(self, desc, msg, diff_text):
        prompt = f"""[Role]: Senior Security Researcher
[Task]: Audit if this code change is a SECURITY PATCH for the CVE.
[Vulnerability]: {desc}
[Commit Msg]: {msg}
[Code Diff]:
{diff_text[:2000]} 

[Requirement]: 
- Answer "yes" ONLY if the code directly fixes the described vulnerability.
- Answer "no" if it is refactoring, testing, or unrelated.
- Respond with ONLY "yes" or "no".

Decision:"""
        try:
            res = self.llm_client.call_llm(prompt).strip().lower()
            return "yes" if "yes" in res else "no"
        except:
            return "no"

def main():
    engine = FastAuditEngine()
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    with open(f"{DATASET_DIR}/list/cve_list.json", 'r', encoding='utf-8') as f:
        cve_list_meta = json.load(f)

    all_results = {}
    
    for cve_id, meta in cve_list_meta.items():
        cve_l = cve_id.lower()
        desc = meta.get("description") or meta.get("DESCRIPTION", "")
        version_pairs = meta.get("version_pair", [])
        
        ctx_path = f"{DATASET_DIR}/commit_context/{cve_l}.json"
        info_path = f"{DATASET_DIR}/commit_info/{cve_l}.json"
        if not (os.path.exists(ctx_path) and os.path.exists(info_path)): continue
        
        try:
            ctx_data = json.load(open(ctx_path)).get(cve_l, [])
            info_data = json.load(open(info_path)).get(cve_l, [])
            cve_out = []
            
            for i, curr_ctx in enumerate(ctx_data):
                b_tag, h_tag = curr_ctx.get("base_tag"), curr_ctx.get("head_tag")
                meta_pair = next((vp for vp in version_pairs if vp.get("BASE_TAG") == b_tag and vp.get("HEAD_TAG") == h_tag), None)
                if not meta_pair or not meta_pair.get("seek_patch", False): continue

                temp_data = {}
                has_any_yes = False
                commits_info = info_data[i].get("commit_info", {})
                diff_results = curr_ctx.get("results", {})

                # --- 阶段 1：海选 (Bi-Encoder) ---
                for hsh, info in commits_info.items():
                    msg = info.get("message", "")
                    hsh_files = {}
                    for f_path, diff in diff_results.get(hsh, {}).items():
                        added = diff.get("modified_added_content", [])
                        diff_text = "\n".join(added)
                        score = engine.get_bi_score(desc, msg, f_path, diff_text)
                        
                        verdict = "yes" if score >= BI_THRESHOLD else "no"
                        if verdict == "yes": has_any_yes = True
                        
                        hsh_files[f_path] = {
                            "verdict": verdict, "score": round(score, 4),
                            "__diff": diff_text, "__msg": msg
                        }
                    temp_data[hsh] = hsh_files

                # --- 阶段 2：全 no 时的 LLM 熔断式扫描 ---
                if not has_any_yes and temp_data:
                    print(f"🔍 [CVE: {cve_id}] No match found. LLM checking all commits until 'yes'...")
                    
                    found_by_llm = False
                    # 按分数从高到低检查，提高 break 的效率
                    all_candidates = []
                    for hsh, files in temp_data.items():
                        for f_path, info in files.items():
                            all_candidates.append((hsh, f_path, info))
                    
                    all_candidates.sort(key=lambda x: x[2]["score"], reverse=True)

                    for hsh, f_path, info in all_candidates:
                        if info["score"] < 0.05: continue # 过滤掉关联度极低的文件
                        
                        llm_verdict = engine.get_llm_verdict(desc, info["__msg"], info["__diff"])
                        if llm_verdict == "yes":
                            print(f"  ✨ [LLM Found!] {cve_id} | {hsh[:8]} | {f_path}")
                            temp_data[hsh][f_path]["verdict"] = "yes"
                            found_by_llm = True
                            break # 发现第一个 yes，退出候选人循环
                    
                    # 如果找到了，逻辑上已经处理完了这个 version_pair 的核心需求

                # --- 阶段 3：格式清理 ---
                final_analysis = {}
                for hsh, files in temp_data.items():
                    final_files = {fp: {"verdict": inf["verdict"], "score": inf["score"]} for fp, inf in files.items()}
                    final_analysis[hsh] = final_files

                cve_out.append({
                    "base_tag": b_tag, "head_tag": h_tag, 
                    "mode": "patch", "analysis": final_analysis
                })
            
            if cve_out: all_results[cve_id] = cve_out

        except Exception as e:
            print(f"❌ Error at {cve_id}: {e}")

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=4, ensure_ascii=False)
    print(f"\n✨ 任务完成。结果已保存至: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()