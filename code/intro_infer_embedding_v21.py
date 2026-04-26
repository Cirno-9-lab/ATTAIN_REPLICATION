import os
import json
import re
import torch
import torch.nn.functional as F
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from modelscope import AutoModel, AutoTokenizer
# 1. 导入 LLM 客户端
from llm import Client as LLMClient 

# ==========================================================
# 🔧 环境配置
# ==========================================================
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

MODEL_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/Qwen3-Embedding-8B/my_model"
DATASET_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"

CONTEXT_FILE = f"{DATASET_DIR}/intro_context.json"
CVE_LIST_FILE = f"{DATASET_DIR}/list/cve_list.json"
EXPERT_FILE = f"{DATASET_DIR}/cwe_expert_intro.json"
SAFE_SAMPLES_FILE = f"{DATASET_DIR}/java_code_samples.json"
OUTPUT_FILE = f"{DATASET_DIR}/result/intro_contrastive_final_f.json"

class Qwen3LogicMaster:
    def __init__(self):
        print(f"🚀 启动全量逻辑审计大师 | 目标: {OUTPUT_FILE}")
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
        self.model = AutoModel.from_pretrained(MODEL_PATH, torch_dtype=torch.bfloat16, trust_remote_code=True).to(device)
        self.model.eval()

        # 2. 初始化 LLM 客户端
        self.llm_client = LLMClient()
        
        self.results = {}
        self.lock = Lock()
        self.full_meta = json.load(open(CVE_LIST_FILE, 'r'))
        self.vule_expert_embeddings = {}
        self.safe_baseline_tensors = None
        self._precompute_all_vectors()

    def _get_batch_embeddings(self, texts):
        if not texts: return None
        inputs = self.tokenizer(texts, return_tensors="pt", padding=True, truncation=True, max_length=1536).to(device)
        with torch.no_grad():
            outputs = self.model(**inputs)
            mask = inputs['attention_mask'].unsqueeze(-1).expand(outputs.last_hidden_state.size()).float()
            emb = torch.sum(outputs.last_hidden_state * mask, 1) / torch.clamp(mask.sum(1), min=1e-9)
            return F.normalize(emb, p=2, dim=1)

    def _precompute_all_vectors(self):
        vule_data = json.load(open(EXPERT_FILE, 'r'))
        for cwe_id, text in vule_data.items():
            self.vule_expert_embeddings[cwe_id] = self._get_batch_embeddings([text])
        if os.path.exists(SAFE_SAMPLES_FILE):
            with open(SAFE_SAMPLES_FILE, 'r') as f:
                safe_data = json.load(f)
            self.safe_baseline_tensors = self._get_batch_embeddings(list(safe_data.values()))

    def clean_line(self, line):
        return re.sub(r'^\s*\d+:\s*', '', line).strip()

    def extract_precise_body(self, lines, method_name):
        start_idx = -1
        for i, line in enumerate(lines):
            clean = self.clean_line(line)
            if method_name in clean and "(" in clean and "{" in clean:
                if any(kw in clean for kw in ["public", "private", "protected", "static", "BigDecimal", "Integer"]):
                    start_idx = i
                    break
        if start_idx == -1: return "\n".join([self.clean_line(l) for l in lines[:10]])
        
        body, brace_count, started = [], 0, False
        for line in lines[start_idx:]:
            clean = self.clean_line(line)
            body.append(clean)
            brace_count += clean.count("{")
            brace_count -= clean.count("}")
            if "{" in clean: started = True
            if started and brace_count <= 0: break
        return "\n".join(body)

    def get_audit_score(self, cwe_ids, method_name, code_body, msg):
        prompt = f"Audit Task: Identify logic flaws in method '{method_name}'.\nContext: {msg}\nCode:\n{code_body}"
        emb = self._get_batch_embeddings([prompt])
        
        safe_sims = torch.mm(emb, self.safe_baseline_tensors.T)
        safe_score = torch.topk(safe_sims, k=min(3, safe_sims.size(1))).values.mean().item()

        max_vule_score = 0.0
        for cid in cwe_ids:
            if cid in self.vule_expert_embeddings:
                v_score = torch.mm(emb, self.vule_expert_embeddings[cid].T).item()
                max_vule_score = max(max_vule_score, v_score)

        logic_boost = 0.0
        call_pattern = rf"\b{method_name}\s*\("
        calls = re.findall(call_pattern, code_body)
        
        if len(calls) > 1:
            logic_boost += 0.1 
            if "catch" in code_body:
                catch_content = code_body.split("catch")[-1]
                if method_name in catch_content:
                    logic_boost += 0.05 

        return round(max_vule_score + logic_boost, 4), round(safe_score, 4)

    def process_cve_group(self, group_items, pbar):
        for cve_id, ctx_list in group_items:
            # 调试过滤条件
            if cve_id != "cve-2014-3625": continue
            
            meta = self.full_meta.get(cve_id.upper())
            target_cwes = meta.get("cwe", []) if meta else []
            
            cve_res = []
            for curr_ctx in ctx_list:
                base_tag = curr_ctx.get("base_tag", "N/A")
                head_tag = curr_ctx.get("head_tag", "N/A")
                
                analysis = {}
                for c_hash, c_info in curr_ctx.get("results", {}).items():
                    msg = c_info.get("message", "")
                    file_v = {}
                    for f_path, diff in c_info.get("files", {}).items():
                        if not f_path.endswith(".java"): continue
                            
                        added = diff.get("modified_added_content", [])
                        if not added: continue

                        all_lines = diff.get("context_before", []) + added + diff.get("context_after", [])
                        m_match = re.search(r'(?:public|static|private|protected)\s+[\w\<\>\[\]]+\s+(\w+)\s*\(', "\n".join(added[:10]))
                        m_name = m_match.group(1) if m_match else "unknown"
                        
                        code_body = self.extract_precise_body(all_lines, m_name)
                        v_score, s_score = self.get_audit_score(target_cwes, m_name, code_body, msg)
                        margin = round(v_score - s_score, 4)
                        
                        # 初始判定逻辑
                        verdict = "yes" if (margin > -0.05) else "no"
                        llm_explanation = "Skipped"

                        # 3. 核心修改：如果 margin < 0.05，调用 LLM 进行最终判定
                        if margin < 0.05:
                            llm_prompt = (
                                f"Review the following Java code change for {cve_id}.\n"
                                f"CWE Context: {target_cwes}\n"
                                f"Commit Message: {msg}\n"
                                f"Code Body:\n{code_body}\n\n"
                                "Does this code introduce or contain a vulnerability? "
                                "Answer 'YES' or 'NO' followed by a brief reason."
                            )
                            llm_res = self.llm_client.call_llm(llm_prompt)
                            
                            if llm_res == "STOP_SIGNAL":
                                print("⚠️ LLM Quota exceeded. Stopping LLM calls.")
                                llm_explanation = "LLM STOP_SIGNAL"
                            else:
                                llm_explanation = llm_res
                                # 更新 Verdict
                                if "YES" in llm_res.upper()[:10]: # 简单解析前10个字符
                                    verdict = "yes"
                                elif "NO" in llm_res.upper()[:10]:
                                    verdict = "no"

                        file_v[f_path] = {
                            "method": m_name,
                            "vule_score": v_score,
                            "safe_score": s_score,
                            "margin": margin,
                            "verdict": verdict,
                            "llm_audit": llm_explanation, # 保存 LLM 的详细回复
                            "evidence": code_body[:300]
                        }
                    if file_v: analysis[c_hash] = file_v
                
                if analysis:
                    cve_res.append({
                        "base_tag": base_tag,
                        "head_tag": head_tag,
                        "analysis": analysis
                    })

            with self.lock: self.results[cve_id] = cve_res
            pbar.update(1)

def main():
    with open(CONTEXT_FILE, 'r') as f: data = json.load(f)
    auditor = Qwen3LogicMaster()
    items = list(data.items())

    with tqdm(total=len(items)) as pbar:
        # 注意：调用 LLM 且有 ThreadPool 时，需确保 llm.py 中的 Lock 正常工作
        # 建议 max_workers 不要设置过大以防请求拥堵
        with ThreadPoolExecutor(max_workers=2) as executor: 
            chunk = 5
            groups = [items[i:i+chunk] for i in range(0, len(items), chunk)]
            for _ in executor.map(lambda g: auditor.process_cve_group(g, pbar), groups): pass

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(auditor.results, f, indent=4, ensure_ascii=False)
    print(f"✨ 审计完成！结果已存至 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()