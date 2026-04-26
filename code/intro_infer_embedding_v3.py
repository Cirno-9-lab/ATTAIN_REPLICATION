import os
import json
import re
import torch
import torch.nn.functional as F
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from modelscope import AutoModel, AutoTokenizer

# 导入自定义的 DeepSeek 客户端模块
import llm

# ==========================================================
# 🔧 环境与路径配置
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

class DeepSeekDrivenAuditor:
    def __init__(self):
        print("🚀 启动语义-逻辑双引擎审计模式 (DeepSeek-V3 + Qwen3-Embedding)")
        self.llm_client = llm.Client()
        
        # 向量模型初始化
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
        self.model = AutoModel.from_pretrained(MODEL_PATH, torch_dtype=torch.bfloat16, trust_remote_code=True).to(device)
        self.model.eval()

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

    # ------------------------------------------------------
    # STAGE 1: 提取焦点方法
    # ------------------------------------------------------
    def get_focal_method_via_v3(self, msg, nvd_desc):
        prompt = (
            "Identify the specific Java method name that is the root cause or target of the vulnerability "
            "based on the following Commit Message and NVD Description.\n"
            f"Commit Message: {msg}\n"
            f"NVD Description: {nvd_desc}\n\n"
            "Output ONLY the raw method name (e.g., toBigDecimal). If not found, output 'Unknown'."
        )
        res = self.llm_client.call_llm(prompt).strip()
        if res == "STOP_SIGNAL": return None
        clean_res = re.sub(r'[`"\']', '', res).split('(')[0] # 清理残留符号
        return clean_res if "Unknown" not in clean_res else None

    # ------------------------------------------------------
    # 代码闭包提取
    # ------------------------------------------------------
    def extract_precise_body(self, lines, target_method):
        start_idx = -1
        for i, line in enumerate(lines):
            clean = re.sub(r'^\s*\d+:\s*', '', line).strip()
            if target_method in clean and "(" in clean and "{" in clean:
                if any(kw in clean for kw in ["public", "private", "protected", "static"]):
                    start_idx = i
                    break
        
        if start_idx == -1: return None

        body, brace_count, started = [], 0, False
        for line in lines[start_idx:]:
            clean = re.sub(r'^\s*\d+:\s*', '', line).strip()
            body.append(clean)
            brace_count += clean.count("{")
            brace_count -= clean.count("}")
            if "{" in clean: started = True
            if started and brace_count <= 0: break
        return "\n".join(body)

    # ------------------------------------------------------
    # STAGE 2: 漏洞逻辑动态研判
    # ------------------------------------------------------
    def analyze_flaw_via_llm(self, method_name, code_body, nvd_desc):
        prompt = (
            "You are a strict code security auditor.\n"
            f"Vulnerability Context: {nvd_desc}\n"
            f"Target Method: {method_name}\n"
            "Source Code:\n"
            f"```java\n{code_body}\n```\n"
            "Task: Does this specific code snippet contain the logical flaw that causes the described vulnerability? "
            "(For example, infinite recursion leading to stack overflow, unhandled exceptions, improper path decoding, etc.)\n"
            "Evaluate the control flow carefully. Your final output MUST end with exactly one of the following words:\n"
            "- CONFIRMED (If the flaw is explicitly present in the logic)\n"
            "- SUSPICIOUS (If the logic is risky but not definitively the root cause)\n"
            "- SAFE (If the code handles the logic correctly or the flaw is absent)"
        )
        
        res = self.llm_client.call_llm(prompt).strip().upper()
        if res == "STOP_SIGNAL": return 0.0
        
        if "CONFIRMED" in res:
            return 0.20
        elif "SUSPICIOUS" in res:
            return 0.08
        else:
            return 0.0

    # ------------------------------------------------------
    # 核心评分流水线
    # ------------------------------------------------------
    def get_audit_score(self, cwe_ids, method_name, code_body, nvd_desc):
        # 1. 向量空间语义计算 (软比对)
        prompt = f"Audit Task: Check method '{method_name}'.\nContext: {nvd_desc}\nCode:\n{code_body}"
        emb = self._get_batch_embeddings([prompt])
        
        safe_sims = torch.mm(emb, self.safe_baseline_tensors.T)
        safe_score = torch.topk(safe_sims, k=3).values.mean().item()

        max_vule_score = 0.0
        for cid in cwe_ids:
            if cid in self.vule_expert_embeddings:
                v_score = torch.mm(emb, self.vule_expert_embeddings[cid].T).item()
                max_vule_score = max(max_vule_score, v_score)

        # 2. 调用大模型研判结构逻辑 (硬校验)
        llm_boost = self.analyze_flaw_via_llm(method_name, code_body, nvd_desc)

        return round(max_vule_score + llm_boost, 4), round(safe_score, 4)

    def process_cve_group(self, group_items, pbar):
        for cve_id, ctx_list in group_items:
            meta = self.full_meta.get(cve_id.upper(), {})
            nvd_desc = meta.get("description", "")
            target_cwes = meta.get("cwe", [])
            
            cve_res = []
            for curr_ctx in ctx_list:
                base_tag = curr_ctx.get("base_tag", "N/A")
                head_tag = curr_ctx.get("head_tag", "N/A")
                analysis = {}

                for c_hash, c_info in curr_ctx.get("results", {}).items():
                    msg = c_info.get("message", "")
                    
                    # 第一阶段: 提取目标
                    focal_method = self.get_focal_method_via_v3(msg, nvd_desc)
                    if not focal_method: continue

                    file_v = {}
                    for f_path, diff in c_info.get("files", {}).items():
                        if not f_path.endswith(".java"): continue
                            
                        added = diff.get("modified_added_content", [])
                        if not added: continue

                        all_lines = diff.get("context_before", []) + added + diff.get("context_after", [])
                        code_body = self.extract_precise_body(all_lines, focal_method)
                        if not code_body: continue

                        # 第二阶段: 获取基础分并引入 LLM 强力补偿
                        v_score, s_score = self.get_audit_score(target_cwes, focal_method, code_body, nvd_desc)
                        margin = round(v_score - s_score, 4)
                        
                        # 判断阈值：如果 margin 大于 0.015 即视为风险
                        verdict = "yes" if (margin > 0.015 or v_score > 0.74) else "no"
                        
                        file_v[f_path] = {
                            "focal_method": focal_method,
                            "vule_score": v_score,
                            "safe_score": s_score,
                            "margin": margin,
                            "verdict": verdict
                        }
                    if file_v: analysis[c_hash] = file_v
                
                if analysis:
                    cve_res.append({"base_tag": base_tag, "head_tag": head_tag, "analysis": analysis})

            with self.lock: self.results[cve_id] = cve_res
            pbar.update(1)

def main():
    with open(CONTEXT_FILE, 'r') as f: data = json.load(f)
    auditor = DeepSeekDrivenAuditor()
    items = list(data.items())

    # 注意：涉及较多在线大模型调用，为避免 Rate Limit 和封禁，max_workers 强制设为 1 或 2
    with tqdm(total=len(items)) as pbar:
        with ThreadPoolExecutor(max_workers=2) as executor:
            chunk = 5
            groups = [items[i:i+chunk] for i in range(0, len(items), chunk)]
            for _ in executor.map(lambda g: auditor.process_cve_group(g, pbar), groups): pass

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(auditor.results, f, indent=4, ensure_ascii=False)
    print(f"✨ 全量测试完成！结果已存至: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()