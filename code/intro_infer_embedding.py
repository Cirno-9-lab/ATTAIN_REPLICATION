import os
import json
import re
import torch
import torch.nn.functional as F
import math
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from modelscope import AutoModel, AutoTokenizer

# ==========================================================
# 🔧 参数与路径配置
# ==========================================================
os.environ["CUDA_VISIBLE_DEVICES"] = "1"
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# 滑动窗口与推理配置
WINDOW_SIZE = 8   
STRIDE = 3        
BATCH_SIZE = 32   

MODEL_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/Qwen3-Embedding-8B/my_model"
DATASET_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"

CONTEXT_FILE = f"{DATASET_DIR}/intro_context.json"
CVE_LIST_FILE = f"{DATASET_DIR}/list/cve_list.json"
EXPERT_FILE = f"{DATASET_DIR}/cwe_expert_intro.json"
# 外部安全样本库
SAFE_SAMPLES_FILE = f"{DATASET_DIR}/java_code_samples.json"
OUTPUT_FILE = f"{DATASET_DIR}/result/intro_contrastive_final.json"

class Qwen3ContrastiveAuditor:
    def __init__(self):
        print(f"🚀 启动对比审计模式 | 加载模型: {MODEL_PATH}")
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
            self.model = AutoModel.from_pretrained(
                MODEL_PATH, torch_dtype=torch.bfloat16, trust_remote_code=True
            ).to(device)
            self.model.eval()
        except Exception as e:
            print(f"❌ 模型加载失败: {e}"); exit(1)

        self.results = {}
        self.lock = Lock()
        self.full_meta = json.load(open(CVE_LIST_FILE, 'r'))
        
        # 向量库初始化
        self.vule_expert_embeddings = {}
        self.safe_baseline_tensors = None
        self._precompute_all_vectors()

    def _get_batch_embeddings(self, texts):
        """批处理向量化"""
        if not texts: return None
        inputs = self.tokenizer(texts, return_tensors="pt", padding=True, truncation=True, max_length=1024).to(device)
        with torch.no_grad():
            outputs = self.model(**inputs)
            mask = inputs['attention_mask'].unsqueeze(-1).expand(outputs.last_hidden_state.size()).float()
            emb = torch.sum(outputs.last_hidden_state * mask, 1) / torch.clamp(mask.sum(1), min=1e-9)
            return F.normalize(emb, p=2, dim=1)

    def _precompute_all_vectors(self):
        # 1. 编码漏洞专家描述
        print(f"🧠 正在编码 CWE 专家描述...")
        vule_data = json.load(open(EXPERT_FILE, 'r'))
        for cwe_id, text in vule_data.items():
            if text.strip():
                self.vule_expert_embeddings[cwe_id] = self._get_batch_embeddings([text])
        
        # 2. 从 JSON 文件编码安全样本基准
        if os.path.exists(SAFE_SAMPLES_FILE):
            print(f"🛡️ 正在从 {os.path.basename(SAFE_SAMPLES_FILE)} 构建安全基准...")
            with open(SAFE_SAMPLES_FILE, 'r', encoding='utf-8') as f:
                safe_data = json.load(f)
            
            # 处理字典格式或列表格式
            safe_texts = list(safe_data.values()) if isinstance(safe_data, dict) else safe_data
            # A800 性能强劲，直接一次性编码 10 条（或更多）
            self.safe_baseline_tensors = self._get_batch_embeddings(safe_texts)
        else:
            print(f"⚠️ 警告：未找到安全样本文件 {SAFE_SAMPLES_FILE}，对比功能将受限。")

    def clean_diff_line(self, line):
        return re.sub(r'^\s*\d+:\s*', '', line)

    def get_rolling_contrastive_score(self, cwe_ids, diff_text):
        if not cwe_ids or not diff_text.strip(): return 0.0, 0.0, ""
        
        # 切分窗口
        lines = [self.clean_diff_line(l) for l in diff_text.splitlines()]
        snippets = ["\n".join(lines[i : i + WINDOW_SIZE]) for i in range(0, len(lines) - WINDOW_SIZE + 1, STRIDE)]
        if not snippets: snippets = ["\n".join(lines)]

        max_vule_score = 0.0
        best_safe_score = 0.0
        best_snippet = ""

        # 批推理
        for i in range(0, len(snippets), BATCH_SIZE):
            batch_texts = snippets[i : i + BATCH_SIZE]
            batch_embs = self._get_batch_embeddings(batch_texts)

            # 计算与 10 条安全基准的相似度 [Batch, Safe_N] -> 取每个窗口的最高分 [Batch]
            if self.safe_baseline_tensors is not None:
                safe_sims_matrix = torch.mm(batch_embs, self.safe_baseline_tensors.T)
                batch_safe_scores, _ = torch.max(safe_sims_matrix, dim=1)
            else:
                batch_safe_scores = torch.zeros(len(batch_texts))

            # 计算与目标 CWE 专家的相似度
            for cwe_id in cwe_ids:
                if cwe_id in self.vule_expert_embeddings:
                    expert_emb = self.vule_expert_embeddings[cwe_id]
                    v_sims = torch.mm(batch_embs, expert_emb.T).squeeze()
                    if v_sims.dim() == 0: v_sims = v_sims.unsqueeze(0)
                    
                    v_val, v_idx = torch.max(v_sims, dim=0)
                    if v_val.item() > max_vule_score:
                        max_vule_score = v_val.item()
                        best_safe_score = batch_safe_scores[v_idx].item()
                        best_snippet = batch_texts[v_idx]

        return round(max_vule_score, 4), round(best_safe_score, 4), best_snippet

    def process_cve_group(self, group_items, pbar):
        for cve_id, ctx_list in group_items:
            cve_key = cve_id.upper()
            meta = self.full_meta.get(cve_key)
            if not meta: pbar.update(1); continue

            target_cwes = meta.get("cwe", [])
            cve_res = []
            for curr_ctx in ctx_list:
                analysis = {}
                for commit_hash, commit_info in curr_ctx.get("results", {}).items():
                    file_v = {}
                    for f_path, diff_content in commit_info.get("files", {}).items():
                        added = diff_content.get("modified_added_content", [])
                        if not added: continue
                        
                        v_score, s_score, evidence = self.get_rolling_contrastive_score(target_cwes, "\n".join(added))
                        margin = round(v_score - s_score, 4)
                        
                        # --- 核心判定逻辑 ---
                        # 只有当比安全基准高出 0.02 以上时，才判定为 yes
                        is_vule = "yes" if (v_score > 0.65 and margin > 0.02) else "no"
                        
                        file_v[f_path] = {
                            "vule_score": v_score,
                            "safe_score": s_score,
                            "margin": margin,
                            "verdict": is_vule,
                            "evidence": evidence
                        }
                    if file_v: analysis[commit_hash] = file_v
                if analysis:
                    cve_res.append({"base_tag": curr_ctx.get("base_tag"), "head_tag": curr_ctx.get("head_tag"), "analysis": analysis})
            
            with self.lock: self.results[cve_id] = cve_res
            pbar.update(1)

def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(CONTEXT_FILE, 'r') as f: data = json.load(f)
    
    auditor = Qwen3ContrastiveAuditor()
    items = list(data.items())
    
    print(f"🔥 对比审计开始 | 任务量: {len(items)}")
    with tqdm(total=len(items)) as pbar:
        # A800 worker=1 保证显存平稳，滑动窗口计算密集
        with ThreadPoolExecutor(max_workers=1) as executor:
            chunk = math.ceil(len(items) / 5)
            groups = [items[i:i+chunk] for i in range(0, len(items), chunk)]
            for _ in executor.map(lambda g: auditor.process_cve_group(g, pbar), groups): pass

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(auditor.results, f, indent=4, ensure_ascii=False)
    print(f"✨ 审计完成！最终结果已存至: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()