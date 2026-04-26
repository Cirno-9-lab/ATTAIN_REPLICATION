# ==========================================================
# 1. 核心环境变量配置 (必须在所有 import torch 之前)
# ==========================================================
import os
# 指定只使用物理 1 号显卡 (80GB 空闲卡)
os.environ["CUDA_VISIBLE_DEVICES"] = "1"
# 开启显存碎片优化，这是针对报错信息的针对性修复
os.environ["PYTORCH_ALLOC_CONF"] = "expandable_segments:True"

import json
import re
import torch
import math
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import transformers.modeling_utils
from transformers import AutoTokenizer, Qwen2ForCausalLM, Qwen2Config

# ==========================================================
# 2. 稳定性补丁：修复某些环境下的权重加载问题
# ==========================================================
original_load_state_dict = transformers.modeling_utils.load_state_dict
def patched_load_state_dict(checkpoint_file, **kwargs):
    try:
        return original_load_state_dict(checkpoint_file, **kwargs)
    except (AttributeError, TypeError):
        from safetensors.torch import load_file
        return load_file(checkpoint_file, device="cpu")
transformers.modeling_utils.load_state_dict = patched_load_state_dict

# 此时物理 1 号卡在程序内即为 "cuda:0"
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

# --- 路径配置 ---
MODEL_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/Qwen2.5-coder-7B/my_model"
DATASET_DIR = "../dataset"
CONTEXT_FILE = f"{DATASET_DIR}/intro_context.json"
CVE_LIST_FILE = f"{DATASET_DIR}/list/cve_list.json"
EXPERT_FILE = f"{DATASET_DIR}/cwe_expert_intro.json"
OUTPUT_FILE = f"{DATASET_DIR}/result/intro_only_results.json"

class QwenContextAuditor:
    def __init__(self):
        print(f"🚀 初始化... 目标设备: {device} ({torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'})")
        
        # 清理显存残余
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

        try:
            config_path = os.path.join(MODEL_PATH, "config.json")
            with open(config_path, "r") as f:
                cfg_json = json.load(f)
            
            # 强制配置确保兼容性
            cfg_json["model_type"] = "qwen2"
            cfg_json["vocab_size"] = 152064 
            
            qwen_config = Qwen2Config.from_dict(cfg_json)
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
            
            # 使用 bfloat16 (A800原生支持) 极大减少显存压力并提升速度
            self.model = Qwen2ForCausalLM.from_pretrained(
                MODEL_PATH, 
                config=qwen_config, 
                torch_dtype=torch.bfloat16, 
                low_cpu_mem_usage=True
            ).to(device)
            
            self.model.eval()
            print(f"✅ 模型就绪。当前占用显存: {torch.cuda.memory_allocated()/1024**3:.2f} GB")
        except Exception as e:
            print(f"❌ 加载失败: {e}"); exit(1)

        self.results = {}
        self.lock = Lock()
        self.full_meta = json.load(open(CVE_LIST_FILE, 'r'))
        self.cwe_expert = json.load(open(EXPERT_FILE, 'r')) if os.path.exists(EXPERT_FILE) else {}

    def clean_diff_line(self, line):
        return re.sub(r'^\s*\d+:\s*', '', line)

    def get_safe_context(self, expert_p, diff_text, max_tokens=30000):
        """
        核心规则筛选：防止长文本导致 OOM
        """
        # 预清洗
        diff_text = re.sub(r'//.*|/\*.*?\*/', '', diff_text, flags=re.DOTALL)
        diff_text = "\n".join([l.strip() for l in diff_text.splitlines() if l.strip()])

        # 估算 Token
        expert_tokens = self.tokenizer.encode(expert_p)
        diff_tokens = self.tokenizer.encode(diff_text)
        
        if len(expert_tokens) + len(diff_tokens) > max_tokens:
            # 优先保住 Expert 部分
            if len(expert_tokens) > 8000:
                expert_tokens = expert_tokens[:8000]
                expert_p = self.tokenizer.decode(expert_tokens)

            # 截断 Diff 部分
            remaining_quota = max_tokens - len(expert_tokens) - 500 
            if len(diff_tokens) > remaining_quota:
                diff_text = self.tokenizer.decode(diff_tokens[:remaining_quota]) + "\n... [TRUNCATED]"
        
        return expert_p, diff_text

    def get_score(self, expert_snippets, diff_text):
        if not expert_snippets or not diff_text: return 0.0
        
        prompt = f"""<|im_start|>system
You are a security expert. Analyze the [Code Diff] based on the [Vulnerability Pattern].
Explain the reasoning briefly, then output 'Score: <float_value>'.<|im_end|>
<|im_start|>user
[Vulnerability Pattern]:
{expert_snippets}

[Code Diff]:
{diff_text}

Analyze and Score:<|im_end|>
<|im_start|>assistant
Reasoning:"""

        # 确保输入转移到 GPU
        inputs = self.tokenizer(prompt, return_tensors="pt").to(device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs, 
                max_new_tokens=150, 
                temperature=0.01, 
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        # 释放输入显存引用
        input_len = inputs.input_ids.shape[1]
        del inputs
        
        resp = self.tokenizer.decode(outputs[0][input_len:], skip_special_tokens=True)
        
        score_match = re.search(r"Score:\s*(\d*\.?\d+)", resp, re.IGNORECASE)
        if score_match:
            try: return min(max(float(score_match.group(1)), 0.0), 1.0)
            except: pass
        return 0.0

    def process_cve_group(self, group_items, pbar):
        for cve_id, ctx_list in group_items:
            cve_key = cve_id.upper()
            meta = self.full_meta.get(cve_key)
            if not meta:
                pbar.update(1); continue

            expert_p = "\n".join([self.cwe_expert.get(c, "") for c in meta.get("cwe", []) if c in self.cwe_expert])
            cve_res = []
            
            for curr_ctx in ctx_list:
                b_tag, h_tag = curr_ctx.get("base_tag"), curr_ctx.get("head_tag")
                meta_pair = next((vp for vp in meta.get('version_pair', []) 
                                 if vp.get("BASE_TAG") == b_tag and vp.get("HEAD_TAG") == h_tag), None)
                
                if not meta_pair or meta_pair.get("seek_patch", True):
                    continue

                analysis = {}
                for commit_hash, commit_info in curr_ctx.get("results", {}).items():
                    file_v = {}
                    files_dict = commit_info.get("files", {}) 
                    
                    for f_path, diff_content in files_dict.items():
                        added = diff_content.get("modified_added_content", [])
                        raw_diff = "\n".join([self.clean_diff_line(l) for l in added])
                        
                        safe_expert, safe_diff = self.get_safe_context(expert_p, raw_diff)
                        if not safe_diff.strip(): continue
                        
                        score = self.get_score(safe_expert, safe_diff)
                        file_v[f_path] = {"verdict": "yes" if score >= 0.5 else "no", "score": round(score, 4)}
                    
                    if file_v: analysis[commit_hash] = file_v
                
                if analysis:
                    cve_res.append({"base_tag": b_tag, "head_tag": h_tag, "mode": "intro", "analysis": analysis})

            if cve_res:
                with self.lock: self.results[cve_id] = cve_res
            pbar.update(1)

def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(CONTEXT_FILE, 'r') as f:
        data = json.load(f)
    
    auditor = QwenContextAuditor()
    items = list(data.items())
    
    print(f"🔥 审计开始 | 总 CVE 任务: {len(items)}")
    
    # 注意：在 A800 上跑 7B 模型，建议单线程推理以防并发导致的 OOM。
    # 如果显存依然紧张，请保持 max_workers=1
    with tqdm(total=len(items)) as pbar:
        with ThreadPoolExecutor(max_workers=1) as executor:
            # 均匀切分任务
            chunk_size = max(1, len(items) // 10)
            groups = [items[i:i+chunk_size] for i in range(0, len(items), chunk_size)]
            
            for _ in executor.map(lambda g: auditor.process_cve_group(g, pbar), groups):
                pass

    with open(OUTPUT_FILE, 'w') as f:
        json.dump(auditor.results, f, indent=4)
    print(f"\n✨ 完成！结果已存至: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()