import os
os.environ["CUDA_VISIBLE_DEVICES"] = "1"

import json
import torch
from sentence_transformers import SentenceTransformer, util

# --- 配置 ---
PATCH_MODEL_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/all-MiniLM-L6-v2/my_model"
INTRO_MODEL_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/flax-sentence-embeddings/my_model"
SIMILARITY_THRESHOLD = 0.5  # 你希望挑战的高阈值

# 噪声文件过滤：这些文件通常不包含核心逻辑修复
NOISE_EXTENSIONS = {'.md', '.txt', '.xml', '.html', '.json', '.png', '.jpg', 'pom.xml', 'LICENSE'}

def format_diff(details):
    deleted = details.get("modified_deleted_content", [])
    added = details.get("modified_added_content", [])
    return "\n".join([f"- {l.strip()}" for l in deleted] + [f"+ {l.strip()}" for l in added])

class RAGFilterEngine:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.patch_model = SentenceTransformer(PATCH_MODEL_PATH, device=self.device)
        self.intro_model = SentenceTransformer(INTRO_MODEL_PATH, device=self.device)

    def get_similarity(self, model, text_a, text_b):
        if not text_a.strip() or not text_b.strip(): return 0.0
        with torch.no_grad():
            emb_a = model.encode(text_a, convert_to_tensor=True, show_progress_bar=False)
            emb_b = model.encode(text_b, convert_to_tensor=True, show_progress_bar=False)
            return util.cos_sim(emb_a, emb_b).item()

def main():
    CODE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATASET_DIR = os.path.join(os.path.dirname(CODE_DIR), "dataset")
    engine = RAGFilterEngine()
    
    with open(os.path.join(DATASET_DIR, "list", "cve_list.json"), 'r', encoding='utf-8') as f:
        cve_list_meta = json.load(f)

    all_results = {}
    
    for idx, (cve_id, meta) in enumerate(cve_list_meta.items(), 1):
        cve_l = cve_id.lower()
        desc = meta.get("description") or meta.get("DESCRIPTION", "")
        version_pairs_meta = meta.get("version_pair", [])

        info_path = os.path.join(DATASET_DIR, "commit_info", f"{cve_l}.json")
        ctx_path = os.path.join(DATASET_DIR, "commit_context", f"{cve_l}.json")
        
        if not (os.path.exists(info_path) and os.path.exists(ctx_path)):
            continue
            
        print(f"[{idx}] Analyzing with Max-Pooling: {cve_id}")
        
        try:
            info_data = json.load(open(info_path)).get(cve_l, [])
            ctx_data = json.load(open(ctx_path)).get(cve_l, [])
            
            cve_out = []
            for i, curr_ctx in enumerate(ctx_data):
                # 标签匹配逻辑保持不变
                b_tag, h_tag = curr_ctx.get("base_tag"), curr_ctx.get("head_tag")
                matched_meta = next((vp for vp in version_pairs_meta if vp.get("BASE_TAG") == b_tag and vp.get("HEAD_TAG") == h_tag), None)
                is_patch = matched_meta.get("seek_patch", True) if matched_meta else True
                model = engine.patch_model if is_patch else engine.intro_model
                
                vp_result = {"base_tag": b_tag, "head_tag": h_tag, "mode": "patch" if is_patch else "intro", "analysis": {}}
                
                commits_info = info_data[i].get("commit_info", {}) if i < len(info_data) else {}
                diff_results = curr_ctx.get("results", {})

                for hsh, info in commits_info.items():
                    msg = info.get("message", "")
                    files_diff = diff_results.get(hsh, {})
                    
                    commit_file_scores = {}
                    
                    for f_path, diff_content in files_diff.items():
                        # 过滤噪声文件
                        if any(f_path.lower().endswith(ext) for ext in NOISE_EXTENSIONS):
                            continue
                        
                        diff_text = format_diff(diff_content)
                        if not diff_text.strip(): continue

                        # 核心改进：Message + 单个文件的 Diff
                        # 这样模型能更专注地看这个文件是不是在解这个漏洞
                        input_text = f"Msg: {msg}\nFile: {f_path}\nDiff: {diff_text}"
                        score = engine.get_similarity(model, desc, input_text)
                        
                        commit_file_scores[f_path] = {
                            "verdict": "yes" if score >= SIMILARITY_THRESHOLD else "no",
                            "score": round(score, 4)
                        }
                    
                    if commit_file_scores:
                        vp_result["analysis"][hsh] = commit_file_scores
                
                cve_out.append(vp_result)
            all_results[cve_id] = cve_out

        except Exception as e:
            print(f"⚠️ Error: {cve_id} -> {e}")

    output_path = os.path.join(DATASET_DIR, "result", "cve_rag_filtered_optimized.json")
    json.dump(all_results, open(output_path, 'w'), indent=4)
    print(f"✨ Finished. Results with threshold {SIMILARITY_THRESHOLD} saved.")

if __name__ == "__main__":
    main()