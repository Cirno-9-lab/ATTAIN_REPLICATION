import os
# 锁定 GPU 0
os.environ["CUDA_VISIBLE_DEVICES"] = "1"

import json
import re
import torch
from openai import OpenAI
from sentence_transformers import SentenceTransformer, util
from multiprocessing import Process

class DualRAGClient:
    def __init__(self):
        # 模型物理路径
        p_path = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/all-MiniLM-L6-v2/my_model"
        i_path = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/flax-sentence-embeddings/my_model"
        
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        
        # 加载轻量化模型
        self.patch_model = SentenceTransformer(p_path).to(self.device)
        self.intro_model = SentenceTransformer(i_path).to(self.device)
        
        # 初始化 LLM 接口
        self.llm_client = OpenAI(
            api_key=os.getenv("CHATANYWHERE_API_KEY"), 
            base_url="https://api.chatanywhere.tech/v1"
        )

    def process_cve(self, cve_id, cve_info, input_dir, output_dir, k=3):
        cve_lower = cve_id.lower()
        asset_file = os.path.join(input_dir, f"{cve_lower}.json")
        if not os.path.exists(asset_file):
            return f"Skip: Missing {cve_id}"

        try:
            with open(asset_file, 'r', encoding='utf-8') as f:
                asset_data = json.load(f)
        except Exception as e:
            return f"Error: Read Failed {cve_id} - {e}"

        description = cve_info.get("description", "")
        version_pairs = cve_info.get("version_pair", [])
        final_results = []

        for idx, entry in enumerate(asset_data):
            # 自动切换逻辑
            is_patch = version_pairs[idx].get("seek_patch", True) if idx < len(version_pairs) else True
            model = self.patch_model if is_patch else self.intro_model
            
            commits = entry.get("api_data", {}).get("commits", [])
            if not commits: continue

            # 1. RAG 检索候选
            raw_msgs = [c.get("commit", {}).get("message", "") for c in commits]
            q_emb = model.encode(description, convert_to_tensor=True)
            m_embs = model.encode(raw_msgs, convert_to_tensor=True)
            
            scores = util.cos_sim(q_emb, m_embs)[0]
            top_k_val = min(20, len(raw_msgs))
            candidates = [raw_msgs[i] for i in torch.topk(scores, k=top_k_val).indices]

            # 2. LLM (DeepSeek-V3) 判定
            try:
                reply = self.llm_client.chat.completions.create(
                    model="deepseek-v3",
                    messages=[
                        {"role": "system", "content": "You are a security expert. Return ONLY a valid JSON array of strings. Escape quotes."},
                        {"role": "user", "content": f"CVE: {description}\nCandidates: {json.dumps(candidates)}\nPick top {k} {'FIX' if is_patch else 'INTRO'} commits."}
                    ],
                    temperature=0.0
                ).choices[0].message.content

                matched = []
                json_match = re.search(r'\[.*\]', reply, re.DOTALL)
                if json_match:
                    try:
                        items = json.loads(json_match.group(0))
                        for it in items:
                            msg_to_match = it.get("message", "").strip() if isinstance(it, dict) else str(it).strip()
                            for c in commits:
                                if msg_to_match in c["commit"]["message"]:
                                    matched.append({"sha": c["sha"], "url": c["url"]})
                                    break
                    except: pass
                
                final_results.append({
                    "base_tag": entry.get("base_tag"),
                    "head_tag": entry.get("head_tag"),
                    "seek_patch": is_patch,
                    "commit": matched[:k]
                })
            except Exception as e:
                print(f"!!! {cve_id} LLM Call Failed: {e}")

        # 3. 强制覆盖保存结果
        output_file = os.path.join(output_dir, f"{cve_lower}.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({cve_lower: final_results}, f, indent=2, ensure_ascii=False)
        return f"Done: {cve_id}"

def worker_task(worker_id, chunk, input_dir, output_dir):
    try:
        # 直接初始化 Client，不再需要补丁
        client = DualRAGClient()
        for cve_id, cve_info in chunk:
            msg = client.process_cve(cve_id, cve_info, input_dir, output_dir)
            print(f"[Worker {worker_id}] {msg}")
    except Exception as e:
        print(f"[Worker {worker_id}] Critical Failure: {e}")

def main():
    workspace = "/home/xinweimao/alv_evaluate/myResearch/workspace"
    input_asset = os.path.join(workspace, "dataset", "commit_asset")
    cve_list_json = os.path.join(workspace, "dataset", "list", "cve_list.json")
    output_dir = os.path.join(workspace, "dataset", "commit_url")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(cve_list_json, 'r', encoding='utf-8') as f:
        all_cves = json.load(f)

    items = list(all_cves.items())
    print(f"🚀 全量匹配开始: 共 {len(items)} 个任务")

    # 分配进程
    num_p = 5
    avg = (len(items) + num_p - 1) // num_p
    chunks = [items[i:i + avg] for i in range(0, len(items), avg)]
    
    procs = []
    for i in range(len(chunks)):
        if chunks[i]:
            p = Process(target=worker_task, args=(i, chunks[i], input_asset, output_dir))
            p.start()
            procs.append(p)
            
    for p in procs:
        p.join()

    print("✅ 全量任务执行完毕。")

if __name__ == "__main__":
    main()