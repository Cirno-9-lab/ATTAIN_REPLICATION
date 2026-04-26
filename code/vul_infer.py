import os
import json
import torch
from sentence_transformers import SentenceTransformer, util

# 配置：使用 GPU 5（可根据需要修改）
os.environ["CUDA_VISIBLE_DEVICES"] = "5"

class DualRAGClient:
    def __init__(self):
        p_path = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/all-MiniLM-L6-v2/my_model"
        i_path = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/flax-sentence-embeddings/my_model"
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.patch_model = SentenceTransformer(p_path).to(self.device)
        self.intro_model = SentenceTransformer(i_path).to(self.device)

    def compute_similarity(self, description, commit_message, is_patch):
        """计算描述与单个commit message的相似度"""
        model = self.patch_model if is_patch else self.intro_model
        emb_desc = model.encode(description, convert_to_tensor=True)
        emb_msg = model.encode(commit_message, convert_to_tensor=True)
        sim = util.cos_sim(emb_desc, emb_msg).item()
        return sim

def format_diff(details):
    """保持与原代码相同的diff格式化函数（此处未使用，但保留以兼容）"""
    deleted = details.get("modified_deleted_content", [])
    added = details.get("modified_added_content", [])
    return "\n".join([f"- {l.strip()}" for l in deleted] + [f"+ {l.strip()}" for l in added])

def process_cve_group(cve_ids, cve_list_meta, rag_client, templates=None, dataset_dir=None):
    """
    使用RAG处理一组CVE，输出结果结构与原代码一致：
    - 每个版本对包含 mode, if_finished (始终 True), analysis
    - analysis 为 {commit_hash: {file_path: 相似度字符串}}
    注意：templates 和 dataset_dir 在此未使用，但保留参数以保持接口兼容。
    """
    all_results = {}

    for cve_id in cve_ids:
        cve_l = cve_id.lower()
        meta = cve_list_meta.get(cve_id, {})
        desc = meta.get("DESCRIPTION") or meta.get("description", "No description available.")
        version_pairs = meta.get("version_pair", [])

        info_path = os.path.join(dataset_dir, "commit_info", f"{cve_l}.json")
        ctx_path = os.path.join(dataset_dir, "commit_context", f"{cve_l}.json")
        if not (os.path.exists(info_path) and os.path.exists(ctx_path)):
            print(f"跳过 {cve_id}：缺少 commit_info 或 commit_context 文件")
            continue

        info_vps = json.load(open(info_path, encoding='utf-8')).get(cve_l, [])
        ctx_vps = json.load(open(ctx_path, encoding='utf-8')).get(cve_l, [])

        cve_out = []
        print(f"\n🚀 [RAG 初步筛选] {cve_id}")

        for i, vp_meta in enumerate(version_pairs):
            mode = "patch" if vp_meta.get("seek_patch", False) else "intro"
            vp_analysis = {"mode": mode, "if_finished": True, "analysis": {}}

            commits = info_vps[i].get("commit_info", {}) if i < len(info_vps) else {}
            diff_results = ctx_vps[i].get("results", {}) if i < len(ctx_vps) else {}

            for hsh, info in commits.items():
                commit_msg = info.get("message", "")
                # 计算相似度
                sim = rag_client.compute_similarity(desc, commit_msg, is_patch=(mode == "patch"))
                sim_str = f"{sim:.4f}"  # 保留4位小数作为字符串

                print(f"  │  ├─ 📑 Commit: {hsh[:7]} ({mode.upper()}) 相似度: {sim_str}")

                # 获取该commit对应的所有文件（从diff_results中）
                files_diff = diff_results.get(hsh, {})
                hsh_res = {}
                for f_path in files_diff.keys():
                    hsh_res[f_path] = sim_str  # 同一commit下所有文件赋予相同相似度

                if hsh_res:
                    vp_analysis["analysis"][hsh] = hsh_res
                else:
                    # 如果没有文件（可能diff为空），仍记录一个空字典
                    vp_analysis["analysis"][hsh] = {}

            cve_out.append(vp_analysis)

        all_results[cve_id] = cve_out
        # 原代码有提前终止逻辑，RAG 无终止信号，故不检查

    return all_results

def main():
    # 初始化 RAG 客户端
    rag_client = DualRAGClient()
    print("RAG 模型加载完成。")

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATASET_DIR = os.path.join(os.path.dirname(BASE_DIR), "dataset")
    OUTPUT_PATH = os.path.join(DATASET_DIR, "result", "cve_final_minimal.json")

    # 加载 CVE 元数据
    cve_list_path = os.path.join(DATASET_DIR, "list", "cve_list.json")
    if not os.path.exists(cve_list_path):
        print(f"错误：CVE 列表文件不存在：{cve_list_path}")
        return
    cve_list_meta = json.load(open(cve_list_path, encoding='utf-8'))

    # 指定要处理的 CVE（可修改为列表）
    target_cve = "CVE-2011-2732"
    # target_cves = ["CVE-2018-8009", "CVE-2023-42503"]  # 多CVE示例

    # 处理
    results = process_cve_group(
        cve_ids=[target_cve],
        cve_list_meta=cve_list_meta,
        rag_client=rag_client,
        templates=None,          # 未使用
        dataset_dir=DATASET_DIR   # 用于定位 commit_info/commit_context
    )

    # 保存结果
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"\n✅ RAG 初步筛选完成，结果已保存至：{OUTPUT_PATH}")

if __name__ == "__main__":
    main()