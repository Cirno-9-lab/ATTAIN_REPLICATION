import os
# 强制所有子进程使用 GPU 2（环境变量会被继承）
os.environ["CUDA_VISIBLE_DEVICES"] = "2"

import json
import re
import torch
from sentence_transformers import SentenceTransformer, util
from openai import OpenAI
from llm import Client  # 请确保此模块可用
from multiprocessing import Pool, Manager
import math

# ------------------- 配置参数 -------------------
RAG_THRESHOLD = 0.5          # RAG 判定阈值
NUM_PROCESSES = 5            # 并行进程数
# ------------------------------------------------

class DualRAGClient:
    """用于 RAG 判定的客户端（基于 SentenceTransformer）"""
    def __init__(self):
        p_path = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/all-MiniLM-L6-v2/my_model"
        i_path = "/home/xinweimao/alv_evaluate/myResearch/workspace/model/flax-sentence-embeddings/my_model"
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        
        # 加载模型
        self.patch_model = SentenceTransformer(p_path).to(self.device)
        self.intro_model = SentenceTransformer(i_path).to(self.device)

    def compute_max_similarity(self, description, commit_messages, is_patch):
        """计算描述与所有 commit message 的最大余弦相似度"""
        if not commit_messages:
            return 0.0
        model = self.patch_model if is_patch else self.intro_model
        q_emb = model.encode(description, convert_to_tensor=True)
        m_embs = model.encode(commit_messages, convert_to_tensor=True)
        scores = util.cos_sim(q_emb, m_embs)[0]
        return scores.max().item()

def format_diff(details):
    """将 diff 内容格式化为带 +/- 的文本"""
    deleted = details.get("modified_deleted_content", [])
    added = details.get("modified_added_content", [])
    return "\n".join([f"- {l.strip()}" for l in deleted] + [f"+ {l.strip()}" for l in added])

def process_cve_group(cve_ids, cve_list_meta, llm_client, templates, dataset_dir,
                      rag_client=None, rag_threshold=RAG_THRESHOLD, lock=None):
    """
    处理一组 CVE，先进行 RAG 初筛，再对通过的版本对进行 LLM 细审。
    返回两个字典：
        - all_results: 完整审计结果
        - rag_only_results: 仅包含 RAG 判定结果的简化字典
    lock: 用于同步控制台输出的 multiprocessing.Lock（可选）
    """
    def safe_print(*args, **kwargs):
        if lock:
            with lock:
                print(*args, **kwargs)
        else:
            print(*args, **kwargs)

    all_results = {}
    rag_only_results = {}

    for cve_id in cve_ids:
        cve_l = cve_id.lower()
        meta = cve_list_meta.get(cve_id, {})
        desc = meta.get("DESCRIPTION") or meta.get("description", "No description available.")
        version_pairs = meta.get("version_pair", [])
        
        # 加载资产数据（用于 RAG 初筛）
        asset_path = os.path.join(dataset_dir, "commit_asset", f"{cve_l}.json")
        if rag_client and not os.path.exists(asset_path):
            safe_print(f"⚠️  {cve_id} 资产文件不存在，将跳过 RAG 初筛（视为全部通过）")
            asset_data = None
        elif rag_client:
            with open(asset_path, 'r', encoding='utf-8') as f:
                asset_data = json.load(f)
        else:
            asset_data = None

        # 加载 commit_info 和 commit_context（用于 LLM 细审）
        info_path = os.path.join(dataset_dir, "commit_info", f"{cve_l}.json")
        ctx_path = os.path.join(dataset_dir, "commit_context", f"{cve_l}.json")
        if not (os.path.exists(info_path) and os.path.exists(ctx_path)):
            safe_print(f"❌ 跳过 {cve_id}：缺少 commit_info 或 commit_context 文件")
            continue

        info_vps = json.load(open(info_path, encoding='utf-8')).get(cve_l, [])
        ctx_vps = json.load(open(ctx_path, encoding='utf-8')).get(cve_l, [])

        cve_out = []
        rag_cve_list = []
        safe_print(f"\n🚀 [审计] {cve_id} 开始处理")

        for i, vp_meta in enumerate(version_pairs):
            mode = "patch" if vp_meta.get("seek_patch", False) else "intro"
            vp_analysis = {
                "mode": mode,
                "rag_verdict": None,
                "rag_max_sim": None,
                "if_finished": False,
                "analysis": {}
            }

            # ----- RAG 初筛 -----
            if rag_client and asset_data is not None:
                if i < len(asset_data):
                    commits = asset_data[i].get("api_data", {}).get("commits", [])
                    commit_msgs = [c.get("commit", {}).get("message", "") for c in commits if c.get("commit")]
                else:
                    commit_msgs = []

                max_sim = rag_client.compute_max_similarity(desc, commit_msgs, is_patch=(mode=="patch"))
                vp_analysis["rag_max_sim"] = max_sim
                if max_sim < rag_threshold:
                    vp_analysis["rag_verdict"] = "no"
                    vp_analysis["if_finished"] = True
                    safe_print(f"  │  ├─ [RAG] 版本对 {i} 最大相似度 {max_sim:.3f} < {rag_threshold}，判定为 no，跳过细审")
                else:
                    vp_analysis["rag_verdict"] = "yes"
                    safe_print(f"  │  ├─ [RAG] 版本对 {i} 最大相似度 {max_sim:.3f} >= {rag_threshold}，进入 LLM 细审")
            else:
                vp_analysis["rag_verdict"] = "skip"
                safe_print(f"  │  ├─ [RAG] 版本对 {i} 未启用初筛，直接进入 LLM 细审")

            # 记录 RAG 结果
            rag_cve_list.append({
                "version_pair_index": i,
                "mode": mode,
                "rag_verdict": vp_analysis["rag_verdict"],
                "rag_max_sim": vp_analysis["rag_max_sim"]
            })

            # ----- LLM 细审 -----
            if vp_analysis["rag_verdict"] in ("yes", "skip"):
                commits = info_vps[i].get("commit_info", {}) if i < len(info_vps) else {}
                diff_results = ctx_vps[i].get("results", {}) if i < len(ctx_vps) else {}

                stop_all = False  # <--- 在这里初始化 stop_all，确保变量被定义
                for hsh, info in commits.items():
                    safe_print(f"  │  ├─ 📑 Commit: {hsh[:7]} ({mode.upper()})")
                    hsh_res = {}
                    files_diff = diff_results.get(hsh, {})

                    for f_path, diff_content in files_diff.items():
                        file_name = os.path.basename(f_path)
                        diff_text = format_diff(diff_content)
                        if not diff_text.strip():
                            continue

                        safe_print(f"  │  │  └─ 🤖 审计中: {file_name}...", end="", flush=True)

                        try:
                            raw_reply = llm_client.call_llm(templates[mode].format(
                                cve_description=desc,
                                commit_message=info.get("message", ""),
                                commit_diff_content=diff_text
                            ))
                        except Exception as e:
                            safe_print(f" [API 调用失败: {e}]")
                            hsh_res[f_path] = "error"
                            continue

                        if raw_reply == "STOP_SIGNAL":
                            safe_print(" 收到停止信号，终止处理。")
                            stop_all = True
                            break

                        verdict = "no"
                        if re.search(r'\[CLASSIFICATION\]\s*YES\s*\[/CLASSIFICATION\]', raw_reply, re.IGNORECASE):
                            verdict = "yes"

                        hsh_res[f_path] = verdict
                        safe_print(f" [{verdict.upper()}]")

                    if stop_all:
                        break
                    vp_analysis["analysis"][hsh] = hsh_res

                vp_analysis["if_finished"] = not stop_all

            cve_out.append(vp_analysis)
            if stop_all:  # 注意：如果 stop_all 未定义，此处会报错，但我们已经在上面的分支中定义了，所以安全
                break

        all_results[cve_id] = cve_out
        rag_only_results[cve_id] = rag_cve_list

        if any(not vp.get("if_finished") for vp in cve_out):
            safe_print(f"⚠️  {cve_id} 因停止信号提前终止，后续 CVE 不再处理")
            break

    return all_results, rag_only_results

def worker_process(cve_chunk, templates_dir, dataset_dir, rag_threshold, lock):
    """
    每个进程的工作函数：处理分配给它的 CVE 块。
    """
    # 重新加载模板
    templates = {}
    for mode in ["patch", "intro"]:
        path = os.path.join(templates_dir, f"prompt_{mode}.txt")
        with open(path, 'r', encoding='utf-8') as f:
            templates[mode] = f.read()

    # 重新加载 CVE 元数据（只取需要的部分，但这里加载全部也无妨）
    cve_list_path = os.path.join(dataset_dir, "list", "cve_list.json")
    with open(cve_list_path, 'r', encoding='utf-8') as f:
        full_meta = json.load(f)

    # 初始化客户端（每个进程独立）
    rag_client = DualRAGClient()
    llm_client = Client()

    # 处理
    full_results, rag_results = process_cve_group(
        cve_ids=cve_chunk,
        cve_list_meta=full_meta,
        llm_client=llm_client,
        templates=templates,
        dataset_dir=dataset_dir,
        rag_client=rag_client,
        rag_threshold=rag_threshold,
        lock=lock
    )
    return full_results, rag_results

def main():
    # 路径设置
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATASET_DIR = os.path.join(os.path.dirname(BASE_DIR), "dataset")
    TEMPLATES_DIR = BASE_DIR  # 假设模板文件在脚本同级目录
    RESULT_DIR = os.path.join(DATASET_DIR, "result")
    os.makedirs(RESULT_DIR, exist_ok=True)

    # 加载 CVE 元数据（仅用于获取所有CVE列表，实际每个进程会重新加载）
    cve_list_path = os.path.join(DATASET_DIR, "list", "cve_list.json")
    if not os.path.exists(cve_list_path):
        print(f"❌ CVE 列表文件不存在：{cve_list_path}")
        return
    with open(cve_list_path, 'r', encoding='utf-8') as f:
        all_cves_meta = json.load(f)

    # 指定要处理的 CVE（可修改为列表）
    target_cves = ["CVE-2011-2732"]  # 示例，可改为多个
    # target_cves = ["CVE-2018-8009", "CVE-2023-42503"]

    # 过滤出实际存在的 CVE
    target_cves = [cve for cve in target_cves if cve in all_cves_meta]
    if not target_cves:
        print("❌ 没有有效的目标 CVE。")
        return

    print(f"📋 目标 CVE 总数：{len(target_cves)}")
    print(f"🔄 将使用 {NUM_PROCESSES} 个进程并行处理")

    # 将 CVE 列表均匀分块
    chunk_size = math.ceil(len(target_cves) / NUM_PROCESSES)
    chunks = [target_cves[i:i+chunk_size] for i in range(0, len(target_cves), chunk_size)]

    # 使用 Manager 创建可序列化的锁
    manager = Manager()
    print_lock = manager.Lock()

    # 准备进程池参数：每个进程需要 (chunk, templates_dir, dataset_dir, RAG_THRESHOLD, lock)
    args_list = [(chunk, TEMPLATES_DIR, DATASET_DIR, RAG_THRESHOLD, print_lock) for chunk in chunks if chunk]

    # 使用进程池执行
    with Pool(processes=min(NUM_PROCESSES, len(args_list))) as pool:
        # starmap 会阻塞直到所有任务完成，返回结果列表
        results = pool.starmap(worker_process, args_list)

    # 合并所有进程的结果
    full_combined = {}
    rag_combined = {}
    for full_part, rag_part in results:
        full_combined.update(full_part)
        rag_combined.update(rag_part)

    # 保存完整审计结果
    full_output_path = os.path.join(RESULT_DIR, "cve_final_minimal.json")
    with open(full_output_path, 'w', encoding='utf-8') as f:
        json.dump(full_combined, f, indent=4, ensure_ascii=False)
    print(f"\n✅ 完整审计结果已保存至：{full_output_path}")

    # 保存 RAG 初筛结果
    rag_output_path = os.path.join(RESULT_DIR, "rag_result.json")
    with open(rag_output_path, 'w', encoding='utf-8') as f:
        json.dump(rag_combined, f, indent=4, ensure_ascii=False)
    print(f"✅ RAG 初筛结果已保存至：{rag_output_path}")

if __name__ == "__main__":
    main()