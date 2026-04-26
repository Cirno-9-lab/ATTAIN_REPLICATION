import requests
import json
import os
import sys

# --- 辅助函数：将 Web URL 转换为 API URL 并调用 ---

def get_info_from_compare_url(web_url, github_token):
    """
    将 github.com 链接转换为 api.github.com 请求并获取数据。
    """
    if "github.com" in web_url and "api.github.com" not in web_url:
        api_url = web_url.replace("github.com", "api.github.com/repos")
    else:
        api_url = web_url

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"    [❌ ERROR] API 请求失败: {http_err}")
        return {"error": str(http_err), "source_url": web_url}
    except Exception as e:
        print(f"    [❌ ERROR] 发生异常: {e}")
        return {"error": str(e), "source_url": web_url}

# --- 主执行逻辑 ---

if __name__ == "__main__":
    # 1. 环境准备
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        print("致命错误：GITHUB_TOKEN 环境变量未设置。")
        sys.exit(1)

    # 路径计算
    script_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_dir = os.path.dirname(script_dir)
    
    INPUT_FILE_PATH = os.path.join(workspace_dir, "dataset", "list", "cve_list.json")
    OUTPUT_BASE_DIR = os.path.join(workspace_dir, "dataset", "commit_asset")

    if not os.path.exists(INPUT_FILE_PATH):
        print(f"致命错误：找不到输入文件 {INPUT_FILE_PATH}")
        sys.exit(1)

    if not os.path.exists(OUTPUT_BASE_DIR):
        os.makedirs(OUTPUT_BASE_DIR)

    # 2. 加载数据
    try:
        with open(INPUT_FILE_PATH, 'r', encoding='utf-8') as f:
            cve_dict = json.load(f)
    except Exception as e:
        print(f"致命错误：解析 JSON 失败: {e}")
        sys.exit(1)

    # 3. 遍历 CVE 和对应的版本对
    for cve_id, cve_info in cve_dict.items():
        version_pairs = cve_info.get("version_pair", [])
        cve_results_collection = []

        print(f"\n🔍 正在分析 {cve_id}...")

        for pair in version_pairs:
            base_tag = pair.get("BASE_TAG")
            head_tag = pair.get("HEAD_TAG")
            compare_url = pair.get("COMPARE_URL")
            
            # 过滤 unknown 和 无效链接
            if not compare_url or str(compare_url).strip().lower() == "unknown":
                print(f"    [⏩ SKIP] 跳过无效链接: {compare_url}")
                continue
            
            print(f"    🚀 抓取中: {base_tag} -> {head_tag}")
            
            # 获取 API 数据
            compare_data = get_info_from_compare_url(compare_url, GITHUB_TOKEN)
            
            # --- 关键修改：按顺序构造字典，确保 Tag 信息在最前面 ---
            result_item = {
                "base_tag": base_tag,
                "head_tag": head_tag,
                "compare_url": compare_url,
                "api_data": compare_data
            }
            cve_results_collection.append(result_item)

        # 4. 保存文件
        if cve_results_collection:
            output_filename = f"{cve_id.lower()}.json"
            output_path = os.path.join(OUTPUT_BASE_DIR, output_filename)

            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    # 使用 indent=4 让输出格式化，方便阅读
                    json.dump(cve_results_collection, f, ensure_ascii=False, indent=4)
                print(f"    ✅ 已汇总保存至: {output_path}")
            except Exception as e:
                print(f"    ❌ 写入文件失败: {e}")
        else:
            print(f"    ⚠️ {cve_id} 无有效数据，未生成文件。")

    print("\n--- 任务处理完毕 ---")