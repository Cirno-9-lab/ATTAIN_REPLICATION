import json
import os

def process_cve_analysis(json_path):
    if not os.path.exists(json_path):
        print(f"❌ 找不到分析结果文件: {json_path}")
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("❌ JSON 文件格式错误")
            return

    print(f"{'CVE ID':<20} | {'Base Tag':<15} | {'Head Tag':<15} | {'Result'}")
    print("-" * 80)

    # 遍历所有 CVE
    for cve_id, version_list in data.items():
        found_unknown_global = False
        
        for entry in version_list:
            base_tag = entry.get("base_tag", "N/A")
            head_tag = entry.get("head_tag", "N/A")
            analysis_data = entry.get("analysis", {})

            is_vulnerable = False
            
            # 检查当前 entry 下的所有 commit 和文件
            for commit_hash, files in analysis_data.items():
                for file_path, verdict in files.items():
                    v_clean = str(verdict).strip().lower()
                    
                    # --- 中止逻辑核心 ---
                    if "unknown" in v_clean:
                        print(f"\n⚠️  在 {cve_id} 的文件中检测到 'unknown'。")
                        print(f"📍 位置: {file_path}")
                        print("🚫 正在中止所有后续输出...")
                        return  # 直接退出函数，中止当前及之后所有 CVE 的处理
                    # ------------------

                    if v_clean in ["yes", "true", "vulnerable"]:
                        is_vulnerable = True

            status = "🔴 VULNERABLE" if is_vulnerable else "🟢 SECURE"
            print(f"{cve_id:<20} | {base_tag:<15} | {head_tag:<15} | {status}")

def main():
    # 请根据实际路径修改
    RESULT_PATH = os.path.join("myResearch", "workspace", "dataset", "result", "cve_analysis_results.json")
    process_cve_analysis(RESULT_PATH)

if __name__ == "__main__":
    main()