import json
import os
import glob
import pandas as pd
from collections import defaultdict
from settings import BASIC_INFO_DIR

def get_full_filename_cve_stats():
    """
    统计非 .java 的完整文件名及其关联的 CVE ID
    """
    # key: 完整文件名 (如 pom.xml), value: set(cve_id)
    file_map = defaultdict(set)
    
    json_files = glob.glob(os.path.join(BASIC_INFO_DIR, "*.json"))
    
    if not json_files:
        print(f"[-] 错误：在 {BASIC_INFO_DIR} 路径下未找到 JSON 文件。")
        return None

    for file_path in json_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 获取 CVE ID，优先从内容取，否则从文件名取
            cve_id = data.get("cve_id", os.path.basename(file_path).replace(".json", ""))
            findings = data.get("findings", [])
            
            for item in findings:
                files = item.get("modified_files", [])
                for file_path_name in files:
                    # 获取纯文件名，去除路径前缀
                    full_name = os.path.basename(file_path_name.strip())
                    
                    if not full_name:
                        continue
                    
                    # 过滤掉所有 Java 源文件
                    if full_name.lower().endswith('.java'):
                        continue
                    
                    # 记录完整文件名与 CVE 的对应关系
                    file_map[full_name].add(cve_id)
                        
        except Exception as e:
            print(f" [!] 处理文件 {file_path} 时出错: {e}")

    return file_map

def main():
    file_stats = get_full_filename_cve_stats()
    
    if file_stats:
        output_list = []
        for filename, cve_set in file_stats.items():
            sorted_cves = sorted(list(cve_set))
            output_list.append({
                "Full Filename": filename,
                "CVE Count": len(sorted_cves),
                "Associated CVEs": ", ".join(sorted_cves)
            })
        
        # 转换为 DataFrame
        df = pd.DataFrame(output_list)
        
        # 按照关联的 CVE 数量降序排列，如果数量相同则按文件名升序
        df = df.sort_values(by=["CVE Count", "Full Filename"], ascending=[False, True])

        print("\n=== 非 Java 完整文件名与 CVE 关联明细 ===")
        # 设置 Pandas 打印选项以展示完整内容
        pd.set_option('display.max_colwidth', None)
        pd.set_option('display.max_rows', None) # 展示所有行
        
        if not df.empty:
            print(df.to_string(index=False))
        else:
            print("[!] 没有发现非 .java 的修改文件。")
        
        # 建议导出为 Excel，方便后续筛选无用文件（如 README.md）
        # df.to_excel("non_java_files_full_report.xlsx", index=False)

if __name__ == "__main__":
    main()