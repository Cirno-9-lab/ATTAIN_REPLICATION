import os
import pandas as pd
import requests
from bs4 import BeautifulSoup
import json
import re

# --- 目录配置 ---
# 假设脚本位于 /.../workspace/code/1.groundtruth/
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path) 
code_dir = os.path.dirname(script_dir) 
workspace_dir = os.path.dirname(code_dir) 

# --- 输入/输出文件路径 ---
# 目标 Excel 文件路径: /.../workspace/dataset/cve_dataset.xlsx
excel_file_path = os.path.join(workspace_dir, "dataset", "cve_dataset.xlsx")
# 输出 JSON 文件路径: /.../workspace/dataset/cve_maven_version.json
output_json_path = os.path.join(workspace_dir, "dataset", "cve_maven_version.json")

# Maven 中央仓库的基础 URL
MAVEN_BASE_URL = "https://repo1.maven.org/maven2/"

def version_sort_key(version_str):
    """
    版本排序键：使用 (优先级, 值) 元组结构，彻底消除 int 和 str 比较的 TypeError。
    确保数值化版本排序正确，且预发布版本位于最终版本之后、下一个主版本之前。
    """
    version_str = str(version_str)
    
    # 将版本号中的短横线 (-) 替换为点号 (.), 便于统一分割
    normalized_str = version_str.replace('-', '.')
    
    key = []

    # 1. Main Version & Qualifiers Parts
    # 将版本号按点号分割，并尝试将每个部分转换为 (type_id, value)
    for part in normalized_str.split('.'):
        if not part:
            continue
            
        # 尝试将整个部分视为整数
        try:
            # Type 0: 数值部分 (优先级 0，最高)
            key.append((0, int(part)))
        except ValueError:
            # 如果不是纯数字，则尝试进一步分割，看是否包含数字
            sub_parts = re.split('(\d+)', part)
            
            # 使用一个标志来处理完全非数字的字符串部分（如 'dev'）
            has_sub_parts = False 
            for sub_part in sub_parts:
                if not sub_part:
                    continue
                
                try:
                    # Type 0: 字符串中的数值部分
                    key.append((0, int(sub_part)))
                except ValueError:
                    # Type 1: 字符串部分 (优先级 1，较低，按字母序)
                    key.append((1, sub_part.lower()))
                has_sub_parts = True
            
            # 极端情况：如果版本部分（如 'dev'）没有被 re.split 细分
            if not has_sub_parts and part.strip():
                key.append((1, part.lower()))

    # 2. Release Status Marker (确保预发布版本在最终版本前)
    # 查找版本中是否含有常见的预发布/快照字符串，这比正则表达式更健壮
    is_prerelease = bool(re.search(r'alpha|beta|rc|m|milestone|snapshot|dev|final', version_str, re.IGNORECASE) and 
                         not re.search(r'final', version_str, re.IGNORECASE)) # 'final'是例外
    
    # 插入一个标记：(0, 1) > (0, 0)，确保最终版排在预发布版后面
    if is_prerelease:
        key.append((0, 0)) # 预发布标记：优先级低
    else:
        key.append((0, 1)) # 最终版标记：优先级高
        
    # 如果版本号极不规范，导致 key 为空 (理论上不应发生)，给一个极低的排序键
    if not key:
        return [(2, 0), (1, version_str)] 

    # 返回最终的、安全的、由元组组成的列表
    return key


def get_maven_versions(group_id: str, artifact_id: str) -> list:
    """
    根据 group_id 和 artifact_id 爬取 Maven 库的所有版本号，并进行数值化排序。
    """
    url_path = group_id.replace('.', '/') + '/' + artifact_id + '/'
    full_url = MAVEN_BASE_URL + url_path
    
    print(f"-> 尝试爬取: {full_url}")
    
    # 定义更宽松的版本正则表达式
    VERSION_PATTERN = re.compile(r'^[a-zA-Z0-9]+([a-zA-Z0-9.\-])*[a-zA-Z0-9]$') 
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(full_url, headers=headers, timeout=15)
        response.raise_for_status() 
        
        soup = BeautifulSoup(response.content, 'html.parser')
        versions = []
        
        for link in soup.find_all('a'):
            href = link.get('href')
            
            if href and href.endswith('/') and not href.startswith('../') and not href.startswith('maven-metadata.xml'):
                version = href[:-1]
                
                if VERSION_PATTERN.match(version):
                    versions.append(version)
        
        unique_versions = list(set(versions))
        
        # 使用修复后的 version_sort_key 函数进行版本排序
        sorted_versions = sorted(unique_versions, key=version_sort_key)
        
        return sorted_versions
        
    except requests.exceptions.RequestException as e:
        print(f"!!! 爬取 {full_url} 失败: {e}")
        return []

def main():
    """
    主函数：读取 Excel 文件，按 cve_id 分组爬取版本，并保存到指定格式的 JSON 文件。
    """
    if not os.path.exists(excel_file_path):
        print(f"错误：输入文件不存在于 {excel_file_path}")
        return

    try:
        # 使用 usecols 确保只读取需要的列，如果文件很大可以节省内存
        df = pd.read_excel(excel_file_path, sheet_name=0, header=0, usecols=['cve_id', 'target_group_id', 'target_artifact_id'])
        df = df.dropna(subset=['cve_id', 'target_group_id', 'target_artifact_id'])
    except Exception as e:
        print(f"读取 Excel 文件失败: {e}")
        return

    required_cols = ['cve_id', 'target_group_id', 'target_artifact_id']
    if not all(col in df.columns for col in required_cols):
        print(f"错误：Excel 文件中缺少必要的列。需要: {required_cols}")
        return

    # 按 cve_id 分组，只取第一条记录，以确保每个 CVE ID 只爬取一次
    cve_groups = df.groupby('cve_id').first().reset_index()

    print(f"总共找到 {len(cve_groups)} 个唯一的 CVE 条目需要处理...")

    cve_version_map = {}
    
    for i, row in cve_groups.iterrows():
        cve_id = str(row['cve_id']).strip()
        group_id = str(row['target_group_id']).strip()
        artifact_id = str(row['target_artifact_id']).strip()

        if not cve_id or not group_id or not artifact_id:
            continue
            
        print(f"\n[{i+1}/{len(cve_groups)}] 处理 CVE ID: {cve_id}")
        print(f"  关联库: {group_id}:{artifact_id}")
        
        versions = get_maven_versions(group_id, artifact_id)
        
        cve_version_map[cve_id] = versions
        
        print(f"  找到版本数量: {len(versions)}")

    try:
        os.makedirs(os.path.dirname(output_json_path), exist_ok=True)
        with open(output_json_path, 'w', encoding='utf-8') as f:
            json.dump(cve_version_map, f, ensure_ascii=False, indent=4)
        print(f"\n--- 任务完成 ---")
        print(f"结果已成功保存到: {output_json_path}")
        print(f"总共处理了 {len(cve_version_map)} 个 CVE ID。")
    except Exception as e:
        print(f"保存 JSON 文件失败: {e}")

if __name__ == "__main__":
    main()