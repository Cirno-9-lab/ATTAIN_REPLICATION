import json
import os
import re

def analyze_single_cve_file(input_file_path, base_input_dir, base_output_dir):
    """
    读取单个CVE数据文件，统计version_type和status的组合情况，并列出对应的版本号。
    
    Args:
        input_file_path (str): 输入JSON文件的绝对路径。
        base_input_dir (str): 输入根目录的绝对路径，用于计算相对路径。
        base_output_dir (str): 输出根目录的绝对路径。
    """
    
    # 1. 动态构建输出文件路径
    # 获取相对于 base_input_dir 的路径，即 CVE-{}-{}.json
    relative_path = os.path.relpath(input_file_path, base_input_dir)
    # 构建输出文件的绝对路径
    output_file_path = os.path.join(base_output_dir, relative_path)

    # 确保输出目录存在
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

    try:
        with open(input_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"错误：未找到文件 {input_file_path}。跳过此文件。")
        return
    except json.JSONDecodeError:
        print(f"错误：文件 {input_file_path} 不是有效的JSON格式。跳过此文件。")
        return

    cve_id = data.get("cve_id", os.path.basename(input_file_path).replace(".json", ""))
    results_by_version = data.get("results_by_version", [])

    # 初始化计数器和版本列表
    counts_with_versions = {
        "affected_成功": {"count": 0, "versions": []},
        "affected_失败": {"count": 0, "versions": []},
        "unaffected_成功": {"count": 0, "versions": []},
        "unaffected_失败": {"count": 0, "versions": []},
        "unknown_成功": {"count": 0, "versions": []},
        "unknown_失败": {"count": 0, "versions": []}
    }

    for result in results_by_version:
        version_type = result.get("version_type", "unknown")
        status = result.get("status", "未知")
        version = result.get("version", "未知版本")

        key = f"{version_type}_{status}"
        
        if key in counts_with_versions:
            counts_with_versions[key]["count"] += 1
            counts_with_versions[key]["versions"].append(version)

    output_data = {
        "cve_id": cve_id,
        "statistics": {}
    }

    for combo, data_stats in counts_with_versions.items():
        output_data["statistics"][combo] = {
            "count": data_stats["count"],
            "versions": data_stats["versions"]
        }

    with open(output_file_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print(f"已处理文件：{input_file_path}")
    print(f"统计结果保存到：{output_file_path}")
    print("-" * 30)

def main():
    """
    主入口函数：根据脚本路径计算输入输出目录的绝对路径，并开始批量处理。
    """
    # 1. 根据脚本路径动态计算 Workspace 路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    code_dir = os.path.dirname(script_dir) 
    workspace_dir = os.path.dirname(code_dir) # /.../workspace

    # 2. 定义输入和输出文件夹相对于 workspace_dir 的路径
    relative_input_dir = 'dataset/ver_test/'
    relative_output_dir = 'dataset/ver_test_stat/'

    # 3. 计算输入和输出文件夹的绝对路径
    input_directory = os.path.join(workspace_dir, relative_input_dir)
    output_directory = os.path.join(workspace_dir, relative_output_dir)
    
    # 打印路径信息以供确认
    print(f"Workspace 目录: {workspace_dir}")
    print(f"输入目录 (ver_test): {input_directory}")
    print(f"输出目录 (ver_test_stat): {output_directory}")
    print("=" * 50)
    
    if not os.path.isdir(input_directory):
        print(f"错误：输入目录 '{input_directory}' 不存在。请检查路径。")
        return

    print(f"开始处理目录 '{input_directory}' 下的所有CVE文件...")
    
    processed_count = 0
    # 遍历目录下的所有文件
    for filename in os.listdir(input_directory):
        # 使用正则表达式匹配 CVE-YYYY-NNNN.json 格式的文件
        if re.match(r"CVE-\d{4}-\d+\.json", filename):
            input_file_path = os.path.join(input_directory, filename)
            
            # 调用分析函数，传入所有必要的路径信息
            analyze_single_cve_file(input_file_path, input_directory, output_directory)
            processed_count += 1
            
    if processed_count == 0:
        print(f"在目录 '{input_directory}' 中没有找到符合 'CVE-YYYY-NNNN.json' 命名模式的文件。")
    else:
        print(f"已完成对 {processed_count} 个CVE文件的统计分析。")

if __name__ == "__main__":
    main()