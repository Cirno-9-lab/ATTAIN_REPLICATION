# import os
# from setting import *
# import argparse
# from identify_duplicated_patch import batch_duplicate_detection

# parser = argparse.ArgumentParser()
# parser.add_argument('repo')
# repo = parser.parse_args().repo

# projects = ['FFmpeg', 'openssl', 'wireshark', 'linux', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg']




# for project in projects:
#     if repo != project:
#         continue
#     batch_duplicate_detection([project])

import os
import json
import argparse
from setting import DATA_FOLDER, WORK_DIR
from identify_duplicated_patch import batch_duplicate_detection

def main():
    # 1. 动态加载所有项目名称（与 main.py 和 step2.py 保持逻辑一致）
    # 假设 dataset_o.json 存放在 data 目录下
    dataset_path = os.path.join('data', 'dataset_o.json')
    
    if not os.path.exists(dataset_path):
        print(f"错误: 找不到数据集文件 {dataset_path}")
        # 如果找不到，尝试从 DATA_FOLDER 寻找
        dataset_path = os.path.join(DATA_FOLDER, 'dataset_o.json')

    try:
        with open(dataset_path, 'r', encoding='utf-8') as f:
            dataset_entries = json.load(f)
        all_projects = sorted(list(set(entry['repo_name'] for entry in dataset_entries)))
    except Exception as e:
        print(f"读取数据集失败: {e}")
        return

    # 2. 设置命令行参数
    parser = argparse.ArgumentParser(description="生成补丁哈希映射（识别重复提交）")
    parser.add_argument('--repo', type=str, help='指定处理单个项目名，若不指定则处理所有项目')
    args = parser.parse_args()

    # 3. 确定要处理的项目范围
    if args.repo:
        projects_to_process = [args.repo]
    else:
        projects_to_process = all_projects

    # 4. 确保输出目录存在
    patch_map_dir = os.path.join(WORK_DIR, 'data_commit_patch_map')
    if not os.path.exists(patch_map_dir):
        os.makedirs(patch_map_dir)
        print(f"创建目录: {patch_map_dir}")

    print(f"开始补丁重复检测，计划处理 {len(projects_to_process)} 个项目...")

    # 5. 调用核心检测函数
    # 内部会生成 {project}-commit-patch.json 和 {project}-patch-commit.json
    try:
        batch_duplicate_detection(projects_to_process)
        print("\n[完成] 所有指定的项目补丁分析已结束。")
    except Exception as e:
        print(f"\n[错误] 批处理过程中出现异常: {e}")

if __name__ == "__main__":
    main()