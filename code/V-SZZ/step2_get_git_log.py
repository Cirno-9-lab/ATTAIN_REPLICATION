# import os
# from extract_tag import generate_logs
# from setting import *
# import argparse
# parser = argparse.ArgumentParser()
# parser.add_argument('repo')
# repo = parser.parse_args().repo

# projects = ['FFmpeg', 'openssl', 'wireshark', 'linux', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg']




# for project in projects:
#     if repo != project:
#         continue
#     try:
#         log_out = os.path.join(LOG_DIR, project+"-meta.log")
#         generate_logs(os.path.join(REPOS_DIR, project), log_out)
#     except Exception as e:
#         print(project, e)

import os
import json
import argparse
from extract_tag import generate_logs
from setting import REPOS_DIR, LOG_DIR

def main():
    # 1. 动态加载所有项目名称（与 main.py 逻辑一致）
    dataset_path = 'data/dataset_o.json'
    if not os.path.exists(dataset_path):
        print(f"错误: 找不到数据文件 {dataset_path}")
        return

    with open(dataset_path, 'r', encoding='utf-8') as f:
        dataset_entries = json.load(f)
    
    # 获取唯一的项目名称列表
    all_projects = sorted(list(set(entry['repo_name'] for entry in dataset_entries)))

    # 2. 设置命令行参数
    parser = argparse.ArgumentParser(description="生成 Git 日志元数据")
    parser.add_argument('--repo', type=str, help='指定处理单个项目名，若不指定则处理所有项目')
    args = parser.parse_args()

    # 3. 确定要处理的项目范围
    if args.repo:
        if args.repo in all_projects:
            projects_to_process = [args.repo]
        else:
            print(f"警告: 指定的项目 '{args.repo}' 不在数据集列表中。")
            projects_to_process = [args.repo] # 强制尝试处理
    else:
        projects_to_process = all_projects

    print(f"共发现 {len(projects_to_process)} 个待处理项目。")

    # 4. 执行日志生成
    for project in projects_to_process:
        repo_path = os.path.join(REPOS_DIR, project)
        log_out = os.path.join(LOG_DIR, f"{project}-meta.log")

        # 检查本地仓库是否存在
        if not os.path.exists(repo_path):
            print(f"跳过 [{project}]: 找不到本地仓库目录 {repo_path}")
            continue

        print(f"正在处理 [{project}] -> {log_out}")
        try:
            # 确保日志目录存在
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR)
                
            generate_logs(repo_path, log_out)
        except Exception as e:
            print(f"错误: 项目 {project} 生成失败: {e}")

if __name__ == "__main__":
    main()