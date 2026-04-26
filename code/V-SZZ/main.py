import os
import sys
import json
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from collections import defaultdict

# 导入原有配置
from setting import *

# 路径修复
sys.path.append(os.path.join(SZZ_FOLDER, 'tools/pyszz/'))

from szz.my_szz import MySZZ
from data_loader import load_annotated_commits

# 确保结果目录存在
if not os.path.exists('results'):
    os.makedirs('results')

def log_project_start(repo, cve_id, owner):
    """记录北京时间到 log.txt"""
    log_path = "results/log.txt"
    bj_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    content = f"{bj_time} - [进程 {os.getpid()}] 开始分析项目: {repo} (CVE: {cve_id}, Owner: {owner})\n"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(content)

def run_szz(project, commits, method, repo_url=None):
    """执行 SZZ 分析，每个项目内部的 CVE 任务串行处理"""
    output_file = f"results/{method}-{project}.json"
    
    # 注意：如果同一项目有多个 CVE，建议把结果追加或合并
    # 这里我们保持逻辑简单：如果文件已存在，先读取旧的
    output = {}
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                output = json.load(f)
        except:
            output = {}

    my_szz = MySZZ(repo_full_name=project, repo_url=repo_url, repos_dir=REPOS_DIR, 
                   use_temp_dir=False, ast_map_path=AST_MAP_PATH)
    
    for commit in commits:
        if commit in output:
            continue  # 跳过已处理的提交
            
        print(f'[{project}] 正在分析提交: {commit}')
        try:
            imp_files = my_szz.get_impacted_files(fix_commit_hash=commit, 
                                                 file_ext_to_parse=['java'], 
                                                 only_deleted_lines=True)
            bic = my_szz.find_bic(fix_commit_hash=commit, impacted_files=imp_files)
            output[commit] = bic
        except Exception as e:
            print(f"[{project}] 提交 {commit} 失败: {e}")

    with open(output_file, 'w') as fout:
        json.dump(output, fout, indent=4)

def process_repo_group(repo_name, entries, cve_mapping, project_commits):
    """
    进程执行单元：负责处理该仓库下的所有 CVE
    由于一个进程负责一个仓库，这里不再需要 Lock
    """
    for entry in entries:
        cve_id = entry['cve_id']
        
        if cve_id in cve_mapping:
            mapping_info = cve_mapping[cve_id]
            repo_url = f"{mapping_info['github_url']}.git"
            owner = mapping_info['owner']
            
            log_project_start(repo_name, cve_id, owner)
            
            if repo_name in project_commits:
                try:
                    # 传入该项目对应的标注 commits
                    run_szz(repo_name, project_commits[repo_name], 'my', repo_url)
                except Exception as e:
                    print(f"项目 {repo_name} 异常: {e}")
            else:
                print(f"跳过: {repo_name} 无标注数据")

if __name__ == "__main__":
    # 1. 加载所有基础数据
    with open('data/dataset_o.json', 'r', encoding='utf-8') as f:
        dataset_entries = json.load(f)
    with open('data/cve_ghrepo.json', 'r', encoding='utf-8') as f:
        cve_mapping = json.load(f)
    project_commits = load_annotated_commits()

    # 2. 按项目名称对输入数据进行分割 (Grouping)
    repo_groups = defaultdict(list)
    for entry in dataset_entries:
        repo_groups[entry['repo_name']].append(entry)

    # 3. 启动多进程池
    # 此时并发数可以设高一些，因为不同项目之间没有竞争
    MAX_WORKERS = 4 
    print(f"按项目分割完成，共 {len(repo_groups)} 个项目。启动 {MAX_WORKERS} 个并发进程...")

    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for repo_name, entries in repo_groups.items():
            executor.submit(process_repo_group, repo_name, entries, cve_mapping, project_commits)

    print("任务全部提交。")