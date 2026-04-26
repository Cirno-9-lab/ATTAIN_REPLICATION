# import os
# import sys
# import json
# import statistics
# import argparse

# from setting import *
# # from data_loader import JAVA_CVE_FIX_COMMITS, C_CVE_FIX_COMMITS, read_cve_commits, REPOS_DIR, JAVA_PROJECTS, C_PROJECTS
# from data_loader import JAVA_CVE_FIX_COMMITS, read_cve_commits, REPOS_DIR, JAVA_PROJECTS, ANNOTATED_CVES
# from log_generation import GitLog
# from extract_tag import generate_vulnerable_versions


# def eval_vulnerable_version(lang='C', szz_method='my', ori_repo='FFmpeg'):
#     repos = os.listdir(input_DIR)
#     labeled_items = []

#     for repo in repos:
#         if repo != ori_repo:
#             continue
#         repo_input_patch = os.listdir(os.path.join(input_DIR, repo))
#         tmp_dict = {}
#         for patch in repo_input_patch:
#             cve = patch.split('_')[1]
#             fix_commit = patch.split('_')[-1]
#             tmp_dict.setdefault(cve, []).append(fix_commit)

#         for cve, fix_commits in tmp_dict.items():
#             labeled_items.append({'project': repo, 'cve_id': cve, 'fixing_details': fix_commits})
    
#     affected_version_dict = {}
    
    
#     for item in labeled_items:
#         project = item['project']
        
#         if project != ori_repo:
#             continue
#         cve_id = item['cve_id']
        
#         # if 'CVE-2023-0216' not in cve_id:
#         #     continue

#         try:
#             with open(os.path.join(WORK_DIR, f"results/{szz_method}-{project}.json")) as fin:
#                 szz_results = json.load(fin)
#         except:
#             continue
#         fixing_inducing_map = {}
#         SZZ_fail = False

        
        
#         inducing_commits = set()
#         szz_commits = set()
#         for fixing_commit in item['fixing_details']:
#             if fixing_commit not in szz_results:
#                 print('SZZ not work', cve_id, project)
#                 SZZ_fail = True
#                 continue
#             # V-SZZ considers the last commit as the inducing commit
#             if szz_method == 'my':
#                 szz_vic = []
#                 for record in szz_results[fixing_commit]:
#                     szz_vic.append(record['previous_commits'][-1][0])
                    
#             for sc in szz_vic:
#                 fixing_inducing_map[sc] = fixing_commit

#             szz_commits |= set(szz_vic)

        
#         sorted_szz_vic = sorted(list(szz_commits), key=lambda k: GitLog().get_commit_time(os.path.join(REPOS_DIR, project), k))
#         print(szz_vic)
        
#         if len(sorted_szz_vic) > 0:
#             szz_vic =  sorted_szz_vic[0]
#         else:
#             szz_vic = None

#         if SZZ_fail:
#             # n_szz_fail += 1
#             continue

#         print('szz commit id', cve_id, project, szz_vic)
#         # print(fixing_inducing_map[szz_vic])
#         # print(szz_vic)

#         if szz_vic is not None:
#             print('szz commit id founded', cve_id, project, szz_vic)
#             idetified_versions = generate_vulnerable_versions(project, fixing_inducing_map[szz_vic], szz_vic, get_duplicated_patch_flag=False)
#             # print(idetified_versions)
#         elif szz_vic is None:
#             idetified_versions = set()
#         # else:
#         #     idetified_versions = commit_version_map[szz_vic]
#         affected_version_dict[cve_id] = list(idetified_versions)
    
    
#     with open(os.path.join(WORK_DIR, 'affected_version_output_without_duplicated_patch', ori_repo+'_affected_version.json'), "w") as fp:
#         json.dump(affected_version_dict, fp, indent=4)


# if __name__ == "__main__":
#     # parser = argparse.ArgumentParser()
#     # parser.add_argument('repo')
#     # repo = parser.parse_args().repo
#     #2594m48.089s
#     repo_list = ['FFmpeg', 'openssl', 'wireshark', 'linux', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg']
    
#     for repo in repo_list:
#         if repo!='openssl':
#             continue
#         print(repo)
#         lang = 'C'
#         szz_method = 'my'
#         results = eval_vulnerable_version(lang, szz_method, repo)

import os
import sys
import json
import argparse
from setting import *
from log_generation import GitLog
from extract_tag import generate_vulnerable_versions

def eval_vulnerable_version(ori_repo, cve_data, szz_method='my'):
    """
    基于 label.json 提供的任务和 SZZ 结果生成版本影响报告
    """
    # 1. 读取该项目的 SZZ 运行结果 (由 main.py 生成)
    szz_result_path = os.path.join(WORK_DIR, f"results/{szz_method}-{ori_repo}.json")
    if not os.path.exists(szz_result_path):
        print(f"  [跳过] {ori_repo}: 找不到 SZZ 结果文件 {szz_result_path}")
        return

    try:
        with open(szz_result_path) as fin:
            szz_results = json.load(fin)
    except Exception as e:
        print(f"  [错误] 读取 SZZ 结果失败 {szz_result_path}: {e}")
        return

    affected_version_dict = {}

    # 2. 遍历 label.json 中的 CVE 任务
    for cve_id, info in cve_data.items():
        fix_commits = info.get('fixing_commits', [])
        szz_commits = set()
        fixing_inducing_map = {}
        found_any_szz = False

        # 遍历该 CVE 所有的修复提交，汇总所有追溯到的诱发提交 (VIC)
        for fixing_commit in fix_commits:
            if fixing_commit not in szz_results:
                continue
            
            try:
                # 适配 MySZZ 数据结构提取诱发提交 ID
                for record in szz_results[fixing_commit]:
                    if 'previous_commits' in record and len(record['previous_commits']) > 0:
                        vic = record['previous_commits'][-1][0]
                        szz_commits.add(vic)
                        fixing_inducing_map[vic] = fixing_commit
                        found_any_szz = True
            except (KeyError, IndexError, TypeError):
                continue

        if not found_any_szz or not szz_commits:
            print(f"  [信息] {cve_id}: SZZ 未能追溯到任何诱发提交")
            continue

        # 3. 在所有潜在诱发提交中，按时间排序取最早的一个作为漏洞起点
        try:
            repo_git_path = os.path.join(REPOS_DIR, ori_repo)
            # 根据 Git 提交时间进行排序
            sorted_vics = sorted(
                list(szz_commits), 
                key=lambda k: GitLog().get_commit_time(repo_git_path, k)
            )
            earliest_vic = sorted_vics[0]
            corresponding_fix = fixing_inducing_map[earliest_vic]

            print(f"  [分析] {cve_id}: 起点 {earliest_vic[:7]} | 终点 {corresponding_fix[:7]}")

            # 4. 计算版本区间
            # 将 get_duplicated_patch_flag 设为 False，不依赖 step3 的 json 文件
            idetified_versions = generate_vulnerable_versions(
                ori_repo, 
                corresponding_fix, 
                earliest_vic, 
                get_duplicated_patch_flag=False 
            )
            
            affected_version_dict[cve_id] = sorted(list(idetified_versions)) if idetified_versions else []

        except Exception as e:
            print(f"  [异常] 分析 {cve_id} 时发生错误: {e}")

    # 5. 保存结果到指定输出目录
    output_subdir = os.path.join(WORK_DIR, 'affected_version_output')
    if not os.path.exists(output_subdir):
        os.makedirs(output_subdir)
        
    output_file = os.path.join(output_subdir, f'{ori_repo}_affected_version.json')
    with open(output_file, "w") as fp:
        json.dump(affected_version_dict, fp, indent=4)
    print(f"  [完成] {ori_repo} 报告已保存。")


if __name__ == "__main__":
    # 1. 动态获取所有待处理项目（从 dataset_o.json 获取）
    dataset_path = os.path.join('data', 'dataset_o.json')
    if not os.path.exists(dataset_path):
        print(f"错误: 找不到数据集定义文件 {dataset_path}")
        sys.exit(1)

    with open(dataset_path, 'r', encoding='utf-8') as f:
        dataset_entries = json.load(f)
    all_projects = sorted(list(set(entry['repo_name'] for entry in dataset_entries)))

    # 2. 加载标签数据 label.json
    label_path = os.path.join('data', 'label.json')
    if not os.path.exists(label_path):
        print(f"错误: 找不到标签文件 {label_path}")
        sys.exit(1)

    with open(label_path, 'r', encoding='utf-8') as f:
        full_labels = json.load(f)

    # 3. 命令行参数解析
    parser = argparse.ArgumentParser(description="根据 label.json 生成漏洞影响版本报告")
    parser.add_argument('--repo', type=str, help='指定处理单个项目名称 (例如: spring-security)')
    parser.add_argument('--method', type=str, default='my', help='使用的 SZZ 方法名 (默认: my)')
    args = parser.parse_args()

    # 4. 确定任务列表
    if args.repo:
        if args.repo in full_labels:
            tasks = {args.repo: full_labels[args.repo]}
        else:
            print(f"警告: 项目 {args.repo} 未在 label.json 中定义，尝试直接搜索...")
            tasks = {} # 或者根据需要自定义
    else:
        tasks = {repo: full_labels[repo] for repo in all_projects if repo in full_labels}

    print(f"主进程启动: 准备处理 {len(tasks)} 个项目...")

    # 5. 循环执行分析
    for repo_name, cve_data in tasks.items():
        print(f"\n>>> 正在处理项目: {repo_name}")
        eval_vulnerable_version(repo_name, cve_data, szz_method=args.method)

    print("\n所有任务执行完毕。")