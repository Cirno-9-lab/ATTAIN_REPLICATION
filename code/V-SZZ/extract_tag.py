# import os
# import sys
# import json
# import subprocess
# import re
# import hashlib
# from log_generation import GitLog

# from setting import *

# # from data_loader import JAVA_CVE_FIX_COMMITS, C_CVE_FIX_COMMITS, read_cve_commits, REPOS_DIR, JAVA_PROJECTS, C_PROJECTS, ANNOTATED_CVES
# from data_loader import JAVA_CVE_FIX_COMMITS, read_cve_commits, REPOS_DIR, JAVA_PROJECTS, ANNOTATED_CVES
# from git_analysis.analyze_git_logs import retrieve_git_logs, retrieve_git_logs_dict, get_ancestors, get_parent_tags, get_son_tags

# repos_dir = REPOS_DIR
# log_dir = LOG_DIR

# def get_tags(repo_dir):
#     output = GitLog().git_tag(repo_dir)
#     tags = output.split('\n')

#     commit_tag_map = {}
#     for tag in tags:
#         # if '2.1.0' not in tag:
#         #     continue

#         if tag.strip() == "":
#             continue

#         try:
#             output = GitLog().git_show(repo_dir, tag)
#         except Exception as e:
#             print(tag, e)
#             continue

#         commit = None
#         timestamp = None
#         for line in output.split('\n'):
#             if line.startswith('commit:'):
#                 commit = line[8:].strip()
            
#             if line.startswith('timestamp:'):
#                 timestamp = line[11:].strip()
#                 break
        
#         if commit is not None:
#             commit_tag_map[commit] = tag
    

#     return commit_tag_map

# def generate_logs(repo_dir, output):
#     log_str = GitLog().git_log(repo_dir)
#     with open(output, 'w') as fout:
#         fout.write(log_str)


# def get_duplicate_commits(commit_id, commit_patch_map, patch_commit_map):
#     if commit_id not in commit_patch_map:
#         return []
    
#     duplicated_commits = set()
#     for h in commit_patch_map[commit_id]:
#         for c in patch_commit_map[h]:
#             if c == commit_id:
#                 continue

#             s1 = set(commit_patch_map[commit_id])
#             s2 = set(commit_patch_map[c])
#             if s1 == s2 or s1.issubset(s2):
#                 duplicated_commits.add(c)

#     return list(duplicated_commits)

# def generate_vulnerable_versions(project, fixing_commit, inducing_commit, get_duplicated_patch_flag=True):
#     git_logs = retrieve_git_logs(os.path.join(log_dir, project+"-meta.log"), project)
#     git_log_dict = retrieve_git_logs_dict(git_logs, project)
    
#     commit_tag_map = get_tags(os.path.join(repos_dir, project))
    
#     for commit_id in git_log_dict:
#         if commit_id in commit_tag_map:
#             git_log_dict[commit_id].set_tag(commit_tag_map[commit_id])
        
#         if len(git_log_dict[commit_id].parent) == 0:
#             git_log_dict[commit_id].set_tag("Initial Commit")
    
    
#     with open(os.path.join(WORK_DIR, f'data_commit_patch_map/{project}-commit-patch.json')) as fin1, \
#             open(os.path.join(WORK_DIR, f'data_commit_patch_map/{project}-patch-commit.json')) as fin2:
#         commit_patch_map = json.load(fin1)
#         patch_commit_map = json.load(fin2)

#     try:
#         fc_sons_tag = get_son_tags(git_log_dict, fixing_commit)
        
#         if get_duplicated_patch_flag:
#             duplicated_commits = get_duplicate_commits(fixing_commit, commit_patch_map, patch_commit_map)
#             if len(duplicated_commits) > 0:
#                 for c in duplicated_commits:
#                     fc_sons_tag |= get_son_tags(git_log_dict, c)
        

#         ic_sons_tag = get_son_tags(git_log_dict, inducing_commit)
        

#         duplicated_commits = get_duplicate_commits(inducing_commit, commit_patch_map, patch_commit_map)
#         for c in duplicated_commits:
#             ic_sons_tag |= get_son_tags(git_log_dict, c)

#         ic_sons_tag = set([t.tag for t in ic_sons_tag])
        
#         fc_sons_tag = set([t.tag for t in fc_sons_tag])

#         return ic_sons_tag - fc_sons_tag

#     except Exception as e:
#         print(e)
#         return None

import os
import sys
import json
import subprocess
import re
import hashlib
from log_generation import GitLog

from setting import *

# 路径与设置保持与原代码一致
from data_loader import JAVA_CVE_FIX_COMMITS, read_cve_commits, REPOS_DIR, JAVA_PROJECTS, ANNOTATED_CVES
from git_analysis.analyze_git_logs import retrieve_git_logs, retrieve_git_logs_dict, get_ancestors, get_parent_tags, get_son_tags

repos_dir = REPOS_DIR
# 建议在 setting.py 中将 LOG_DIR 设置为你的 GitLogs 绝对路径
log_dir = LOG_DIR 

def get_tags(repo_dir):
    output = GitLog().git_tag(repo_dir)
    tags = output.split('\n')

    commit_tag_map = {}
    for tag in tags:
        if tag.strip() == "":
            continue

        try:
            output = GitLog().git_show(repo_dir, tag)
        except Exception as e:
            print(tag, e)
            continue

        commit = None
        timestamp = None
        for line in output.split('\n'):
            if line.startswith('commit:'):
                commit = line[8:].strip()
            
            if line.startswith('timestamp:'):
                timestamp = line[11:].strip()
                break
        
        if commit is not None:
            commit_tag_map[commit] = tag
    
    return commit_tag_map

def generate_logs(repo_dir, output):
    log_str = GitLog().git_log(repo_dir)
    with open(output, 'w') as fout:
        fout.write(log_str)

def get_duplicate_commits(commit_id, commit_patch_map, patch_commit_map):
    if commit_id not in commit_patch_map:
        return []
    
    duplicated_commits = set()
    for h in commit_patch_map[commit_id]:
        if h not in patch_commit_map:
            continue
        for c in patch_commit_map[h]:
            if c == commit_id:
                continue

            s1 = set(commit_patch_map[commit_id])
            if c not in commit_patch_map:
                continue
            s2 = set(commit_patch_map[c])
            if s1 == s2 or s1.issubset(s2):
                duplicated_commits.add(c)

    return list(duplicated_commits)

def generate_vulnerable_versions(project, fixing_commit, inducing_commit, get_duplicated_patch_flag=True):
    # 1. 加载日志字典
    log_file_path = os.path.join(log_dir, project + "-meta.log")
    if not os.path.exists(log_file_path):
        print(f"  [错误] 找不到日志文件: {log_file_path}")
        return set()

    git_logs = retrieve_git_logs(log_file_path, project)
    git_log_dict = retrieve_git_logs_dict(git_logs, project)
    
    # 2. 映射 Tag
    commit_tag_map = get_tags(os.path.join(repos_dir, project))
    for commit_id in git_log_dict:
        if commit_id in commit_tag_map:
            git_log_dict[commit_id].set_tag(commit_tag_map[commit_id])
        if len(git_log_dict[commit_id].parent) == 0:
            git_log_dict[commit_id].set_tag("Initial Commit")
    
    # 3. 补丁映射文件保护逻辑
    commit_patch_map = {}
    patch_commit_map = {}
    
    # 只有当 flag 为 True 时才尝试加载文件
    if get_duplicated_patch_flag:
        path1 = os.path.join(WORK_DIR, f'data_commit_patch_map/{project}-commit-patch.json')
        path2 = os.path.join(WORK_DIR, f'data_commit_patch_map/{project}-patch-commit.json')
        
        if os.path.exists(path1) and os.path.exists(path2):
            try:
                with open(path1) as fin1, open(path2) as fin2:
                    commit_patch_map = json.load(fin1)
                    patch_commit_map = json.load(fin2)
            except Exception as e:
                print(f"  [警告] 加载补丁映射文件失败: {e}")
                get_duplicated_patch_flag = False
        else:
            # 文件不存在时，静默将 flag 设为 False，避免后面读取报错
            get_duplicated_patch_flag = False

    try:
        # 4. 获取修复提交的相关标签
        fc_sons_tag = get_son_tags(git_log_dict, fixing_commit)
        if get_duplicated_patch_flag:
            duplicated_commits = get_duplicate_commits(fixing_commit, commit_patch_map, patch_commit_map)
            for c in duplicated_commits:
                fc_sons_tag |= get_son_tags(git_log_dict, c)

        # 5. 获取引入提交的相关标签
        ic_sons_tag = get_son_tags(git_log_dict, inducing_commit)
        # 注意：原代码中 inducing_commit 的重复检测未受 flag 控制，现统一纳入控制
        if get_duplicated_patch_flag:
            dup_inducing = get_duplicate_commits(inducing_commit, commit_patch_map, patch_commit_map)
            for c in dup_inducing:
                ic_sons_tag |= get_son_tags(git_log_dict, c)

        # 6. 计算受影响版本（差集）
        ic_versions = set([t.tag for t in ic_sons_tag if t.tag])
        fc_versions = set([t.tag for t in fc_sons_tag if t.tag])

        # 排除 Initial Commit 这种占位符
        final_versions = ic_versions - fc_versions
        if "Initial Commit" in final_versions:
            final_versions.remove("Initial Commit")
            
        return final_versions

    except Exception as e:
        print(f"  [错误] 提取版本标签时发生异常: {e}")
        return None