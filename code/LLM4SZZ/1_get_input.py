import os
import re
import git
from tqdm import tqdm
from io import StringIO
import json
import time
from unidiff import PatchSet
from constant import *


def get_cmp_cve():
    #return cve list
    with open('', 'r') as f:
        commit_info = json.load(f)
    all_cve_list = []
    add_cve_list = []
    
    single_func_cve_list = []
    multi_func_single_file_cve_list = []
    multi_func_multi_file_cve_list = []

    #5
    more_deleted_line_cve_list = []

    tmp_list = []
    mod_cve_list = []

    add_dict = {}
    del_dict = {}

    for patch, patch_item in commit_info.items():
        # 

        # if patch_item['deleted_line_num'] == 0:
        #     add_cve_list.append(patch.split('_')[1])
        # # elif patch_item['deleted_line_num'] != 0:
        # #     tmp_list.append(patch.split('_')[1])
        repo = patch.split('_')[0]

        if patch_item['deleted_line_num'] == 0:
            add_dict.setdefault(repo, []).append(patch.split('_')[-1])
        elif patch_item['deleted_line_num'] != 0:
            del_dict.setdefault(repo, []).append(patch.split('_')[-1])
            # tmp_list.append(patch.split('_')[1])
    return add_dict, del_dict


DATA_DIRS = ''
repos = ['FFmpeg', 'openssl', 'wireshark', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg', 'linux']


add_dict, del_dict = get_cmp_cve()


for repo in repos:
    # if repo != 'openssl':
    #     continue

    start_time = time.time()
    start_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

    add_write_list = []
    del_write_list = []

    add_dict_tmp = add_dict[repo]
    del_dict_tmp = del_dict[repo]
    id = 0
    for commit in add_dict_tmp:
        add_write_list.append({
            "id": id,
            "repo_name": repo,
            "fix_commit_hash": commit,
            "bug_commit_hash": '',
            "language": 'c',
            "inducing_commit_hash": []
        })
        id += 1
    id = 0
    for commit in del_dict_tmp:
        del_write_list.append({
            "id": id,
            "repo_name": repo,
            "fix_commit_hash": commit,
            "bug_commit_hash": '',
            "language": 'c',
            "inducing_commit_hash": []
        })
        id += 1
        
    
    with open(f"./dataset/{repo}_dataset_d.json", 'w') as f:
        json.dump(del_write_list, f, indent=4)
    with open(f"./dataset/{repo}_dataset_fa.json", 'w') as f:
        json.dump(add_write_list, f, indent=4)

    end_time = time.time()
    end_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

    elapsed_time = end_time - start_time

    with open("./time.txt", "a") as file:
        file.write(f"step2 gen vcc: {repo}\n")
        file.write(f"repo: {repo}\n")
        file.write(f"Start time: {start_time_readable}\n")
        file.write(f"End time: {end_time_readable}\n")
        file.write(f"Step2-gen_vcc: Execution time: {elapsed_time:.2f} seconds\n")
        file.write(f"\n")

    