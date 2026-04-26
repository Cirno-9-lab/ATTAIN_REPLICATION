import os
import json
import time
from log_generation import GitLog

def get_commit_tags(repo_path, commit):
    
    commit2tag_list = []

    log_str = GitLog().git_tag_contins(repo_path, commit)
    for line in log_str.split('\n'):
        if line.strip() != "":
            commit2tag_list.append(line.strip())
    return commit2tag_list
    
def generate_vulnerable_versions_fix_vcc(repo_path, patch_commit, introduceing_commit):
    patch_tags = get_commit_tags(repo_path, patch_commit)
    introducing_tags = get_commit_tags(repo_path, introduceing_commit)
    
    # vuln_tags = []
    # for i in introducing_tags:
    #     if i not in patch_tags:
    #         vuln_tags.append(i)

    return patch_tags, introducing_tags

def gen_cve_patch_dict(repo_patch_dir):
    """
    save_info.json:
    {"info": {"id": "", "repo_name": "linux", "fix_commit_hash": "7e0438f83dc769465ee663bb5dcf8cc154940712", "bug_commit_hash": [], "language": ["c"], "inducing_commit_hash": []}, "buggy_stmts_dicts": [{"func_name": "tpm_add_char_device", "lines": [449], "line_strs": ["\t\tif (rc) {"], "is_cond": true, "patch_file_name": "drivers/char/tpm/tpm-chip.c", "cids": ["af82455f7dbd9dc20244d80d033721b30d22c065"]}], "find_cids": [], "find_cid": ["af82455f7dbd9dc20244d80d033721b30d22c065"]}
    """
    # fix_commit: cve

    patch2cve_dict = {}
    cve2patch_dict = {}
    # for repo in os.listdir(patch_dir):
    #     repo_patch_dir = os.path.join(patch_dir, repo)
    for patch in os.listdir(repo_patch_dir):
        cve = patch.split('_')[1]
        fix_commit = patch.split('_')[-1]
        patch2cve_dict.setdefault(fix_commit, []).append(cve)
        cve2patch_dict.setdefault(cve, []).append(fix_commit)
            

    return patch2cve_dict, cve2patch_dict

def get_cmp_cve():
    #return cve list
    with open('', 'r') as f:
        commit_info = json.load(f)
    all_cve_list = []
    add_cve_list = []
    
    single_func_cve_list = []
    multi_func_single_file_cve_list = []
    multi_func_multi_file_cve_list = []

    more_deleted_line_cve_list = []

    tmp_list = []
    mod_cve_list = []

    add_dict = {}
    del_dict = {}

    for patch, patch_item in commit_info.items():

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

def gen_vuln_version(szz_dir, patch2cve_dict, cve2patch_dict, vuln_version_path, REPO_DIR, repo):
    vuln_version_dict = {}
    patch_version_dict = {}
    vcc_version_dict = {}
    
    add_dict, del_dict = get_cmp_cve()
    added_commits = []
    for cve, commits in add_dict.items():
        added_commits.extend(commits)
    added_commits = list(set(added_commits))
    

    for fix_commit in os.listdir(szz_dir):
        # if '934a04f0e775309cadbef0aa6b9692e1b12a76c6' not in fix_commit:
        #     continue
        # if fix_commit not in added_commits:
        #     continue

        save_info = os.path.join(szz_dir, fix_commit, 'save_info.json')
        
        with open(save_info, 'r') as f:
            save_info_dict = json.load(f)
            
            if 'find_cid' not in save_info_dict.keys():
                continue
            introduceing_commit = save_info_dict['find_cid']

        if repo != save_info_dict['info']['repo_name']:
            continue
        
        if introduceing_commit == []:
            patch_tags, introducing_tags = [], []
        else:
            if type(introduceing_commit[0])==list:
                introduceing_commit = introduceing_commit[0]
            patch_tags, introducing_tags = generate_vulnerable_versions_fix_vcc(os.path.join(REPO_DIR, save_info_dict['info']['repo_name']), fix_commit, introduceing_commit[0])

        patch_version_dict[fix_commit] = patch_tags
        vcc_version_dict[fix_commit] = introducing_tags
        
        # if fix_commit not in patch2cve_dict.keys():
        #     continue
        
        # for cve in patch2cve_dict[fix_commit]:
        #     vuln_version_dict[cve] = list(set(vuln_version+vuln_version_dict.get(cve, [])))
    
    for cve, patches in cve2patch_dict.items():
        # if 'CVE-2020-22042' not in cve:
        #     continue
        # print(cve)
        vuln_vers = []
        patch_vers = []
        for patch in patches:
            if patch not in patch_version_dict.keys():
                continue
            patch_vers += patch_version_dict[patch]
            vuln_vers += vcc_version_dict[patch]

        vuln_version_dict[cve] = list(set(vuln_vers) - set(patch_vers))
    
    

    with open(os.path.join(vuln_version_path, f'{repo}_vuln_version.json'), 'w') as f:
        json.dump(vuln_version_dict, f)
    
    return


repos = ['FFmpeg', 'openssl', 'wireshark', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg', 'linux']

PATCH_DIR = ''
SZZ_DIR = ''
REPO_DIR = ''

vuln_version_path = ''



for repo in repos:
    # if repo != 'openssl':
    #     continue

    print(repo)
    patch2cve_dict, cve2patch_dict = gen_cve_patch_dict(os.path.join(PATCH_DIR, repo))
    
    start_time = time.time()
    start_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

    gen_vuln_version(SZZ_DIR, patch2cve_dict, cve2patch_dict, vuln_version_path, REPO_DIR, repo)
    
    end_time = time.time()
    end_time_readable = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

    elapsed_time = end_time - start_time

    with open("./time.txt", "a") as file:
        file.write(f"step3 gen vuln_versions: {repo}\n")
        file.write(f"repo: {repo}\n")
        file.write(f"Start time: {start_time_readable}\n")
        file.write(f"End time: {end_time_readable}\n")
        file.write(f"Step3-vuln_versions: Execution time: {elapsed_time:.2f} seconds\n")
        file.write(f"\n")

# print(patch2cve_dict)




