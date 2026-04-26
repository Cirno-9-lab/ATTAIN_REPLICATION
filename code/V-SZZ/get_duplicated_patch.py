from setting import *
import json
import os
from tqdm import tqdm
from extract_tag import generate_vulnerable_versions, get_duplicate_commits


def get_fix_vers(repo_path, output_path, patch):
    cmd = 'cd {} && git tag --contains {} > {}'.format(repo_path, patch, output_path)
    os.system(cmd)
    with open(output_path, 'r') as fout:
        lines = fout.readlines()
    vers = []
    for line in lines:
        vers.append(line.strip())
    return vers


patch_root_dir = ''
repo_list = ['FFmpeg', 'openssl', 'wireshark', 'linux', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg']

repo_cve2commit_dict = {}
for repo in repo_list:
    patch_dir = os.path.join(patch_root_dir, repo)
    patch_list = os.listdir(patch_dir)
    cve2commit_dict = {}
    for patch in patch_list:
        cve = patch.split('_')[1]
        commit = patch.split('_')[-1]
        cve2commit_dict.setdefault(cve, []).append(commit)
    repo_cve2commit_dict[repo] = cve2commit_dict


repos_root_dir = ''

for repo, cve2commit_dict in repo_cve2commit_dict.items():
    print(repo)
    with open(os.path.join(WORK_DIR, f'data_commit_patch_map/{repo}-commit-patch.json')) as fin1, \
        open(os.path.join(WORK_DIR, f'data_commit_patch_map/{repo}-patch-commit.json')) as fin2:
        commit_patch_map = json.load(fin1)
        patch_commit_map = json.load(fin2)
    
    
    repos_dir = os.path.join(repos_root_dir, repo)
    for cve, commits in tqdm(cve2commit_dict.items()):

        duplicated_commits = []
        for fixing_commit in commits:
            duplicated_commits_tmp = get_duplicate_commits(fixing_commit, commit_patch_map, patch_commit_map)
            duplicated_commits = list(set(duplicated_commits+duplicated_commits_tmp))
        patch_vers = []

        for patch in duplicated_commits:
            vers = get_fix_vers(repos_dir, os.path.join(WORK_DIR, 'tmp.txt'), patch)
            patch_vers = list(set(patch_vers+vers))
        patch_ver_dict[cve] = patch_vers
        

with open('', 'w') as fout:
    json.dump(patch_ver_dict, fout, indent=4)
