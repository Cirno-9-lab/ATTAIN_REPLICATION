import os
import json

duplicated_ver_path = ''

with open(duplicated_ver_path, 'r') as f:
    duplicated_patched_ver = json.load(f)

input_path = ''

input_list = os.listdir(input_path)
output_path = ''
if not os.path.exists(output_path):
    os.makedirs(output_path)

for input_file in input_list:
    repo_duplicated_dict = {}
    with open(os.path.join(input_path, input_file), 'r') as f:
        repo_data = json.load(f)

    for cve, vers in repo_data.items():
        if cve not in duplicated_patched_ver:
            repo_duplicated_dict[cve] = vers
            continue
        tmp_list = []
        for ver in vers:
            if ver in duplicated_patched_ver[cve]:
                continue
            tmp_list.append(ver)
        repo_duplicated_dict[cve] = tmp_list
    
    with open(os.path.join(output_path, input_file), 'w') as f:
        json.dump(repo_duplicated_dict, f, indent=4)

