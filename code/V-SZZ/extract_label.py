# -*- coding: utf-8 -*-
import os
import sys
import json
import subprocess
import re
import hashlib

from setting import *



if __name__ == "__main__":
    project = 'wireshark'
    c_cve_fix_commit_file = os.path.join('results', 'my-'+project+'.json')
    with open(c_cve_fix_commit_file) as fin:
        c_cve_fix_commits = json.load(fin)
        # print(c_cve_fix_commits)
    label_commit_path = os.path.join(DATA_FOLDER, 'label.json')
    with open(label_commit_path) as fin:
        label_commit = json.load(fin)
        # print(label_commit.keys())

    
    # list = []
    # for i in label_commit['linux']:
    #     list.append(i)
    # print(list)
    # print(len(list))
    # exit(0)

    
    for cve_id in label_commit[project].keys():
        
        print(cve_id)
        # print(type(cve_list))
        # for cve_id in cve_list.keys():
        #     print(cve_id)
        fix_commits = label_commit[project][cve_id]['fixing_commits'].keys()
        # print(label_commit[project][cve_id]['fixing_commits'].keys())
        for fix_commit in fix_commits:
            # if fix_commit == str.encode('8069e2f6fbd79e3d3d2ba17f5f097475b43e2921').decode():
            #     print(123)
            # print(fix_commit)
            # print(str.encode('8069e2f6fbd79e3d3d2ba17f5f097475b43e2921').decode())
            
            # if fix_commit != str.encode('c0cbe36b18ab3eb13a53fe684ec1f63a00df2c86').decode():
            #     continue
            # print(456)
            
            

            
            for tmp_dict in c_cve_fix_commits[fix_commit]:  #tmp_dictlinedict
                pre_commits = []
                file_path = tmp_dict['file_path']
                line_num = tmp_dict['line_num']
                print(fix_commit)
                print(file_path)
                print(line_num)

                for i in tmp_dict['previous_commits']:
                    pre_commits.append(i[0])   #get pre_commits
                
                if label_commit[project][cve_id]['fixing_commits'][fix_commit][file_path] == {}:
                    label_commit[project][cve_id]['fixing_commits'][fix_commit][file_path]={}
                    label_commit[project][cve_id]['fixing_commits'][fix_commit][file_path][str(line_num)]={}
                    label_commit[project][cve_id]['fixing_commits'][fix_commit][file_path][str(line_num)]['Previous Commits'] = pre_commits
                    label_commit[project][cve_id]['fixing_commits'][fix_commit][file_path][str(line_num)]['Vulnerability Introducing Commit'] = ''
                if str(line_num) in label_commit[project][cve_id]['fixing_commits'][fix_commit][file_path].keys():
                    label_commit[project][cve_id]['fixing_commits'][fix_commit][file_path][str(line_num)]['Previous Commits'] = pre_commits
                

    label_commit_out = os.path.join(DATA_FOLDER, 'label.json')

    with open(label_commit_out, 'w') as fout:
        json.dump(label_commit, fout, indent=4)      
        
        
        
        