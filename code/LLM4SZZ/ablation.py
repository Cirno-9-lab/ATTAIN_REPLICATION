# %%
import json
import os

# %%
dataset_fa_results = []
with open('./result/dataset_fa_results.json') as f:
    dataset_fa_results = json.load(f)

# %%
find_cnt= 0
find_true_cnt = 0
true_cnt = 0

for dataset_fa_result in dataset_fa_results:
    info = dataset_fa_result['info']
    bug_commit_cids = info['bug_commit_hash']
    true_cnt = true_cnt + len(bug_commit_cids)
    is_cond = False
    for buggy_stmt in dataset_fa_result['buggy_stmts']:
        if buggy_stmt['is_cond']:
            is_cond = True
    if not is_cond:
        continue
    
    find_cids = dataset_fa_result['find_cid']
    find_cnt = find_cnt + len(find_cids)
    
    for cid1 in bug_commit_cids:
        for cid2 in find_cids:
            if cid1 == cid2:
                find_true_cnt = find_true_cnt + 1
    

print(find_cnt)
print(find_true_cnt)
print(true_cnt)

# %%
find_cnt= 0
find_true_cnt = 0
true_cnt = 0

for dataset_fa_result in dataset_fa_results:
    info = dataset_fa_result['info']
    bug_commit_cids = info['bug_commit_hash']
    true_cnt = true_cnt + len(bug_commit_cids)
    is_cond = False
    for buggy_stmt in dataset_fa_result['buggy_stmts']:
        if buggy_stmt['is_cond']:
            is_cond = True
    if  is_cond:
        continue
    
    find_cids = dataset_fa_result['find_cid']
    
    find_cnt = find_cnt + len(find_cids)
    
    for cid1 in bug_commit_cids:
        for cid2 in find_cids:
            if cid1 == cid2:
                find_true_cnt = find_true_cnt + 1
    

print(find_cnt)
print(find_true_cnt)
print(true_cnt)


