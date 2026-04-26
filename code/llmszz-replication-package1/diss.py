# %%
import json
import os
import git
from util import *
from cal_statistics_util import *

# %%
valid_github_ds = []
with open(
    os.path.join(DATASET_DIR,"DS_GITHUB_EXTEND.json")
) as f:
    valid_github_ds = json.load(f)
print(len(valid_github_ds))

# %%
test_cids = set()
for info in valid_github_ds:
    info["repo_name"] = info["repo_name"].split("/")[1]
    info["bug_inducing_commit"] = info["bug_commit_hash"]
    test_cids.add(info["bug_fixing_commit"])

# %%
print("----DS_GITHUB-extended----")
precision, recall, f1_score,_ = get_metrics(valid_github_ds, test_cids)
print(
    f"llm4szz precision:{precision},llm4szz recall:{recall},llm4szz f1-score:{f1_score}"
)

# %%
valid_linux_ds = []
with open(
    os.path.join(DATASET_DIR,'DS_LINUX_EXTEND.json')
) as f:
    valid_linux_ds = json.load(f)
print(len(valid_linux_ds))

# %%
test_cids = set()
for info in valid_linux_ds:
    info["bug_inducing_commit"] = info["bug_commit_hash"]
    test_cids.add(info["bug_fixing_commit"])

# %%
print("----DS_LINUX-extended----")
precision, recall, f1_score, _ = get_metrics(valid_linux_ds, test_cids)
print(
    f"llm4szz precision:{precision},llm4szz recall:{recall},llm4szz f1-score:{f1_score}"
)

# %%
def get_scalability_statistics(all_info, test_cids):
    all_token_costs = []
    all_call_llm_times = []
    all_elapsed_time = []
    for repeat_cnt in range(0, 3):
        token_costs = 0
        call_llm_times = 0
        elapsed_time = 0
        for info in all_info:
            repo_name = info["repo_name"]
            bug_fixing_cid = info["bug_fixing_commit"]
            if bug_fixing_cid not in test_cids:
                continue

            save_path = os.path.join(
                SAVE_LOG_DIR, repo_name, bug_fixing_cid, f"llm4szz{repeat_cnt}.json"
            )

            if os.path.exists(save_path):
                logs = []
                with open(save_path) as f:
                    logs = json.load(f)

                for log in logs:
                    if "token_cost" in str(log):
                        token_costs = token_costs + log["token_cost"]

                    if "call_llm_times" in str(log):
                        call_llm_times = call_llm_times + log["call_llm_times"]

                    if "elapsed_time" in str(log):
                        elapsed_time = elapsed_time + log["elapsed_time"]

        all_token_costs.append(token_costs / len(test_cids))
        all_call_llm_times.append(call_llm_times / len(test_cids))
        all_elapsed_time.append(elapsed_time / len(test_cids))

    return (
        sum(all_token_costs) / len(all_token_costs),
        sum(all_call_llm_times) / len(all_call_llm_times),
        sum(all_elapsed_time) / len(all_elapsed_time),
    )

# %%
all_info = []
with open(os.path.join(DATASET_DIR, "final_all_dataset.json")) as f:
    all_info = json.load(f)

test_info = []
with open(os.path.join(DATASET_DIR, "DS_LINUX.json")) as f:
    test_info = json.load(f)
test_cids = set()
for info in test_info:
    test_cids.add(info["fix_commit_hash"])

# %%
print('----DS_LINUX statistics----')
avg_token_costs, avg_call_llm_times, avg_elapsed_time = get_scalability_statistics(all_info,test_cids)
print(f'llm calls:{avg_call_llm_times},token numbers:{avg_token_costs},time:{avg_elapsed_time}')

# %%
test_info = []
with open(os.path.join(DATASET_DIR, "DS_GITHUB.json")) as f:
    test_info = json.load(f)
test_cids = set()
for info in test_info:
    test_cids.add(info["fix_commit_hash"])

# %%
print('----DS_GITHUB statistics----')
avg_token_costs, avg_call_llm_times, avg_elapsed_time = get_scalability_statistics(all_info,test_cids)
print(f'llm calls:{avg_call_llm_times},token numbers:{avg_token_costs},time:{avg_elapsed_time}')

# %%
test_info = []
with open(os.path.join(DATASET_DIR, "DS_APACHE.json")) as f:
    test_info = json.load(f)
test_cids = set()
for info in test_info:
    test_cids.add(info["bug_fixing_commit"])

# %%
print('----DS_APACHE statistics----')
avg_token_costs, avg_call_llm_times, avg_elapsed_time = get_scalability_statistics(all_info,test_cids)
print(f'llm calls:{avg_call_llm_times},token numbers:{avg_token_costs},time:{avg_elapsed_time}')


