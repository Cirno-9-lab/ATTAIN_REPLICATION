# %%
import json
import os
import git
from util import *
from cal_statistics_util import *

# %%
all_info = []
with open(os.path.join(DATASET_DIR, "final_all_dataset.json")) as f:
    all_info = json.load(f)

# %%


# test_info = []
# with open(os.path.join(DATASET_DIR, "DS_LINUX.json")) as f:
#     test_info = json.load(f)
# test_cids = set()
# for info in test_info:
#     test_cids.add(info["fix_commit_hash"])

# # %%
# print("----DS_LINUX----")

# llm4szz_p, llm4szz_r, llm4szz_f1,s1_propotions = get_metrics(all_info, test_cids)
# print(
#     f"llm4szz precision:{llm4szz_p},llm4szz recall:{llm4szz_r},llm4szz f1-score:{llm4szz_f1},s1_propotions:{s1_propotions}"
# )

# # %%
# llm4szz_raw_p, llm4szz_raw_r, llm4szz_raw_f1 = get_metrics_variants_raw(
#     all_info, test_cids
# )
# print(
#     f"llm4szz_raw precision:{llm4szz_raw_p},llm4szz_raw recall:{llm4szz_raw_r},llm4szz_raw f1-score:{llm4szz_raw_f1}"
# )

# # %%
# llm4szz_r_p, llm4szz_r_r, llm4szz_r_f1 = get_metrics_variants_r(all_info, test_cids)
# print(
#     f"llm4szz_r precision:{llm4szz_r_p},llm4szz_r recall:{llm4szz_r_r},llm4szz_r f1-score:{llm4szz_r_f1}"
# )

# # %%
# llm4szz_re_p, llm4szz_re_r, llm4szz_re_f1 = get_metrics_variants_re(all_info, test_cids)
# print(
#     f"llm4szz_re precision:{llm4szz_re_p},llm4szz_re recall:{llm4szz_re_r},llm4szz_re f1-score:{llm4szz_re_f1}"
# )

# # %%
# llm4szz_c_p, llm4szz_c_r, llm4szz_c_f1 = get_metrics_variants_c(all_info, test_cids)
# print(
#     f"llm4szz_c precision:{llm4szz_c_p},llm4szz_c recall:{llm4szz_c_r},llm4szz_c f1-score:{llm4szz_c_f1}"
# )

# # %%
# llm4szz_h_p, llm4szz_h_r, llm4szz_h_f1 = get_metrics_variants_h(all_info, test_cids)
# print(
#     f"llm4szz_h precision:{llm4szz_h_p},llm4szz_h recall:{llm4szz_h_r},llm4szz_h f1-score:{llm4szz_h_f1}"
# )

# %%
test_info = []
with open(os.path.join(DATASET_DIR, "DS_GITHUB.json")) as f:
    test_info = json.load(f)
test_cids = set()
for info in test_info:
    test_cids.add(info["fix_commit_hash"])

# %%
print(len(test_cids))

# %%
print("----DS_GITHUB----")

llm4szz_p, llm4szz_r, llm4szz_f1, s1_propotions = get_metrics(all_info, test_cids)
print(
    f"llm4szz precision:{llm4szz_p},llm4szz recall:{llm4szz_r},llm4szz f1-score:{llm4szz_f1},s1_propotions:{s1_propotions}"
)

# %%
test_info = []
with open(os.path.join(DATASET_DIR, "DS_GITHUB.json")) as f:
    test_info = json.load(f)
test_cids = set()
for info in test_info:
    if 'java' in str(info).lower():
        test_cids.add(info["fix_commit_hash"])

# %%
print(len(test_cids))

# # %%
# print("----DS_GITHUB_java----")
# llm4szz_p, llm4szz_r, llm4szz_f1,s1_propotions = get_metrics(all_info, test_cids)
# print(
#     f"llm4szz precision:{llm4szz_p},llm4szz recall:{llm4szz_r},llm4szz f1-score:{llm4szz_f1},s1_propotions:{s1_propotions}"
# )

# %%
test_info = []
with open(os.path.join(DATASET_DIR, "DS_GITHUB.json")) as f:
    test_info = json.load(f)
test_cids = set()
for info in test_info:
    if 'java' not in str(info).lower():
        test_cids.add(info["fix_commit_hash"])

# %%
print("----DS_GITHUB_c----")
llm4szz_p, llm4szz_r, llm4szz_f1,s1_propotions = get_metrics(all_info, test_cids)
print(
    f"llm4szz precision:{llm4szz_p},llm4szz recall:{llm4szz_r},llm4szz f1-score:{llm4szz_f1},s1_propotions:{s1_propotions}"
)

# %%
llm4szz_raw_p, llm4szz_raw_r, llm4szz_raw_f1 = get_metrics_variants_raw(
    all_info, test_cids
)
print(
    f"llm4szz_raw precision:{llm4szz_raw_p},llm4szz_raw recall:{llm4szz_raw_r},llm4szz_raw f1-score:{llm4szz_raw_f1}"
)

# %%
llm4szz_r_p, llm4szz_r_r, llm4szz_r_f1 = get_metrics_variants_r(all_info, test_cids)
print(
    f"llm4szz_r precision:{llm4szz_r_p},llm4szz_r recall:{llm4szz_r_r},llm4szz_r f1-score:{llm4szz_r_f1}"
)

# %%
llm4szz_re_p, llm4szz_re_r, llm4szz_re_f1 = get_metrics_variants_re(all_info, test_cids)
print(
    f"llm4szz_re precision:{llm4szz_re_p},llm4szz_re recall:{llm4szz_re_r},llm4szz_re f1-score:{llm4szz_re_f1}"
)

# %%
llm4szz_c_p, llm4szz_c_r, llm4szz_c_f1 = get_metrics_variants_c(all_info, test_cids)
print(
    f"llm4szz_c precision:{llm4szz_c_p},llm4szz_c recall:{llm4szz_c_r},llm4szz_c f1-score:{llm4szz_c_f1}"
)

# %%
llm4szz_h_p, llm4szz_h_r, llm4szz_h_f1 = get_metrics_variants_h(all_info, test_cids)
print(
    f"llm4szz_h precision:{llm4szz_h_p},llm4szz_h recall:{llm4szz_h_r},llm4szz_h f1-score:{llm4szz_h_f1}"
)

# # %%
# test_info = []
# with open(os.path.join(DATASET_DIR, "DS_APACHE.json")) as f:
#     test_info = json.load(f)
# test_cids = set()
# for info in test_info:
#     test_cids.add(info["bug_fixing_commit"])
# print(len(test_cids))

# # %%
# print("----DS_APACHE----")

# llm4szz_p, llm4szz_r, llm4szz_f1,s1_propotions = get_metrics(all_info, test_cids)
# print(
#     f"llm4szz precision:{llm4szz_p},llm4szz recall:{llm4szz_r},llm4szz f1-score:{llm4szz_f1},s1_propotions:{s1_propotions}"
# )

# # %%
# llm4szz_raw_p, llm4szz_raw_r, llm4szz_raw_f1 = get_metrics_variants_raw(
#     all_info, test_cids
# )
# print(
#     f"llm4szz_raw precision:{llm4szz_raw_p},llm4szz_raw recall:{llm4szz_raw_r},llm4szz_raw f1-score:{llm4szz_raw_f1}"
# )

# # %%
# llm4szz_r_p, llm4szz_r_r, llm4szz_r_f1 = get_metrics_variants_r(all_info, test_cids)
# print(
#     f"llm4szz_r precision:{llm4szz_r_p},llm4szz_r recall:{llm4szz_r_r},llm4szz_r f1-score:{llm4szz_r_f1}"
# )

# # %%
# llm4szz_re_p, llm4szz_re_r, llm4szz_re_f1 = get_metrics_variants_re(all_info, test_cids)
# print(
#     f"llm4szz_re precision:{llm4szz_re_p},llm4szz_re recall:{llm4szz_re_r},llm4szz_re f1-score:{llm4szz_re_f1}"
# )

# # %%
# llm4szz_c_p, llm4szz_c_r, llm4szz_c_f1 = get_metrics_variants_c(all_info, test_cids)
# print(
#     f"llm4szz_c precision:{llm4szz_c_p},llm4szz_c recall:{llm4szz_c_r},llm4szz_c f1-score:{llm4szz_c_f1}"
# )

# # %%
# llm4szz_h_p, llm4szz_h_r, llm4szz_h_f1 = get_metrics_variants_h(all_info, test_cids)
# print(
#     f"llm4szz_h precision:{llm4szz_h_p},llm4szz_h recall:{llm4szz_h_r},llm4szz_h f1-score:{llm4szz_h_f1}"
# )


