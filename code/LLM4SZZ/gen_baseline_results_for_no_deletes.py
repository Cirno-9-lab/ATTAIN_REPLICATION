# %%
import os
import sys
import json
import logging as log
import random

sys.path.append(
    "./NoDelBaselines/icse2021-szz-replication-package/tools/pyszz"
)
from szz.ag_szz import AGSZZ
from szz.b_szz import BaseSZZ
from szz.ma_szz import MASZZ, DetectLineMoved
from szz.r_szz import RSZZ
from szz.l_szz import LSZZ
import traceback


# enter your path here
REPOS_DIR = ""
SAVE_RESULT_PATH = ""

# %%
data_to_check = []
with open(
    "/data1/lingxiaotang/sema-szz-replication-package/dataset/dataset_a.json"
) as f:
    data_to_check = json.load(f)

abaseszz = BaseSZZ(
    repo_full_name="linux", repo_url=None, repos_dir=REPOS_DIR, use_temp_dir=True
)
aagszz = AGSZZ(
    repo_full_name="linux", repo_url=None, repos_dir=REPOS_DIR, use_temp_dir=True
)
amaszz = MASZZ(
    repo_full_name="linux", repo_url=None, repos_dir=REPOS_DIR, use_temp_dir=True
)
raszz = RSZZ(repo_full_name="linux", repo_url=None, repos_dir=REPOS_DIR)
laszz = LSZZ(repo_full_name="linux", repo_url=None, repos_dir=REPOS_DIR)

# %%
b_find_cnt = 0
b_true_cnt = 0
a_find_cnt = 0
a_true_cnt = 0
m_find_cnt = 0
m_true_cnt = 0
r_find_cnt = 0
r_true_cnt = 0
l_find_cnt = 0
l_true_cnt = 0
true_cnt = 0
cnt = 0
for cid_info in data_to_check:
    save_info = {}
    save_info["info"] = cid_info
    save_info["b_induce_cids"] = []
    save_info["a_induce_cids"] = []
    save_info["ma_induce_cids"] = []
    save_info["r_induce_cids"] = []
    save_info["l_induce_cids"] = []
    fix_cid = cid_info["fix_commit_hash"]
    try:
        cnt = cnt + 1

        induce_cids = cid_info["bug_commit_hash"]
        true_cnt = true_cnt + len(induce_cids)

        b_impact_files = abaseszz.get_impacted_files(
            fix_commit_hash=fix_cid,
            file_ext_to_parse=["c", "java", "cpp", "h", "hpp"],
            only_deleted_lines=False,
        )
        b_induce_cids = [
            cid.hexsha
            for cid in abaseszz.find_bic(
                fix_commit_hash=fix_cid, impacted_files=b_impact_files
            )
        ]
        save_info["b_induce_cids"] = b_induce_cids

        a_impact_files = aagszz.get_impacted_files(
            fix_commit_hash=fix_cid,
            file_ext_to_parse=["c", "java", "cpp", "h", "hpp"],
            only_deleted_lines=False,
        )
        a_induce_cids = [
            cid.hexsha
            for cid in aagszz.find_bic(
                fix_commit_hash=fix_cid, impacted_files=a_impact_files
            )
        ]
        save_info["a_induce_cids"] = a_induce_cids

        ma_impact_files = amaszz.get_impacted_files(
            fix_commit_hash=fix_cid,
            file_ext_to_parse=["c", "java", "cpp", "h", "hpp"],
            only_deleted_lines=False,
        )
        ma_induce_cids = [
            cid.hexsha
            for cid in amaszz.find_bic(
                fix_commit_hash=fix_cid, impacted_files=ma_impact_files
            )
        ]
        save_info["ma_induce_cids"] = ma_induce_cids

        r_impact_files = raszz.get_impacted_files(
            fix_commit_hash=fix_cid,
            file_ext_to_parse=["c", "java", "cpp", "h", "hpp"],
            only_deleted_lines=False,
        )
        r_induce_cids = [
            cid.hexsha
            for cid in raszz.find_bic(
                fix_commit_hash=fix_cid, impacted_files=r_impact_files
            )
        ]
        save_info["r_induce_cids"] = r_induce_cids

        l_impact_files = laszz.get_impacted_files(
            fix_commit_hash=fix_cid,
            file_ext_to_parse=["c", "java", "cpp", "h", "hpp"],
            only_deleted_lines=False,
        )
        l_induce_cids = [
            cid.hexsha
            for cid in laszz.find_bic(
                fix_commit_hash=fix_cid, impacted_files=l_impact_files
            )
        ]
        save_info["l_induce_cids"] = l_induce_cids

        print(f"fix_cid:{fix_cid}")
        print(f"b_induce_cids:{b_induce_cids}")
        print(f"a_induce_cids:{a_induce_cids}")
        print(f"ma_induce_cids:{ma_induce_cids}")
        print(f"r_induce_cids:{r_induce_cids}")
        print(f"l_induce_cids:{l_induce_cids}")

        b_find_cnt = b_find_cnt + len(b_induce_cids)
        a_find_cnt = a_find_cnt + len(a_induce_cids)
        m_find_cnt = m_find_cnt + len(ma_induce_cids)
        r_find_cnt = r_find_cnt + 1
        l_find_cnt = l_find_cnt + 1

        for cid in b_induce_cids:
            if cid in induce_cids:
                b_true_cnt = b_true_cnt + 1

        for cid in a_induce_cids:
            if cid in induce_cids:
                a_true_cnt = a_true_cnt + 1

        for cid in ma_induce_cids:
            if cid in induce_cids:
                m_true_cnt = m_true_cnt + 1

        for cid in r_induce_cids:
            if cid in induce_cids:
                r_true_cnt = r_true_cnt + 1

        for cid in l_induce_cids:
            if cid in induce_cids:
                l_true_cnt = l_true_cnt + 1

        with open("baseline_results_for_dataset_no_dels.txt", "w") as f:
            f.write(f"ab_find_cnt:{b_find_cnt}\n")
            f.write(f"ab_true_cnt:{b_true_cnt}\n")
            f.write(f"aa_find_cnt:{a_find_cnt}\n")
            f.write(f"aa_true_cnt:{a_true_cnt}\n")
            f.write(f"am_find_cnt:{m_find_cnt}\n")
            f.write(f"am_true_cnt:{m_true_cnt}\n")
            f.write(f"ar_find_cnt:{r_find_cnt}\n")
            f.write(f"ar_true_cnt:{r_true_cnt}\n")
            f.write(f"al_find_cnt:{l_find_cnt}\n")
            f.write(f"al_true_cnt:{l_true_cnt}\n")
            f.write(f"true_cnt:{true_cnt}\n")
    except:
        traceback.print_exc()
    finally:
        save_cid_path = os.path.join(SAVE_RESULT_PATH, fix_cid)
        os.makedirs(save_cid_path, exist_ok=True)
        save_info_path = os.path.join(save_cid_path, "save_info.json")
        with open(save_info_path, "w") as f:
            json.dump(save_info, f)
