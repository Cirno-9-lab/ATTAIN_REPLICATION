import json
import os
import git
from util import *


def get_metrics(all_info, test_cids):
    precisions = []
    recalls = []
    f1_scores = []
    s1_propotions = []
    for repeat_cnt in range(0, 3):
        find_cnt = 0
        find_true_cnt = 0
        true_cnt = 0
        s1_cnt = 0
        for info in all_info:

            repo_name = info["repo_name"]
            bug_fixing_cid = info["bug_fixing_commit"]
            if bug_fixing_cid not in test_cids:
                continue
            # print('here')
            bug_inducing_cids = info["bug_inducing_commit"]
            true_cnt = true_cnt + len(bug_inducing_cids)
            repo_path = os.path.join(REPOS_DIR, repo_name)

            save_path = os.path.join(
                SAVE_LOG_DIR, repo_name, bug_fixing_cid, f"llm4szz{repeat_cnt}.json"
            )
            save_dir_path = os.path.join(SAVE_LOG_DIR, repo_name, bug_fixing_cid)

            if os.path.exists(save_path):
                logs = []
                with open(save_path) as f:
                    logs = json.load(f)

                final_find_cids = []
                s2_final_cids = []
                s2_cand_cids = []

                s1_ranked_stmts_infos = []
                s1_llm_file_final_cids = []
                s1_final_cids = []

                can_determine = True
                for log in logs:
                    if "can_determine" in str(log):
                        can_determine = can_determine and log["can_determine"]

                    if "s2_final_cid" in str(log):
                        s2_final_cids.extend(log["s2_final_cid"])

                    if "s2_cand_cids" in str(log):
                        s2_cand_cids.extend(log["s2_cand_cids"])

                    if "s1_ranked_stmts_infos" in str(log):
                        s1_ranked_stmts_infos.extend(log["s1_ranked_stmts_infos"][:5])

                    if "s1_llm_file_final_cids" in str(log):
                        s1_llm_file_final_cids.extend(log["s1_llm_file_final_cids"])

                    if "llm_patch_file_names" in str(log):
                        file_names = log["llm_patch_file_names"]

                for rank_info in s1_ranked_stmts_infos:
                    s1_final_cids.append(rank_info["induce_cid"])

                s1_final_cids = list(set(s1_final_cids))
                s1_final_cids = get_r_commits(repo_name, s1_final_cids)

                if can_determine:
                    s2_final_cids = list(set(s2_final_cids))
                    s2_final_cids = get_r_commits(repo_name, s2_final_cids)

                if can_determine:
                    final_find_cids = s2_final_cids

                if len(final_find_cids) == 0:
                    final_find_cids = s1_final_cids
                    s1_cnt = s1_cnt + len(s1_final_cids)

                find_cnt = find_cnt + len(final_find_cids)

                for final_cid in final_find_cids:
                    for cid1 in bug_inducing_cids:
                        if cid1 in final_cid:
                            find_true_cnt = find_true_cnt + 1

        precisions.append(find_true_cnt / find_cnt)
        recalls.append(find_true_cnt / true_cnt)
        f1_scores.append(
            (2 * (find_true_cnt / find_cnt) * (find_true_cnt / true_cnt))
            / (find_true_cnt / find_cnt + find_true_cnt / true_cnt)
        )
        s1_propotions.append(s1_cnt/len(test_cids))
    # print(precisions)
    # print(recalls)
    # print(f1_scores)
    return sum(precisions)/len(precisions), sum(recalls)/len(recalls), sum(f1_scores)/len(f1_scores),sum(s1_propotions)/len(s1_propotions)


def get_metrics_variants_raw(all_info, test_cids):
    precisions = []
    recalls = []
    f1_scores = []
    for repeat_cnt in range(0, 3):
        find_cnt = 0
        find_true_cnt = 0
        true_cnt = 0
        for info in all_info:

            repo_name = info["repo_name"]
            bug_fixing_cid = info["bug_fixing_commit"]
            if bug_fixing_cid not in test_cids:
                continue
            bug_inducing_cids = info["bug_inducing_commit"]
            true_cnt = true_cnt + len(bug_inducing_cids)
            repo_path = os.path.join(REPOS_DIR, repo_name)

            save_path = os.path.join(
                SAVE_LOG_DIR, repo_name, bug_fixing_cid, f"llm4szz_raw{repeat_cnt}.json"
            )
            save_dir_path = os.path.join(SAVE_LOG_DIR, repo_name, bug_fixing_cid)

            if os.path.exists(save_path):
                logs = []
                with open(save_path) as f:
                    logs = json.load(f)

                llm_file_cand_cids = []
                for log in logs:
                    if "llm_file_cand_cids" in str(log):
                        llm_file_cand_cids = list(set(log["llm_file_cand_cids"]))

                find_cnt = find_cnt + len(llm_file_cand_cids)

                for final_cid in llm_file_cand_cids:
                    for cid1 in bug_inducing_cids:
                        if cid1 in final_cid:
                            find_true_cnt = find_true_cnt + 1

        if find_cnt != 0 and find_true_cnt != 0:
            precisions.append(find_true_cnt / find_cnt)
            recalls.append(find_true_cnt / true_cnt)
            f1_scores.append(
                (2 * (find_true_cnt / find_cnt) * (find_true_cnt / true_cnt))
                / (find_true_cnt / find_cnt + find_true_cnt / true_cnt)
            )

    return sum(precisions)/len(precisions), sum(recalls)/len(recalls), sum(f1_scores)/len(f1_scores)


def get_metrics_variants_c(all_info, test_cids):
    precisions = []
    recalls = []
    f1_scores = []
    for repeat_cnt in range(0, 3):
        find_cnt = 0
        find_true_cnt = 0
        true_cnt = 0
        for info in all_info:
            repo_name = info["repo_name"]
            bug_fixing_cid = info["bug_fixing_commit"]
            if bug_fixing_cid not in test_cids:
                continue
            bug_inducing_cids = info["bug_inducing_commit"]
            true_cnt = true_cnt + len(bug_inducing_cids)
            repo_path = os.path.join(REPOS_DIR, repo_name)

            save_path = os.path.join(
                SAVE_LOG_DIR, repo_name, bug_fixing_cid, f"llm4szz_c{repeat_cnt}.json"
            )

            save_dir_path = os.path.join(SAVE_LOG_DIR, repo_name, bug_fixing_cid)

            if os.path.exists(save_path):

                logs = []
                with open(save_path) as f:
                    logs = json.load(f)

                s2_final_cid = []
                for log in logs:
                    if "s2_final_cid" in str(log):
                        s2_final_cid = list(set(log["s2_final_cid"]))

                find_cnt = find_cnt + len(s2_final_cid)

                for final_cid in s2_final_cid:
                    for cid1 in bug_inducing_cids:
                        if cid1 in final_cid:
                            find_true_cnt = find_true_cnt + 1

        if find_cnt != 0 and find_true_cnt != 0:
            precisions.append(find_true_cnt / find_cnt)
            recalls.append(find_true_cnt / true_cnt)
            f1_scores.append(
                (2 * (find_true_cnt / find_cnt) * (find_true_cnt / true_cnt))
                / (find_true_cnt / find_cnt + find_true_cnt / true_cnt)
            )

    return sum(precisions)/len(precisions), sum(recalls)/len(recalls), sum(f1_scores)/len(f1_scores)


def get_metrics_variants_h(all_info, test_cids):
    precisions = []
    recalls = []
    f1_scores = []
    for repeat_cnt in range(0, 3):
        find_cnt = 0
        find_true_cnt = 0
        true_cnt = 0
        for info in all_info:
            repo_name = info["repo_name"]
            bug_fixing_cid = info["bug_fixing_commit"]
            if bug_fixing_cid not in test_cids:
                continue
            bug_inducing_cids = info["bug_inducing_commit"]
            true_cnt = true_cnt + len(bug_inducing_cids)
            repo_path = os.path.join(REPOS_DIR, repo_name)

            save_path = os.path.join(
                SAVE_LOG_DIR, repo_name, bug_fixing_cid, f"llm4szz_h{repeat_cnt}.json"
            )

            save_dir_path = os.path.join(SAVE_LOG_DIR, repo_name, bug_fixing_cid)

            if os.path.exists(save_path):

                logs = []
                with open(save_path) as f:
                    logs = json.load(f)

                s2_final_cid = []
                for log in logs:
                    if "s2_final_cid" in str(log):
                        s2_final_cid = list(set(log["s2_final_cid"]))

                find_cnt = find_cnt + len(s2_final_cid)

                for final_cid in s2_final_cid:
                    for cid1 in bug_inducing_cids:
                        if cid1 in final_cid:
                            find_true_cnt = find_true_cnt + 1

        if find_cnt != 0 and find_true_cnt != 0:
            precisions.append(find_true_cnt / find_cnt)
            recalls.append(find_true_cnt / true_cnt)
            f1_scores.append(
                (2 * (find_true_cnt / find_cnt) * (find_true_cnt / true_cnt))
                / (find_true_cnt / find_cnt + find_true_cnt / true_cnt)
            )

    return sum(precisions)/len(precisions), sum(recalls)/len(recalls), sum(f1_scores)/len(f1_scores)


def get_metrics_variants_re(all_info, test_cids):
    precisions = []
    recalls = []
    f1_scores = []
    for repeat_cnt in range(0, 3):
        find_cnt = 0
        find_true_cnt = 0
        true_cnt = 0
        for info in all_info:
            repo_name = info["repo_name"]
            bug_fixing_cid = info["bug_fixing_commit"]
            if bug_fixing_cid not in test_cids:
                continue
            bug_inducing_cids = info["bug_inducing_commit"]
            true_cnt = true_cnt + len(bug_inducing_cids)
            repo_path = os.path.join(REPOS_DIR, repo_name)

            save_path = os.path.join(
                SAVE_LOG_DIR, repo_name, bug_fixing_cid, f"llm4szz_re{repeat_cnt}.json"
            )

            save_dir_path = os.path.join(SAVE_LOG_DIR, repo_name, bug_fixing_cid)

            if os.path.exists(save_path):

                logs = []
                with open(save_path) as f:
                    logs = json.load(f)

                s1_final_cids = []
                s1_ranked_stmts_infos = []
                for log in logs:
                    if "s1_ranked_stmts_infos" in str(log):
                        s1_ranked_stmts_infos.extend(log["s1_ranked_stmts_infos"][:5])

                for rank_info in s1_ranked_stmts_infos:
                    s1_final_cids.append(rank_info["induce_cid"])

                s1_final_cids = list(set(s1_final_cids))
                s1_final_cids = get_r_commits(repo_name, s1_final_cids)

                for final_cid in s1_final_cids:
                    for cid1 in bug_inducing_cids:
                        if cid1 in final_cid:
                            find_true_cnt = find_true_cnt + 1

                find_cnt = find_cnt + len(s1_final_cids)
        if find_cnt != 0 and find_true_cnt != 0:
            precisions.append(find_true_cnt / find_cnt)
            recalls.append(find_true_cnt / true_cnt)
            f1_scores.append(
                (2 * (find_true_cnt / find_cnt) * (find_true_cnt / true_cnt))
                / (find_true_cnt / find_cnt + find_true_cnt / true_cnt)
            )

    return sum(precisions)/len(precisions), sum(recalls)/len(recalls), sum(f1_scores)/len(f1_scores)


def get_metrics_variants_r(all_info, test_cids):
    precisions = []
    recalls = []
    f1_scores = []
    for repeat_cnt in range(0, 3):
        find_cnt = 0
        find_true_cnt = 0
        true_cnt = 0
        for info in all_info:
            repo_name = info["repo_name"]
            bug_fixing_cid = info["bug_fixing_commit"]
            if bug_fixing_cid not in test_cids:
                continue
            bug_inducing_cids = info["bug_inducing_commit"]
            true_cnt = true_cnt + len(bug_inducing_cids)
            repo_path = os.path.join(REPOS_DIR, repo_name)

            save_path = os.path.join(
                SAVE_LOG_DIR, repo_name, bug_fixing_cid, f"llm4szz_r{repeat_cnt}.json"
            )

            save_dir_path = os.path.join(SAVE_LOG_DIR, repo_name, bug_fixing_cid)

            if os.path.exists(save_path):

                logs = []
                with open(save_path) as f:
                    logs = json.load(f)

                s1_final_cids = []
                s1_ranked_stmts_infos = []
                for log in logs:
                    if "s1_ranked_stmts_infos" in str(log):
                        s1_ranked_stmts_infos.extend(log["s1_ranked_stmts_infos"][:5])

                for rank_info in s1_ranked_stmts_infos:
                    s1_final_cids.append(rank_info["induce_cid"])

                s1_final_cids = list(set(s1_final_cids))
                s1_final_cids = get_r_commits(repo_name, s1_final_cids)

                for final_cid in s1_final_cids:
                    for cid1 in bug_inducing_cids:
                        if cid1 in final_cid:
                            find_true_cnt = find_true_cnt + 1

                find_cnt = find_cnt + len(s1_final_cids)
        if find_cnt != 0 and find_true_cnt != 0:
            precisions.append(find_true_cnt / find_cnt)
            recalls.append(find_true_cnt / true_cnt)
            f1_scores.append(
                (2 * (find_true_cnt / find_cnt) * (find_true_cnt / true_cnt))
                / (find_true_cnt / find_cnt + find_true_cnt / true_cnt)
            )
    # print(precisions)
    # print(recalls)
    # print(f1_scores)
    return sum(precisions)/len(precisions), sum(recalls)/len(recalls), sum(f1_scores)/len(f1_scores)
