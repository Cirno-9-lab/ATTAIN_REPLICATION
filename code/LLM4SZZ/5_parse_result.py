import os
import json
from util import *
import git
import constant
import functools
from tree_sitter import Language, Parser
import tree_sitter as ts
import tree_sitter_c

input_path = '/output'

patchs = os.listdir(input_path)

SAVE_PATH = ""
except_infos = []
repos = ['FFmpeg', 'openssl', 'wireshark', 'curl', 'httpd', 'ImageMagick', 'qemu', 'openjpeg', 'linux']
for repo in repos:
    repo_path = os.path.join(REPOS_DIR, repo)
    git_repo = git.Repo(repo_path)

    with open(f"./dataset/{repo}_dataset_fa.json") as f:
        dataset = json.load(f)

    for info in dataset:
        C_LANGUAGE = Language(tree_sitter_c.language(), "c")
        c_parser = Parser()
        c_parser.set_language(C_LANGUAGE)
        repo_path = os.path.join(REPOS_DIR, repo)

        git_repo = git.Repo(repo_path)
        cid = info["fix_commit_hash"]

        print(f"begin to deal with {cid}")
        save_cid_path = os.path.join(SAVE_PATH, cid)
        read_path = os.path.join(input_path, cid, 'save_info.json')
        with open(read_path, 'r') as f:
            save_info = json.load(f)
        all_buggy_stmt_dicts = save_info['buggy_stmts']
        cand_cids = set()
        for buggy_stmt_dict in all_buggy_stmt_dicts:
            for i in buggy_stmt_dict["cids"]:
                cand_cids.add(i)
            
        cand_cids = list(cand_cids)
        cid_infos = []
        for cand_cid in cand_cids:
            date_time = git_repo.commit(cand_cid).committed_datetime
            cid_infos.append({"cid": cand_cid, "datetime": date_time})
        cid_infos.sort(key=functools.cmp_to_key(my_compare))
        cand_cids = []

        for cid_info in cid_infos:
            cand_cids.append(cid_info["cid"])

        for cand_cid in cand_cids:
            flag = False
            for buggy_stmt_dict in all_buggy_stmt_dicts:
                if match_buggy_stmts(
                    repo_path, cand_cid, buggy_stmt_dict, c_parser, C_LANGUAGE
                ):
                    save_info["find_cids"].append(cand_cid)
                    flag = True
                    break
            if flag:
                break
        if len(save_info["find_cids"]) == 0 and len(cand_cids) > 0:
            save_info["find_cids"] = [cand_cids[0]]
        os.makedirs(save_cid_path, exist_ok=True)
        save_info_path = os.path.join(save_cid_path, "save_info.json")
        save_info["find_cid"] = get_r_commits(repo, save_info["find_cids"])
        with open(save_info_path, "w") as f:
            json.dump(save_info, f)
        

    with open(f"./dataset/{repo}_dataset_d.json") as f:
        dataset = json.load(f)
    

    for info in dataset:
        try:
            C_LANGUAGE = Language(tree_sitter_c.language(), "c")
            c_parser = Parser()
            c_parser.set_language(C_LANGUAGE)
            cid = info["fix_commit_hash"]
            print(f"begin to deal with {cid}")

            save_cid_path = os.path.join(SAVE_PATH, cid)

            read_path = os.path.join(input_path, cid, 'save_info.json')
            with open(read_path, 'r') as f:
                save_info = json.load(f)
            
            all_buggy_stmt_dicts = save_info['buggy_stmts_dicts']
            final_cid = []
            final_cid_cands = []
            for buggy_stmt_dict in all_buggy_stmt_dicts:
                cand_cids = list(set(buggy_stmt_dict["cids"]))
                cand_cid_infos = []
                for cand_cid in cand_cids:
                    date_time = git_repo.commit(cand_cid).committed_datetime
                    cand_cid_infos.append({"cid": cand_cid, "datetime": date_time})
                cand_cid_infos.sort(key=functools.cmp_to_key(my_compare))
                flag = False
                for cand_cid_info in cand_cid_infos:
                    if match_buggy_stmts(
                        repo_path,
                        cand_cid_info["cid"],
                        buggy_stmt_dict,
                        c_parser,
                        C_LANGUAGE,
                    ):
                        flag = True
                        final_cid_cands.append(cand_cid_info["cid"])
                        break
                if not flag and len(cand_cid_infos) > 0:
                    final_cid_cands.append(cand_cid_infos[-1]["cid"])

            final_cid_infos = []
            for cid_cand in final_cid_cands:
                final_cid_infos.append(
                    {
                        "cid": cid_cand,
                        "datetime": git_repo.commit(cid_cand).committed_datetime,
                    }
                )
            final_cid_infos.sort(key=functools.cmp_to_key(my_compare))
            if len(final_cid_infos) > 0:
                final_cid = [final_cid_infos[-1]["cid"]]

        # print(all_buggy_stmt_dicts)
        except:
            except_infos.append(info)
            traceback.print_exc()
        finally:
            # print(final_cid)
            # save_info["buggy_stmts_dicts"] = all_buggy_stmt_dicts
            save_info["find_cid"] = final_cid
            os.makedirs(save_cid_path, exist_ok=True)
            save_info_path = os.path.join(save_cid_path, "save_info.json")
            with open(save_info_path, "w") as f:
                json.dump(save_info, f)
        
        