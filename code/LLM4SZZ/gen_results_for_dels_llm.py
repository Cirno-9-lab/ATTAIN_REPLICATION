# %%
from tree_sitter import Language, Parser
import tree_sitter as ts
import tree_sitter_c
from CFG import *
from util import *
import copy
import git
import functools
import Levenshtein
import json
import traceback
import argparse
from core.vszz import *


def get_introducing_cid(repo_path, cid, patch_file_name, lineno):
    repo = git.Repo(repo_path)
    blame_result = repo.blame(cid, patch_file_name, L=lineno)
    commit = blame_result[0][0].hexsha
    return commit


# %%
def get_pre_diff_line(
    pre_path, cur_path, cfg1, cfg2, line_pre2cur, line_cur2pre, c_lan
):
    state1 = collect_state(pre_path, cfg1, c_lan)
    # print(f'state1:\n{state1.__str__()}')
    state2 = collect_state(cur_path, cfg2, c_lan)
    # print(f'state2:\n{state2.__str__()}')

    cons1 = state1.all_constraint
    cons2 = state2.all_constraint

    cur_buggy_stmts = []

    i = 0
    while i < len(cons1) and i < len(cons2):
        if cons1[i].con_str != cons2[i].con_str:
            break
        i = i + 1

    if not (i == len(cons1) and i == len(cons2)):
        buggy_stmt = BuggyStmt(True)
        for con1 in cons1:
            if con1.beg_line not in line_pre2cur:
                buggy_stmt.add_line(con1.beg_line)
        if len(buggy_stmt.lines) > 0:
            cur_buggy_stmts.append(buggy_stmt)

    if len(cur_buggy_stmts) != 0:
        return cur_buggy_stmts

    for pre_ident_name, pre_ident_info in state1.ident_table.items():
        buggy_stmt = BuggyStmt(False)
        for i, _ in enumerate(pre_ident_info.beg_dataflow_pos):
            beg_pos = pre_ident_info.beg_dataflow_pos[i]
            end_pos = pre_ident_info.end_dataflow_pos[i]
            for lineno in range(beg_pos, end_pos + 1):
                if lineno not in line_pre2cur:
                    buggy_stmt.add_line(lineno)

            if len(buggy_stmt.lines) != 0:
                cur_buggy_stmts.append(buggy_stmt)

    return cur_buggy_stmts

# fadjson
# %%
parser = argparse.ArgumentParser()
parser.add_argument('repo')
repo = parser.parse_args().repo

# %%
read_list = ['dataset_d', 'dataset_fa']
for _ in read_list:
    dataset = []
    with open(f"./dataset/{repo}_{_}.json") as f:
        dataset = json.load(f)
    
    except_infos = []
    # enter your save results path here
    SAVE_PATH = ""

    runned_cid_list = []
    commits_list_tmp = os.listdir(SAVE_PATH)
    for commit_key in commits_list_tmp:
        runned_cid_list.append(commit_key)

    bad_case_write = open(f'bad_case/{repo}_bad_case_result.txt', 'a')

    # combine_vszz
    use_temp_dir = False
    v_szz = MySZZ(repo_full_name=repo, repo_url='', repos_dir=REPOS_DIR, use_temp_dir=use_temp_dir)
    llm_input_path = '/save_logs'

    except_infos = []
    for info in dataset:
        C_LANGUAGE = Language(tree_sitter_c.language(), "c")
        c_parser = Parser()
        c_parser.set_language(C_LANGUAGE)
        repo_path = os.path.join(REPOS_DIR, repo)
        git_repo = git.Repo(repo_path)
        cid = info["fix_commit_hash"]
        # if '6b98dc63701b1da1cc7681cb383dabb0b7007d73' not in cid:
        #     continue
        llm_read_path = os.path.join(llm_input_path, repo)

        save_info = {}
        save_info["info"] = info
        # print(info)
        save_info["buggy_stmts"] = []
        save_info["find_cids"] = []
        save_info["find_cid"] = []

        save_cid_path = os.path.join(SAVE_PATH, cid)

        print(f"\033[31mbegin to deal with {cid}\033[0m")

        if os.path.exists(os.path.join(llm_read_path, cid)):
            with open(os.path.join(llm_read_path, cid, f"llm4szz0.json"), "r") as f:
                llm_input_json = json.load(f)
        else:
            os.makedirs(save_cid_path, exist_ok=True)
            save_info_path = os.path.join(save_cid_path, "save_info.json")
            with open(save_info_path, "w") as f:
                json.dump(save_info, f)
            continue


        llm_statement = {}
        for log in llm_input_json:
            if 's2_cand_stmts' in str(log):
                llm_statement = log
        

        if llm_statement == {}:
            os.makedirs(save_cid_path, exist_ok=True)
            save_info_path = os.path.join(save_cid_path, "save_info.json")
            with open(save_info_path, "w") as f:
                json.dump(save_info, f)
            continue
        #
        try:

            buggy_stmt_dicts = []

            tmp_file_statements_dict = {}
            for statement_item in llm_statement['s2_cand_stmts']:
                if statement_item['file_name'] not in tmp_file_statements_dict:
                    tmp_file_statements_dict[statement_item['file_name']] = [[], [], False]

                if statement_item['lineno'] not in tmp_file_statements_dict[statement_item['file_name']][0]:
                    tmp_file_statements_dict[statement_item['file_name']][0].append(statement_item['lineno'])
                    tmp_file_statements_dict[statement_item['file_name']][1].append(statement_item['buggy_stmt'])
                    if 'if' in statement_item['buggy_stmt']:
                        tmp_file_statements_dict[statement_item['file_name']][2] = True


            for file, statement_item in tmp_file_statements_dict.items():
                buggy_stmt_dicts.append({
                    "func_name": 'LLM_test',
                    "lines": statement_item[0],
                    "line_strs": statement_item[1],
                    'is_cond': statement_item[2],
                    'patch_file_name': file,
                })
                
            blame_dict = {}

            for buggy_stmt_dict in buggy_stmt_dicts:
                file_name = buggy_stmt_dict["patch_file_name"]
                if file_name not in blame_dict:
                    blame_dict[file_name] = {}
                for lineno in buggy_stmt_dict["lines"]:
                    func_name = buggy_stmt_dict["func_name"]
                    lst = blame_dict[file_name].get(func_name, [])
                    lst.append(lineno)

                    blame_dict[file_name][func_name] = list(set(lst))
            bug_introducing_commits = v_szz.find_bic(fix_commit_hash=cid, impacted_files=blame_dict)

            #sem-szz，tmp
            vszz_buggy_stmt_dicts = []
            tmp_dict = {}

            for vszz_introducing_data in bug_introducing_commits:
                if vszz_introducing_data["func_name"] not in tmp_dict:
                    tmp_dict[vszz_introducing_data["func_name"]] = {
                        "lines": [vszz_introducing_data["previous_commits"][-1][1]],
                        "line_strs": [vszz_introducing_data["previous_commits"][-1][2]],
                        "patch_file_name": vszz_introducing_data["file_path"],
                        'cids': [vszz_introducing_data["previous_commits"][-1][0]],
                    }

                else:
                    tmp_dict[vszz_introducing_data["func_name"]]["lines"].append(
                        vszz_introducing_data["previous_commits"][-1][1]
                    )
                    tmp_dict[vszz_introducing_data["func_name"]]["line_strs"].append(
                        vszz_introducing_data["previous_commits"][-1][2]
                    )
                    tmp_dict[vszz_introducing_data["func_name"]]["cids"].append(
                        vszz_introducing_data["previous_commits"][-1][0]
                    )

            cand_cids = []
            for func_name, func_data in tmp_dict.items():
                vszz_buggy_stmt_dicts.append({
                    "func_name": func_name,
                    "lines": func_data["lines"],
                    "line_strs": func_data["line_strs"],
                    "patch_file_name": func_data["patch_file_name"],
                    "cids": func_data["cids"]
                })
                cand_cids.extend(func_data["cids"])

            
            all_buggy_stmt_dicts = vszz_buggy_stmt_dicts

            final_cid = []

            # 
            cand_cids = set(cand_cids)
            final_cid_cands = []
            
            for buggy_stmt_dict in all_buggy_stmt_dicts:
                cand_cids = list(set(buggy_stmt_dict["cids"]))
                
                final_cid_cands.extend(cand_cids)

                #init

                cand_cid_infos = []
                for cand_cid in cand_cids:
                    date_time = git_repo.commit(cand_cid).committed_datetime
                    cand_cid_infos.append({"cid": cand_cid, "datetime": date_time})
                cand_cid_infos.sort(key=functools.cmp_to_key(my_compare))
                flag = False
                for cand_cid_info in cand_cid_infos:
                    if match_buggy_stmts_llm(
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

            save_info["buggy_stmts"].extend(all_buggy_stmt_dicts)
            save_info["find_cid"] = final_cid

        
        except:
            except_infos.append(info)
            traceback.print_exc()

        finally:
            os.makedirs(save_cid_path, exist_ok=True)
            save_info_path = os.path.join(save_cid_path, "save_info.json")
            with open(save_info_path, "w") as f:
                json.dump(save_info, f)
            
