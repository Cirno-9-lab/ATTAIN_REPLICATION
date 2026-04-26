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

# %%
parser = argparse.ArgumentParser()
parser.add_argument('repo')
repo = parser.parse_args().repo

# %%
dataset = []
with open(f"./dataset/{repo}_dataset_d.json") as f:
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


except_infos = []
for info in dataset:
    C_LANGUAGE = Language(tree_sitter_c.language(), "c")
    c_parser = Parser()
    c_parser.set_language(C_LANGUAGE)
    repo_path = os.path.join(REPOS_DIR, repo)
    git_repo = git.Repo(repo_path)
    cid = info["fix_commit_hash"]
    print(f"begin to deal with {cid}")
    patch_content = get_patch_content(repo_path, cid)
    patch = Patch(patch_content)

    save_info = {}
    save_info["info"] = info
    # print(info)
    save_info["buggy_stmts_dicts"] = []
    save_info["find_cids"] = []
    save_cid_path = os.path.join(SAVE_PATH, cid)
    try:
        all_buggy_stmt_dicts = []
        for patch_file in patch.get_files():

            patch_file_name = patch_file.file_name
            print(f"begin to deal with {patch_file_name}")
            if ".c" not in patch_file_name:
                continue
            pre_file_content = get_file_content(repo_path, f"{cid}^1", patch_file_name)
            cur_file_content = get_file_content(repo_path, f"{cid}", patch_file_name)

            line_pre2cur = get_line_map(
                f"{cid}^1",
                cid,
                git_repo,
                patch_file_name,
                len(pre_file_content.split("\n")),
            )
            line_cur2pre = get_line_map(
                cid,
                f"{cid}^1",
                git_repo,
                patch_file_name,
                len(cur_file_content.split("\n")),
            )

            patch_content = get_patch_content(repo_path, cid)
            patch = Patch(patch_content)

            pre_tree = c_parser.parse(bytes(pre_file_content, "utf8"))
            pre_root_node = pre_tree.root_node

            cur_tree = c_parser.parse(bytes(cur_file_content, "utf8"))
            cur_root_node = cur_tree.root_node

            del_lines, added_lines = get_changed_lines(patch, patch_file_name)

            pre_changed_funcs = []
            pre_funcs = get_func_defs(pre_root_node, C_LANGUAGE)

            cur_changed_funcs = []
            cur_funcs = get_func_defs(cur_root_node, C_LANGUAGE)

            for del_line in del_lines:
                f_node = get_ts_node_by_line(pre_funcs, del_line)
                if (f_node is not None) and (f_node not in pre_changed_funcs):
                    pre_changed_funcs.append(f_node)

            for added_line in added_lines:
                f_node = get_ts_node_by_line(cur_funcs, added_line)
                if (f_node is not None) and (f_node not in cur_changed_funcs):
                    cur_changed_funcs.append(f_node)

            changed_func_map = {}
            print(f"len(pre_changed_funcs):{len(pre_changed_funcs)}")
            for pre_changed_func in pre_changed_funcs:
                pre_changed_func_name = get_func_name(pre_changed_func, C_LANGUAGE)
                for cur_func in cur_funcs:
                    cur_func_name = get_func_name(cur_func, C_LANGUAGE)
                    if pre_changed_func_name == cur_func_name:
                        changed_func_map[pre_changed_func] = cur_func

            print(f"len(cur_changed_funcs):{len(cur_changed_funcs)}")
            for cur_changed_func in cur_changed_funcs:
                cur_changed_func_name = get_func_name(cur_changed_func, C_LANGUAGE)
                for pre_func in pre_funcs:
                    pre_func_name = get_func_name(pre_func, C_LANGUAGE)
                    if pre_func_name == cur_changed_func_name:
                        changed_func_map[pre_func] = cur_changed_func

            block_pre2cur = {}
            block_cur2pre = {}

            print(f"len(changed_func_map):{len(changed_func_map)}")

            cur_buggy_stmt_dicts = []

            for pre_func_node, cur_func_node in changed_func_map.items():
                print(
                    f"begin to deal with func {get_func_name(pre_func_node,C_LANGUAGE)}"
                )
                pre_cfg = CFG(pre_func_node)
                cur_cfg = CFG(cur_func_node)

                pre_basic_blocks = []
                for _, basic_block in pre_cfg.basic_blocks.items():
                    pre_basic_blocks.append(basic_block)

                cur_basic_blocks = []
                for _, basic_block in cur_cfg.basic_blocks.items():
                    cur_basic_blocks.append(basic_block)

                pre_changed_basic_blocks = []
                cur_changed_basic_blocks = []

                for del_line in del_lines:
                    pre_changed_basic_blocks.extend(
                        get_basic_blocks_by_line(pre_basic_blocks, del_line)
                    )

                for added_line in added_lines:
                    cur_changed_basic_blocks.extend(
                        get_basic_blocks_by_line(cur_basic_blocks, added_line)
                    )

                cur_all_path = get_all_paths(cur_changed_basic_blocks, 3, cur_cfg)
                cur_all_path = cur_all_path[:5]
                # print(f'cur_all_path:{len(cur_all_path)}')

                pre_all_path = get_all_paths(pre_changed_basic_blocks, 3, pre_cfg)
                # print(f'pre_all_path:{len(pre_all_path)}')

                block_pre2cur, block_cur2pre = get_block_map(
                    pre_basic_blocks,
                    cur_basic_blocks,
                    pre_changed_basic_blocks,
                    cur_changed_basic_blocks,
                    line_pre2cur,
                    line_cur2pre,
                    pre_cfg,
                    cur_cfg,
                )

                cur_buggy_stmts = []

                pre_all_path = pre_all_path[:5]
                for pre_path in pre_all_path:
                    pre_path = filter_path(pre_path)
                    # print(f'pre_path:\n{pre_cfg.get_path_str(pre_path)}')
                    if len(pre_path) == 0:
                        continue

                    if pre_path[0] not in block_pre2cur:
                        continue

                    cur_beg_block = block_pre2cur[pre_path[0]]
                    cur_end_block = None

                    if pre_path[-1] in block_pre2cur:
                        cur_end_block = block_pre2cur[pre_path[-1]]

                    pre_max_line = get_path_max_line(pre_path)
                    cur_max_line = -1
                    if pre_max_line in line_pre2cur:
                        cur_max_line = line_pre2cur[pre_max_line]

                    path_candidates = get_corr_paths_candidates(
                        cur_beg_block, cur_end_block, len(pre_path) + 2, -1, cur_cfg
                    )
                    if len(path_candidates) == 0:
                        continue
                    if len(path_candidates) > 100:
                        continue
                    corr_path = get_correspond_path(
                        pre_path,
                        pre_cfg,
                        path_candidates,
                        cur_cfg,
                        line_pre2cur,
                        C_LANGUAGE,
                    )
                    buggy_stmts = get_pre_diff_line(
                        pre_path,
                        corr_path,
                        pre_cfg,
                        cur_cfg,
                        line_pre2cur,
                        line_cur2pre,
                        C_LANGUAGE,
                    )

                    for buggy_stmt in buggy_stmts:
                        if buggy_stmt.is_cond:
                            cur_buggy_stmts.clear()
                            cur_buggy_stmts.append(buggy_stmt)
                        else:
                            cur_buggy_stmts.append(buggy_stmt)

                if len(cur_buggy_stmts) == 0 and len(del_lines) != 0:
                    buggy_stmt = BuggyStmt(False)
                    for del_line in del_lines:
                        buggy_stmt.add_line(del_line)
                    cur_buggy_stmts.append(buggy_stmt)

                for buggy_stmt in cur_buggy_stmts:
                    if buggy_stmt.is_cond:
                        cur_buggy_stmt_dicts.clear()
                    buggy_stmt.lines.sort()
                    line_strs = []
                    for lineno in buggy_stmt.lines:
                        line_strs.append(pre_file_content.split("\n")[lineno - 1])
                    cur_buggy_stmt_dicts.append(
                        {
                            "func_name": get_func_name(pre_func_node, C_LANGUAGE),
                            "lines": buggy_stmt.lines,
                            "line_strs": line_strs,
                            "is_cond": buggy_stmt.is_cond,
                            "patch_file_name": patch_file_name,
                        }
                    )
            
            for buggy_stmt_dict in cur_buggy_stmt_dicts:
                if (
                    (not buggy_stmt_dict["is_cond"])
                    and len(cur_buggy_stmt_dicts) > 0
                    and cur_buggy_stmt_dicts[0]["is_cond"]
                ):
                    continue
                if (
                    buggy_stmt_dict["is_cond"]
                    and len(cur_buggy_stmt_dicts) > 0
                    and (not cur_buggy_stmt_dicts[0]["is_cond"])
                ):
                    all_buggy_stmt_dicts.clear()
                lines = buggy_stmt_dict["lines"]
                lines_cand_cid = []
                for lineno in lines:
                    lines_cand_cid.append(
                        get_introducing_cid(
                            repo_path, f"{cid}^1", patch_file_name, lineno
                        )
                    )
                buggy_stmt_dict["cids"] = lines_cand_cid
                all_buggy_stmt_dicts.append(buggy_stmt_dict)

        #added to combine vszz
        blame_dict = {}

        for buggy_stmt_dict in all_buggy_stmt_dicts:
            file_name = buggy_stmt_dict["patch_file_name"]
            if file_name not in blame_dict:
                blame_dict[file_name] = {}
            for lineno in buggy_stmt_dict["lines"]:
                func_name = buggy_stmt_dict["func_name"]
                lst = blame_dict[file_name].get(func_name, [])
                lst.append(lineno)

                blame_dict[file_name][func_name] = list(set(lst))
        
        print(all_buggy_stmt_dicts)
        print(blame_dict)
        exit(0)
        
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
                "patch_file_name": patch_file_name,
                "cids": func_data["cids"]
            })
            cand_cids.extend(func_data["cids"])

        cand_cids = set(cand_cids)


            
        all_buggy_stmt_dicts = vszz_buggy_stmt_dicts
        

        final_cid = []

        # 
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

        # final_cid = get_l_commits(repo, final_cid_cands)
        

        
        save_info["buggy_stmts_dicts"] = all_buggy_stmt_dicts
        save_info["find_cid"] = final_cid
    

    except:
        except_infos.append(info)
        traceback.print_exc()

    finally:
        exit(0)
        os.makedirs(save_cid_path, exist_ok=True)
        save_info_path = os.path.join(save_cid_path, "save_info.json")
        with open(save_info_path, "w") as f:
            json.dump(save_info, f)
        
