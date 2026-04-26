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


def get_cur_diff_line(pre_path, cur_path, cfg1, cfg2, line_cur2pre, c_lan):
    state1 = collect_state(pre_path, cfg1, c_lan)
    state2 = collect_state(cur_path, cfg2, c_lan)

    cons1 = state1.all_constraint
    cons2 = state2.all_constraint

    all_buggy_stmts = []

    i = 0

    while i < len(cons1) and i < len(cons2):
        if cons1[i].con_str != cons2[i].con_str:

            break
        i = i + 1

    if i == len(cons1) and i < len(cons2):
        all_buggy_stmts.append(get_add_cond_info(cons2, i, line_cur2pre))
    elif i < len(cons1) and i < len(cons2):
        all_buggy_stmts.append(get_add_cond_info(cons2, i, line_cur2pre))

    if len(all_buggy_stmts) != 0 and len(all_buggy_stmts[0].lines) != 0:
        return all_buggy_stmts

    for pre_ident_name, pre_ident_info in state1.ident_table.items():
        cur_ident_table = state2.ident_table

        if pre_ident_name not in cur_ident_table:
            continue

        cur_ident_info = cur_ident_table[pre_ident_name]
        buggy_stmt = get_add_ident_info(pre_ident_info, cur_ident_info)
        if len(buggy_stmt.lines) > 0:
            all_buggy_stmts.append(buggy_stmt)

    return all_buggy_stmts


def get_curr_diff_line1(cur_path, changed_lines, line_cur2pre):
    all_buggy_stmts = []
    path_cfg_nodes = []
    for basic_block in cur_path:
        path_cfg_nodes.extend(basic_block.get_cfg_nodes())

    if len(path_cfg_nodes) == 0:
        return all_buggy_stmts

    changed_nodes = []
    for changed_line in changed_lines:
        ts_node = get_ts_node_by_line(path_cfg_nodes, changed_line)
        if ts_node is not None:
            changed_nodes.append(ts_node)

    for changed_node in changed_nodes:
        index = path_cfg_nodes.index(changed_node)

        pre_node = None
        next_node = None

        if index > 0:
            pre_node = path_cfg_nodes[index - 1]
        if index < len(path_cfg_nodes) - 1:
            next_node = path_cfg_nodes[index + 1]

        buggy_stmt = BuggyStmt(False)
        if pre_node is not None:
            if pre_node.start_point[0] + 1 in line_cur2pre:
                buggy_stmt.add_line(line_cur2pre[pre_node.start_point[0] + 1])
        if next_node is not None:
            if next_node.start_point[0] + 1 in line_cur2pre:
                buggy_stmt.add_line(line_cur2pre[next_node.start_point[0] + 1])
        all_buggy_stmts.append(buggy_stmt)

    if len(all_buggy_stmts) == 0:
        for changed_line in changed_lines:
            pre_line = -1
            next_line = -1
            for i in range(changed_line, 0, -1):
                if i not in changed_lines:
                    pre_line = i
                    break

            for i in range(changed_line, changed_line + 100):
                if i not in changed_lines:
                    next_line = i
                    break

            if pre_line != -1 and next_line != -1:
                buggy_stmt = BuggyStmt(False)
                buggy_stmt.add_line(line_cur2pre[pre_line])
                buggy_stmt.add_line(line_cur2pre[next_line])
                all_buggy_stmts.append(buggy_stmt)

    return all_buggy_stmts


# %%

# %%
parser = argparse.ArgumentParser()
parser.add_argument('repo')
repo = parser.parse_args().repo

# %%
dataset = []
with open(f"./dataset/{repo}_dataset_fa.json") as f:
    dataset = json.load(f)

except_infos = []
# enter your save results path here
SAVE_PATH = ""

runned_cid_list = []
commits_list_tmp = os.listdir(SAVE_PATH)
for commit_key in commits_list_tmp:
    runned_cid_list.append(commit_key)


for info in dataset:
    C_LANGUAGE = Language(tree_sitter_c.language(), "c")
    c_parser = Parser()
    c_parser.set_language(C_LANGUAGE)
    repo_path = os.path.join(REPOS_DIR, repo)

    git_repo = git.Repo(repo_path)
    cid = info["fix_commit_hash"]
    # if cid in runned_cid_list:
    #     continue

    print(f"begin to deal with {cid}")
    save_cid_path = os.path.join(SAVE_PATH, cid)
    try:
        patch_content = get_patch_content(repo_path, cid)
    except Exception as e:
        bad_case_write.write(f'{repo} {cid} \n')
        continue
    
    patch = Patch(patch_content)

    save_info = {}
    save_info["info"] = info
    save_info["buggy_stmts"] = []
    save_info["find_cids"] = []

    try:
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

            for pre_changed_func in pre_changed_funcs:
                pre_changed_func_name = get_func_name(pre_changed_func, C_LANGUAGE)
                for cur_func in cur_funcs:
                    cur_func_name = get_func_name(cur_func, C_LANGUAGE)
                    if pre_changed_func_name == cur_func_name:
                        changed_func_map[pre_changed_func] = cur_func

            for cur_changed_func in cur_changed_funcs:
                cur_changed_func_name = get_func_name(cur_changed_func, C_LANGUAGE)
                for pre_func in pre_funcs:
                    pre_func_name = get_func_name(pre_func, C_LANGUAGE)
                    if pre_func_name == cur_changed_func_name:
                        changed_func_map[pre_func] = cur_changed_func

            block_pre2cur = {}
            block_cur2pre = {}

            buggy_stmt_dicts = []

            for pre_func_node, cur_func_node in changed_func_map.items():
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

                pre_all_path = get_all_paths(pre_changed_basic_blocks, 3, pre_cfg)

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

                all_buggy_stmts = []
                for cur_path in cur_all_path:
                    cur_path = filter_path(cur_path)

                    if len(cur_path) == 0:
                        continue

                    if cur_path[0] not in block_cur2pre:
                        continue

                    pre_beg_block = block_cur2pre[cur_path[0]]
                    pre_end_block = None

                    if cur_path[-1] in block_cur2pre:
                        pre_end_block = block_cur2pre[cur_path[-1]]

                    cur_max_line = get_path_max_line(cur_path)
                    pre_max_line = -1
                    if cur_max_line in line_cur2pre:
                        pre_max_line = line_cur2pre[cur_max_line]

                    path_candidates = get_corr_paths_candidates(
                        pre_beg_block, pre_end_block, len(cur_path) + 2, -1, pre_cfg
                    )

                    if len(path_candidates) == 0:
                        continue

                    path_candidates = path_candidates  # [10:12]

                    corr_path = get_correspond_path(
                        cur_path,
                        cur_cfg,
                        path_candidates,
                        pre_cfg,
                        line_cur2pre,
                        C_LANGUAGE,
                    )

                    buggy_stmts = get_cur_diff_line(
                        corr_path, cur_path, pre_cfg, cur_cfg, line_cur2pre, C_LANGUAGE
                    )

                    for buggy_stmt in buggy_stmts:
                        if buggy_stmt.is_cond:
                            all_buggy_stmts.clear()
                            all_buggy_stmts.append(buggy_stmt)
                        else:
                            all_buggy_stmts.append(buggy_stmt)

                cid_finder = CidFinder()

                if len(all_buggy_stmts) == 0 and len(cur_all_path) > 0:
                    all_buggy_stmts = get_curr_diff_line1(
                        cur_all_path[0], added_lines, line_cur2pre
                    )

                for buggy_stmt in all_buggy_stmts:
                    buggy_stmt.lines.sort()
                    line_strs = []
                    for lineno in buggy_stmt.lines:
                        line_strs.append(pre_file_content.split("\n")[lineno - 1])
                    buggy_stmt_dicts.append(
                        {
                            "func_name": get_func_name(pre_func_node, C_LANGUAGE),
                            "lines": buggy_stmt.lines,
                            "line_strs": line_strs,
                            "is_cond": buggy_stmt.is_cond,
                            "patch_file_name": patch_file_name,
                        }
                    )

                cand_cids = set()
                for buggy_stmt_dict in buggy_stmt_dicts:
                    lines = buggy_stmt_dict["lines"]
                    lines_cand_cid = []
                    for lineno in lines:
                        lines_cand_cid.append(
                            cid_finder.get_introducing_cid(
                                repo_path, f"{cid}^1", patch_file_name, lineno
                            )
                        )
                    for cand_cid in lines_cand_cid:
                        cand_cids.add(cand_cid)
                    buggy_stmt_dict["cids"] = lines_cand_cid
                print(buggy_stmt_dict)
                exit(0)
                
                save_info["buggy_stmts"].extend(buggy_stmt_dicts)

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
                    for buggy_stmt_dict in buggy_stmt_dicts:
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

    except:
        except_infos.append(info)
        traceback.print_exc()

    finally:
        exit(0)
        os.makedirs(save_cid_path, exist_ok=True)
        save_info_path = os.path.join(save_cid_path, "save_info.json")
        save_info["find_cid"] = get_r_commits(repo, save_info["find_cids"])
        with open(save_info_path, "w") as f:
            json.dump(save_info, f)
