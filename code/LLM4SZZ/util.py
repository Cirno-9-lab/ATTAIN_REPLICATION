import os
import subprocess
from pydriller import ModificationType, GitRepository as PyDrillerGitRepo
import git
from tree_sitter import Language, Parser
import tree_sitter
import os
from util import *
from parse_patch import *
import subprocess, tempfile
from constant import *
from collections import Counter
import Levenshtein
import copy


def get_patch_content(repo_path, cid):
    cwd = os.getcwd()
    os.chdir(repo_path)
    cmd = f"git format-patch {cid} -1 --stdout"
    patch_content = subprocess.check_output(cmd, shell=True).decode(
        "utf-8", errors="ignore"
    )
    os.chdir(cwd)
    return patch_content


def get_file_content(repo_path, cid, file_name):
    cwd = os.getcwd()
    try:
        os.chdir(repo_path)
        cmd = f"git show {cid}:{file_name}"
        file_content = subprocess.check_output(cmd, shell=True).decode(
            "utf-8", errors="ignore"
        )
        os.chdir(cwd)
        return file_content
    except Exception as e:
        os.chdir(cwd)
        return ""


def get_func_defs(root_node, c_lan):
    # func_def_query = c_lan.query(
    #     """
    #     ((function_definition
    #     declarator: (function_declarator
    #     declarator: (identifier) @function.name))
    #     @function.definition)
    # """
    # )
    func_def_query = c_lan.query(
        """
        ((function_definition body: (compound_statement))
        @function.definition)
        """
    )
    nodes = []
    method_def_results = func_def_query.captures(root_node)
    nodes.extend([result[0] for result in method_def_results])

    ret_nodes = []
    for node in nodes:
        if node.child_by_field_name("body") is not None:
            ret_nodes.append(node)
    return ret_nodes


def get_func_name(node, c_lan):

    func_name_query = c_lan.query(
        """
    (function_declarator declarator:(identifier)@func_name)
    """
    )

    nodes = []
    func_name_results = func_name_query.captures(node)
    nodes.extend([result[0] for result in func_name_results])

    if len(nodes) == 0:
        return ""

    return nodes[0].text.decode("utf8")


def get_func_call_names(root_node, c_lan):
    query = c_lan.query(
        """
    (call_expression(
        (identifier) @function_name))
    """
    )
    captures = query.captures(root_node)
    function_names = [capture[0].text.decode("utf8") for capture in captures]
    return function_names


def get_introducing_cid(repo_path, cid, patch_file_name, lineno):
    repo = git.Repo(repo_path)
    blame_result = repo.blame(cid, patch_file_name, L=lineno)
    commit = blame_result[0][0].hexsha
    return commit


class CidFinder:
    def __init__(self):
        self.file_cid_map = {}

    def get_introducing_cid(self, repo_path, cid, patch_file_name, lineno):
        if patch_file_name in self.file_cid_map:
            cid_map = self.file_cid_map[patch_file_name]
            return cid_map[lineno]

        git_repo = git.Repo(repo_path)
        blame_gen = git_repo.blame_incremental(rev=f"{cid}^1", file=patch_file_name)
        cid_map = {}
        for entry in blame_gen:
            for l in entry.linenos:
                cid_map[l] = entry.commit.hexsha
        self.file_cid_map[patch_file_name] = cid_map
        return cid_map[lineno]


def get_r_commits(repo_name, cand_cids):
    # （）
    max_date = 0.0
    max_cid = []
    repo_path = os.path.join(REPOS_DIR, repo_name)
    for cand_cid in cand_cids:
        repo = git.Repo(repo_path)
        date = repo.commit(cand_cid).committed_datetime
        if date.timestamp() > max_date:
            max_date = date.timestamp()
            max_cid.clear()
            max_cid.append(cand_cid)

    return max_cid

def get_l_commits(repo_name, cand_cids):
    # （）
    min_date = float('inf')
    min_cid = []
    repo_path = os.path.join(REPOS_DIR, repo_name)
    repo = git.Repo(repo_path)

    for cand_cid in cand_cids:
        commit = repo.commit(cand_cid)
        ts = commit.committed_datetime.timestamp()
       
        if ts < min_date:
            min_date = ts
            min_cid.clear()
            min_cid = [cand_cid]
    

    return min_cid


def get_diff_index(diff_ranges, lineno):
    i = 0
    for i in range(len(diff_ranges)):
        diff_range = diff_ranges[i]
        if lineno >= diff_range[0] and lineno < diff_range[0] + diff_range[1]:
            return i
    return -1


def get_line_map(pre_cid, cur_cid, git_repo, patch_file_name, file_length):
    diff_str = git_repo.git.diff(pre_cid, cur_cid, "--", patch_file_name)
    
    diff_lines = diff_str.split("\n")
    i = 0
    flag = False
    while True:
        if i >= len(diff_lines):
            break
        if diff_lines[i].startswith("@@"):
            flag = True
            break
        i = i + 1

    if not flag:
        line_map = {}
        for j in range(1, file_length + 1):
            line_map[j] = j
        return line_map

    diffs = []
    j = i + 1
    while j < len(diff_lines):
        if diff_lines[j].startswith("@@"):
            diffs.append(diff_lines[i:j])
            i = j
            j = i + 1
        else:
            j = j + 1
    diffs.append(diff_lines[i:j])

    diff_ranges = []
    for diff in diffs:
        beg_line = int(diff[0].split(" ")[1].split(",")[0][1:])
        length = int(diff[0].split(" ")[1].split(",")[1])
        diff_ranges.append([beg_line, length])

    lineno = 1
    offset = 0
    line_map = {}
    while True:
        diff_index = get_diff_index(diff_ranges, lineno)
        if diff_index == -1:
            line_map[lineno] = lineno + offset
            lineno = lineno + 1
        else:
            diff_lines = diffs[diff_index]
            for diff_line in diff_lines[1:]:
                if diff_line.startswith("+"):
                    offset = offset + 1
                elif diff_line.startswith("-"):
                    offset = offset - 1
                    lineno = lineno + 1
                else:
                    line_map[lineno] = lineno + offset
                    lineno = lineno + 1
        if lineno >= file_length:
            break
    return line_map


def get_ts_node_by_line(nodes, lineno):
    for node in nodes:
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        if lineno >= start_line and lineno <= end_line:
            return node
    return None


def get_changed_lines(patch: Patch, patch_file_name):
    del_lines = []
    added_lines = []
    for patch_file in patch.get_files():
        if patch_file.file_name != patch_file_name:
            continue
        for patch_hunk in patch_file.get_hunks():
            for patch_line in patch_hunk.get_lines():
                if patch_line.is_del:
                    del_lines.append(patch_line.lineno)
                if patch_line.is_add:
                    added_lines.append(patch_line.lineno)
    return del_lines, added_lines


def get_basic_blocks_by_line(basic_blocks, lineno):
    ret_basic_blocks = []
    for basic_block in basic_blocks:
        start_line = basic_block.get_beg_line()
        end_line = basic_block.get_end_line()
        # print(f"start_line:{start_line}, end_line:{end_line}, lineno:{lineno}")
        if lineno >= start_line and lineno <= end_line:
            ret_basic_blocks.append(basic_block)
    return ret_basic_blocks


def copy_path(p):
    ret = []
    for b in p:
        ret.append(b)
    return ret


def gen_preds(
    slice_num, step, cfg, cur_block, cur_path, cur_paths, visited, changed_blocks
):
    if (cur_block in visited) and (cur_block not in changed_blocks):
        if len(cur_path) > 0:
            cur_paths.append(copy_path(cur_path))
        return

    visited.add(cur_block)

    if cur_block.get_isbeg():
        cur_path.append(cur_block)
        cur_paths.append(copy_path(cur_path))

        cur_path.pop()

        return

    if step >= slice_num:
        cur_path.append(cur_block)
        cur_paths.append(copy_path(cur_path))
        cur_path.pop()
        return

    cur_path.append(cur_block)

    if cur_block in changed_blocks:
        step = step - 1

    for pred_id in cur_block.get_preds_ids():
        pred_block = cfg.get_basic_block(pred_id)
        gen_preds(
            slice_num,
            step + 1,
            cfg,
            pred_block,
            cur_path,
            cur_paths,
            visited,
            changed_blocks,
        )

    cur_path.pop()


def gen_succs(
    slice_num, step, cfg, cur_block, cur_path, cur_paths, visited, changed_blocks
):

    if cur_block in visited:

        if len(cur_path) > 0:
            cur_paths.append(copy_path(cur_path))
        return

    visited.add(cur_block)

    if cur_block.get_isend():
        cur_path.append(cur_block)
        cur_paths.append(copy_path(cur_path))
        cur_path.pop()
        return

    if cur_block in changed_blocks:

        step = step - 1

    if step >= slice_num:
        cur_path.append(cur_block)
        cur_paths.append(copy_path(cur_path))
        cur_path.pop()
        return

    cur_path.append(cur_block)

    for succ_id in cur_block.get_succs_ids():
        succ_block = cfg.get_basic_block(succ_id)
        gen_succs(
            slice_num,
            step + 1,
            cfg,
            succ_block,
            cur_path,
            cur_paths,
            visited,
            changed_blocks,
        )

    cur_path.pop()


def gen_succs1(
    cur_block, end_block, cfg, step, cur_path, cur_paths, max_step, max_lineno
):

    if cur_block == end_block or cur_block.get_isend():
        cur_path.append(cur_block)
        cur_paths.append(copy_path(cur_path))
        cur_path.pop()
        return

    beg_line = cur_block.get_beg_line()
    if beg_line != -1 and max_lineno != -1 and beg_line > max_lineno:
        cur_paths.append(copy_path(cur_path))
        return

    if step >= max_step:
        cur_path.append(cur_block)
        cur_paths.append(copy_path(cur_path))
        cur_path.pop()
        return

    cur_path.append(cur_block)

    if len(cur_block.get_succs_ids()) == 0:
        cur_paths.append(copy_path(cur_path))
        cur_path.pop()
        return

    for succ_id in cur_block.get_succs_ids():
        succ_block = cfg.get_basic_block(succ_id)
        gen_succs1(
            succ_block,
            end_block,
            cfg,
            step + 1,
            cur_path,
            cur_paths,
            max_step,
            max_lineno,
        )

    cur_path.pop()


def get_all_paths(changed_blocks, slice_num, cfg):
    visited = set()
    all_paths = []
    for changed_block in changed_blocks:
        pred_path = []
        pred_paths = []

        gen_preds(
            slice_num,
            0,
            cfg,
            changed_block,
            pred_path,
            pred_paths,
            visited,
            changed_blocks,
        )

        succ_path = []
        succ_paths = []
        for succ_id in changed_block.get_succs_ids():
            succ_basic_block = cfg.get_basic_block(succ_id)
            gen_succs(
                slice_num,
                0,
                cfg,
                succ_basic_block,
                succ_path,
                succ_paths,
                visited,
                changed_blocks,
            )

        if len(succ_paths) == 0:
            for p in pred_paths:
                p.reverse()
                all_paths.append(p)
            return all_paths

        if len(pred_paths) == 0:
            for p in succ_paths:
                p.insert(0, changed_block)
                all_paths.append(p)
            return all_paths

        for p1 in pred_paths:
            p1.reverse()
            for p2 in succ_paths:
                final_path = p1 + p2
                all_paths.append(final_path)

    return all_paths


def get_corr_paths_candidates(beg_block, end_block, max_step, max_lineno, cfg):
    cur_path = []
    cur_paths = []
    gen_succs1(beg_block, end_block, cfg, 0, cur_path, cur_paths, max_step, max_lineno)
    return cur_paths


def get_path_max_line(path):
    return path[-1].get_end_line()


def get_var_names1(node, var_names, func_names):
    if node.type == "identifier":
        if (node.text.decode("utf8") not in func_names) and (
            not node.text.decode("utf8").isupper()
        ):
            var_names.append(node.text.decode("utf8"))

    for n in node.named_children:
        get_var_names1(n, var_names, func_names)


def get_ident_names(node, c_lan):
    func_call_names = get_func_call_names(node, c_lan)
    var_names = []
    get_var_names1(node, var_names, func_call_names)
    return list(set(var_names))


class Constraint:
    def __init__(self, node, text, flag):
        self.node = node
        self.flag = flag
        if flag:
            self.con_str = text
        else:
            self.con_str = "!" + text
        if ":" in text:
            self.beg_line = node.start_point[0] + 1
            self.end_line = node.start_point[0] + 1
        else:
            self.beg_line = node.start_point[0] + 1
            self.end_line = node.end_point[0] + 1


class Identifier:
    def __init__(self, name):
        self.name = name
        self.dataflow_nodes = []
        self.dataflow_strs = []
        self.beg_dataflow_pos = []
        self.end_dataflow_pos = []

    def add_dataflow(self, node, text):
        self.dataflow_nodes.append(node)
        self.dataflow_strs.append(text)
        self.beg_dataflow_pos.append(node.start_point[0] + 1)
        self.end_dataflow_pos.append(node.end_point[0] + 1)


class State:
    def __init__(self) -> None:
        self.all_constraint = []
        self.ident_table = {}

    def add_constraint(self, n, text, flag):
        self.all_constraint.append(Constraint(n, text, flag))

    def add_ident(self, ident_name, n, text):
        if ident_name not in self.ident_table:
            ident = Identifier(ident_name)
            self.ident_table[ident_name] = ident
        ident = self.ident_table[ident_name]
        ident.add_dataflow(n, text)

    def __str__(self) -> str:
        state_str = ""
        state_str = state_str + "constraints:\n"
        for cons in self.all_constraint:
            state_str = state_str + cons.con_str + "\n"
        for ident_str, info in self.ident_table.items():
            state_str = state_str + ident_str + ":\n"
            for dataflow_str in info.dataflow_strs:
                state_str = state_str + dataflow_str + "\n"
        return state_str


def collect_state(path, cfg, c_lan):
    state = State()
    path_node_ids = []

    for basic_block in path:
        for node_id in basic_block.get_cfg_nodes_ids():
            path_node_ids.append(node_id)

    for i, node_id in enumerate(path_node_ids):
        node_info = cfg.get_node_info(node_id)
        ts_node = None
        if len(node_info["ast_nodes"]) > 0:
            ts_node = node_info["ast_nodes"][0]

        is_cond = node_info["is_cond"]
        text = node_info["text"]

        if not is_cond and ts_node is not None:
            # print(f'ts_node text:\n{text}')
            ident_names = get_ident_names(ts_node, c_lan)
            # print(ident_names)

            for ident_name in ident_names:
                state.add_ident(ident_name, ts_node, text)

        if is_cond:
            if ":" not in text and ts_node is not None:
                ident_names = get_ident_names(ts_node, c_lan)
                for ident_name in ident_names:
                    state.add_ident(ident_name, ts_node, text)

            if i < len(path_node_ids) - 1 and ts_node is not None:
                next_node_id = path_node_ids[i + 1]
                # print(f'node_id:{node_id}')
                # print(f'next_node_id:{next_node_id}')
                # print(f'cfg.get_node_info(node_id):{cfg.get_node_info(node_id)}')
                # print(f'cfg.get_node_info(next_node_id):{cfg.get_node_info(next_node_id)}')
                edge_info = cfg.get_edge_info(node_id, next_node_id)
                if edge_info is not None and edge_info["condition"] == "False":
                    state.add_constraint(ts_node, text, False)
                else:
                    state.add_constraint(ts_node, text, True)

    return state


def get_block_map(
    pre_basic_blocks,
    cur_basic_blocks,
    pre_changed_basic_blocks,
    cur_changed_basic_blocks,
    line_pre2cur,
    line_cur2pre,
    pre_cfg,
    cur_cfg,
):
    block_pre2cur = {}
    block_cur2pre = {}

    for pre_basic_block in pre_basic_blocks:
        for cur_basic_block in cur_basic_blocks:
            if (pre_basic_block.get_isbeg() and cur_basic_block.get_isbeg()) or (
                pre_basic_block.get_isend() and cur_basic_block.get_isend()
            ):
                block_pre2cur[pre_basic_block] = cur_basic_block
                block_cur2pre[cur_basic_block] = pre_basic_block

    for pre_basic_block in pre_basic_blocks:
        if (pre_basic_block in pre_changed_basic_blocks) or (
            pre_basic_block in block_pre2cur
        ):
            continue
        beg_line = pre_basic_block.get_beg_line()
        end_line = pre_basic_block.get_end_line()
        if beg_line != -1 and end_line != -1:
            corr_beg_line = line_pre2cur[beg_line]
            corr_end_line = line_pre2cur[end_line]
            corr_cur_blocks1 = get_basic_blocks_by_line(cur_basic_blocks, corr_beg_line)
            corr_cur_blocks2 = get_basic_blocks_by_line(cur_basic_blocks, corr_end_line)

            candidates = []
            for corr_cur_block1 in corr_cur_blocks1:
                for corr_cur_block2 in corr_cur_blocks2:
                    if corr_cur_block1 == corr_cur_block2:
                        candidates.append(corr_cur_block1)

            for cand in candidates:
                if pre_cfg.get_basic_block_str(
                    pre_basic_block
                ) == cur_cfg.get_basic_block_str(cand):
                    block_pre2cur[pre_basic_block] = cand
                    block_cur2pre[cand] = pre_basic_block

    for cur_basic_block in cur_basic_blocks:
        if (cur_basic_block in cur_changed_basic_blocks) or (
            cur_basic_block in block_cur2pre
        ):
            continue
        beg_line = cur_basic_block.get_beg_line()
        end_line = cur_basic_block.get_end_line()
        if beg_line != -1 and end_line != -1:

            corr_beg_line = line_cur2pre[beg_line]
            corr_end_line = line_cur2pre[end_line]
            corr_cur_blocks1 = get_basic_blocks_by_line(pre_basic_blocks, corr_beg_line)
            corr_cur_blocks2 = get_basic_blocks_by_line(pre_basic_blocks, corr_end_line)

            candidates = []
            for corr_cur_block1 in corr_cur_blocks1:
                for corr_cur_block2 in corr_cur_blocks2:
                    if corr_cur_block1 == corr_cur_block2:
                        candidates.append(corr_cur_block1)

            for cand in candidates:
                if cur_cfg.get_basic_block_str(
                    cur_basic_block
                ) == pre_cfg.get_basic_block_str(cand):
                    block_pre2cur[cand] = cur_basic_block
                    block_cur2pre[cur_basic_block] = cand

    return block_pre2cur, block_cur2pre


def get_common_conds_num(state: State, cand_state: State):
    i = 0
    while i < len(state.all_constraint) and i < len(cand_state.all_constraint):
        if state.all_constraint[i].con_str == cand_state.all_constraint[i].con_str:
            i = i + 1
        else:
            break
    return i


def get_common_lines(path, cand_path, line_map):

    line_set1 = set()
    for block in path:
        for lineno in range(block.get_beg_line(), block.get_end_line() + 1):
            line_set1.add(lineno)

    line_set2 = set()
    for block in cand_path:
        for lineno in range(block.get_beg_line(), block.get_end_line() + 1):
            line_set2.add(lineno)

    cnt = 0
    for line1 in line_set1:
        if (line1 in line_map) and (line_map[line1] in line_set2):
            cnt = cnt + 1

    return cnt


def get_correspond_path(path, cfg1, cand_paths, cfg2, line_map, c_lan):
    state1 = collect_state(path, cfg1, c_lan)

    corr_path = None
    max_corr_cond_num = 0
    max_common_lines = 0
    max_cand_cond_num = 0
    min_block_cnt = 99999

    for i, cand_path in enumerate(cand_paths):
        state2 = collect_state(cand_path, cfg2, c_lan)

        # print(f'begin to deal with candidate {i}')
        # print(f'max_corr_cond_num:{max_corr_cond_num}')
        # print(f'max_common_lines:{max_common_lines}')
        # print(f'max_cand_cond_num:{max_cand_cond_num}')
        # print(f'min_block_cnt:{min_block_cnt}')
        #
        # print(f'get_common_conds_num(state1,state2):{get_common_conds_num(state1,state2)}')
        # print(f'get_common_lines(path,cand_path,line_map):{get_common_lines(path,cand_path,line_map)}')
        # print(f'len(state2.all_constraint):{len(state2.all_constraint)}')
        # print(f'len(cand_path):{len(cand_path)}')

        if get_common_conds_num(state1, state2) > max_corr_cond_num:
            max_corr_cond_num = get_common_conds_num(state1, state2)
            corr_path = cand_path
            max_common_lines = get_common_lines(path, cand_path, line_map)
            max_cand_cond_num = len(state2.all_constraint)
            min_block_cnt = len(cand_path)
        elif get_common_conds_num(state1, state2) == max_corr_cond_num:
            if len(state2.all_constraint) < max_cand_cond_num:
                corr_path = cand_path
                # print(f'update corr_path to candidate {i} in len(state2.all_constraint) < max_cand_cond_num')
                max_cand_cond_num = len(state2.all_constraint)
                min_block_cnt = len(cand_path)
                max_common_lines = get_common_lines(path, cand_path, line_map)
            elif get_common_lines(path, cand_path, line_map) > max_common_lines:
                max_common_lines = get_common_lines(path, cand_path, line_map)
                corr_path = cand_path
                # print(f'update corr_path to candidate {i} in get_common_lines(path,cand_path,line_map) > max_common_lines')
                min_block_cnt = len(cand_path)
            elif (
                get_common_lines(path, cand_path, line_map) == max_common_lines
                and len(cand_path) < min_block_cnt
            ):
                max_common_lines = get_common_lines(path, cand_path, line_map)
                corr_path = cand_path
                # print(f'update corr_path to candidate {i} in get_common_lines(path,cand_path,line_map) == max_common_lines and len(cand_path) < min_block_cnt')
                min_block_cnt = len(cand_path)

    return corr_path


class BuggyStmt:
    def __init__(self, is_cond):
        self.is_cond = is_cond
        self.lines = []

    def add_line(self, lineno):
        self.lines.append(lineno)


def get_add_cond_info(cons, i, line_cur2pre):
    buggy_stmt = BuggyStmt(True)

    pre_last_line = -1
    next_new_line = -1

    for j in range(cons[i].beg_line, -1, -1):
        if j in line_cur2pre:
            pre_last_line = line_cur2pre[j]
            break

    for j in range(cons[i].end_line, cons[i].end_line + 20):
        if j in line_cur2pre:
            next_new_line = line_cur2pre[j]
            break

    if pre_last_line != -1:
        buggy_stmt.add_line(pre_last_line)

    if next_new_line != -1:
        buggy_stmt.add_line(next_new_line)

    return buggy_stmt


def get_add_ident_info1(pre_ident_info, indexes):
    buggy_stmt = BuggyStmt(False)

    for index in indexes:
        if index >= 0 and index < len(pre_ident_info.dataflow_strs):
            # print(pre_ident_info.dataflow_strs[index])
            for j in range(
                pre_ident_info.beg_dataflow_pos[index],
                pre_ident_info.end_dataflow_pos[index] + 1,
            ):

                buggy_stmt.add_line(j)

    return buggy_stmt


def get_add_ident_info(pre_ident_info, cur_ident_info):

    buggy_stmt = BuggyStmt(False)
    i = 0

    while i < len(pre_ident_info.dataflow_strs) and i < len(
        cur_ident_info.dataflow_strs
    ):
        if pre_ident_info.dataflow_strs[i] != cur_ident_info.dataflow_strs[i]:

            break
        i = i + 1

    if not (i == len(cur_ident_info.dataflow_strs)):
        if i == len(pre_ident_info.dataflow_strs) and i < len(
            cur_ident_info.dataflow_strs
        ):
            buggy_stmt = get_add_ident_info1(pre_ident_info, [i - 1, i - 2])
        elif i < len(pre_ident_info.dataflow_strs) and i < len(
            cur_ident_info.dataflow_strs
        ):
            buggy_stmt = get_add_ident_info1(pre_ident_info, [i - 1, i])
    return buggy_stmt


def my_compare(i1, i2):
    if i1["datetime"] < i2["datetime"]:
        return -1
    elif i1["datetime"] > i2["datetime"]:
        return 1
    else:
        return 0


def remove_whitespace(line_str):
    return "".join(line_str.strip().split())


def compute_line_ratio(line_str1, line_str2):
    l1 = remove_whitespace(line_str1)
    l2 = remove_whitespace(line_str2)
    return Levenshtein.ratio(l1, l2)

def get_most_early_commt(vccs, git_repo):
    counter = Counter(vccs)
    max_count = max(counter.values())  # 

    # 
    # most_frequent_vcc = [key for key, count in counter.items() if count == max_count]
    
    most_frequent_vcc = []
    if len(most_frequent_vcc) == 1:
        vcc = most_frequent_vcc[0]
    
    else:
        sorted_szz = sorted(list(vccs), key=lambda k: git_repo.commit(k).committed_datetime)
        vcc = sorted_szz[0]  #commit
    return vcc


def match_buggy_stmts(repo_path, cid, buggy_stmt_dict, parser, c_lan):
    patch_file_name = buggy_stmt_dict["patch_file_name"]
    func_name = buggy_stmt_dict["func_name"]
    source_file_content = get_file_content(repo_path, cid, patch_file_name)
    if len(source_file_content) == 0:
        return False

    root_node = parser.parse(bytes(source_file_content, "utf8")).root_node
    funcs = get_func_defs(root_node, c_lan)

    corr_func_node = None
    for func_node in funcs:
        if get_func_name(func_node, c_lan) == func_name:
            corr_func_node = func_node
            break

    if corr_func_node is None:
        return False

    corr_func_lines = corr_func_node.text.decode("utf8").split("\n")
    find_cnt = 0

    for line_str in buggy_stmt_dict["line_strs"]:
        for corr_func_line in corr_func_lines:
            ratio = compute_line_ratio(line_str, corr_func_line)
            if ratio >= 0.60:
                find_cnt = find_cnt + 1
                break

    if find_cnt >= len(buggy_stmt_dict["line_strs"]):
        return True

    return False

def match_buggy_stmts_llm(repo_path, cid, buggy_stmt_dict, parser, c_lan):
    patch_file_name = buggy_stmt_dict["patch_file_name"]
    func_name = buggy_stmt_dict["func_name"]
    source_file_content = get_file_content(repo_path, cid, patch_file_name)
    if len(source_file_content) == 0:
        
        return False
    
    source_file_content_list = source_file_content.split("\n")
    
    find_cnt = 0

    for line_str in buggy_stmt_dict["line_strs"]:
        for corr_func_line in source_file_content_list:
            ratio = compute_line_ratio(line_str, corr_func_line)
            if ratio >= 0.60:
                find_cnt = find_cnt + 1
                break
    
    if find_cnt >= len(buggy_stmt_dict["line_strs"]):
        return True
    
    return False

def filter_path(path):
    i = 0
    while i < len(path) and path[i].is_blank_block():
        i = i + 1
    return path[i:]


class CidFinder:
    def __init__(self):
        self.file_cid_map = {}

    def get_introducing_cid(self, repo_path, cid, patch_file_name, lineno):
        if patch_file_name in self.file_cid_map:
            cid_map = self.file_cid_map[patch_file_name]
            return cid_map[lineno]

        git_repo = git.Repo(repo_path)
        blame_gen = git_repo.blame_incremental(rev=f"{cid}^1", file=patch_file_name)
        cid_map = {}
        for entry in blame_gen:
            for l in entry.linenos:
                cid_map[l] = entry.commit.hexsha
        self.file_cid_map[patch_file_name] = cid_map
        return cid_map[lineno]
