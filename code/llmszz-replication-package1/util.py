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
import json
from prompts import *
from llm import *
import random
from openai import OpenAI
import transformers
import torch
import os
from openai import OpenAI
import os
from pydriller import ModificationType, GitRepository as PyDrillerGitRepo
from parse_patch import *

import time
import json
import git
import csv
from util import *
import traceback
import Levenshtein
import re
import copy
import random
from constants import *


def get_patch_content(repo_path, cid):
    cwd = os.getcwd()
    os.chdir(repo_path)
    cmd = f"git format-patch {cid} -1 --stdout"
    patch_content = subprocess.check_output(cmd, shell=True).decode(
        "utf-8", errors="ignore"
    )
    os.chdir(cwd)
    return patch_content


def get_file_content1(repo_path, cid, file_name):
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


def get_file_content(repo_path, cid, file_name):
    file_content = get_file_content1(repo_path, cid, file_name)
    if len(file_content) > 0:
        return file_content

    file_name_set = set()
    cwd = os.getcwd()
    try:
        os.chdir(repo_path)
        cmd = f"git log --follow --name-only  --pretty='' -- {file_name}"
        file_names_str = subprocess.check_output(cmd, shell=True).decode(
            "utf-8", errors="ignore"
        )
        for line in file_names_str.split("\n"):
            if len(line.strip()) > 0:
                file_name_set.add(line.strip())
    except Exception as e:
        os.chdir(cwd)
        return ""

    os.chdir(cwd)
    for file_name1 in file_name_set:
        if file_name1 != file_name:
            file_content = get_file_content1(repo_path, cid, file_name1)
            if len(file_content) > 0:
                return file_content
    return ""


def get_methods_and_constructs(root_node, java_lan):
    method_def_query = java_lan.query(
        """(
        (method_declaration)  @method_def
    )"""
    )

    constructor_decl_query = java_lan.query(
        """
        (constructor_declaration) @construct_def                        
    """
    )

    nodes = []

    method_def_results = method_def_query.captures(root_node)
    nodes.extend([result[0] for result in method_def_results])

    construct_del_results = constructor_decl_query.captures(root_node)
    nodes.extend([result[0] for result in construct_del_results])

    ret_nodes = []
    for node in nodes:
        if node.child_by_field_name("body") is not None:
            ret_nodes.append(node)
    return ret_nodes


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


def get_root_node(file_content, lan_str):
    if lan_str == "java":
        java_lan = Language(os.path.join(TREE_SITTER_DIR, "my-languages.so"), "java")
        java_parser = Parser()
        java_parser.set_language(java_lan)
        return java_parser.parse(bytes(file_content, "utf8")).root_node
    if lan_str == "c":
        c_lan = Language(os.path.join(TREE_SITTER_DIR, "my-languages.so"), "c")
        c_parser = Parser()
        c_parser.set_language(c_lan)
        return c_parser.parse(bytes(file_content, "utf8")).root_node


def get_ts_func_nodes(root_node, lan_str):
    if lan_str == "java":
        java_lan = Language(os.path.join(TREE_SITTER_DIR, "my-languages.so"), "java")
        return get_methods_and_constructs(root_node, java_lan)
    if lan_str == "c":
        c_lan = Language(os.path.join(TREE_SITTER_DIR, "my-languages.so"), "c")
        return get_func_defs(root_node, c_lan)


def get_node_by_lineno(lineno, nodes):
    if nodes is None:
        return None
    for node in nodes:
        beg_lineno = node.start_point[0]
        end_lineno = node.end_point[0]
        if lineno >= beg_lineno and lineno <= end_lineno:
            return node
    return None


def method_constructor_eq(
    pre_func_node: tree_sitter.Node, cur_func_node: tree_sitter.Node, line_map
):

    func_node1_start_line = pre_func_node.start_point[0] + 1
    func_node2_start_line = cur_func_node.start_point[0] + 1

    func_node1_end_line = pre_func_node.end_point[0] + 1
    func_node2_end_line = cur_func_node.end_point[0] + 1

    for pre_line in range(func_node1_start_line, func_node1_end_line + 1):
        if pre_line in line_map:
            cur_line = line_map[pre_line]
            if cur_line >= func_node2_start_line and cur_line <= func_node2_end_line:
                return True

    return False


def compare_strings_with_git_diff(string1, string2):
    ret = ""
    with tempfile.NamedTemporaryFile(
        delete=False
    ) as tmpfile1, tempfile.NamedTemporaryFile(delete=False) as tmpfile2:

        tmpfile1.write(string1.encode())
        tmpfile2.write(string2.encode())

        tmpfile1_name = tmpfile1.name
        tmpfile2_name = tmpfile2.name

    try:
        result = subprocess.run(
            ["git", "diff", "--no-index", "-U99999", tmpfile1_name, tmpfile2_name],
            capture_output=True,
            text=True,
        )
        ret = result.stdout
    finally:
        try:
            os.remove(tmpfile1_name)
            os.remove(tmpfile2_name)
        except OSError:
            pass

    return ret


def filter_git_diff_result(diff_str: str):
    ret_lines = []

    origin_lines = diff_str.split("\n")
    flag = False
    for origin_line in origin_lines:
        if flag:
            ret_lines.append(origin_line)
        if origin_line.startswith("@@"):
            flag = True

    ret_str = ""
    for line in ret_lines:
        ret_str = ret_str + line + "\n"
    return ret_str


def get_context_maps(patch_file, repo_path, cid, java_parser, java_lan):
    patch_file_name = patch_file.file_name

    pre_file_content = get_file_content(repo_path, f"{cid}^1", patch_file_name)
    pre_root_node = java_parser.parse(bytes(pre_file_content, "utf8")).root_node
    pre_nodes = get_methods_and_constructs(pre_root_node, java_lan)

    cur_file_content = get_file_content(repo_path, f"{cid}", patch_file_name)
    cur_root_node = java_parser.parse(bytes(cur_file_content, "utf8")).root_node
    cur_nodes = get_methods_and_constructs(cur_root_node, java_lan)

    pre_hunk_map = {}
    cur_hunk_map = {}
    pre_context_map = {}
    cur_context_map = {}

    for hunk in patch_file.get_hunks():
        for patch_line in hunk.get_lines():
            context_map = {}
            hunk_map = {}
            if not (patch_line.is_add or patch_line.is_del):
                continue

            lineno = patch_line.lineno
            func_node = None

            if patch_line.is_del:
                # print(patch_line)
                func_node = get_node_by_lineno(lineno, pre_nodes)
                context_map = pre_context_map
                hunk_map = pre_hunk_map
                # print(func_node)

            if patch_line.is_add:
                # print(patch_line)
                func_node = get_node_by_lineno(lineno, cur_nodes)
                context_map = cur_context_map
                hunk_map = cur_hunk_map
                # print(func_node)

            if func_node is not None:
                if func_node not in context_map:
                    context_map[func_node] = []
                # print('begin to add func node into context map')
                # print(f'func_node type:{type(func_node)}')
                context_map[func_node].append(patch_line)
            else:
                if hunk not in hunk_map:
                    hunk_map[hunk] = []
                # print('begin to add hunk into context map')
                hunk_map[hunk].append(patch_line)

    return pre_hunk_map, cur_hunk_map, pre_context_map, cur_context_map


def get_diff_index(diff_ranges, lineno):
    i = 0
    for i in range(len(diff_ranges)):
        diff_range = diff_ranges[i]
        if lineno >= diff_range[0] and lineno < diff_range[0] + diff_range[1]:
            return i
    return -1


def get_line_map(pre_cid, cur_cid, repo_path, patch_file_name, file_length):

    pre_file_content = get_file_content(repo_path, pre_cid, patch_file_name)
    cur_file_content = get_file_content(repo_path, cur_cid, patch_file_name)

    with open(os.path.join(TMP_DIR, "pre_file_content"), "w") as f:
        f.write(pre_file_content)

    with open(os.path.join(TMP_DIR, "cur_file_content"), "w") as f:
        f.write(cur_file_content)

    cmd = f"git diff --no-index  -- {os.path.join(TMP_DIR,'pre_file_content')} {os.path.join(TMP_DIR,'cur_file_content')}"
    diff_str = os.popen(cmd).read()

    # diff_str = git_repo.git.diff(pre_cid,cur_cid, '--find-renames',"--", patch_file_name)

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
        # print(lineno)
        diff_index = get_diff_index(diff_ranges, lineno)
        if diff_index == -1:
            line_map[lineno] = lineno + offset
            lineno = lineno + 1
        else:
            diff_lines = diffs[diff_index]
            for diff_line in diff_lines[1:]:
                # print(diff_line)
                # print(lineno)
                if diff_line.startswith("+"):
                    offset = offset + 1
                elif diff_line.startswith("-"):
                    offset = offset - 1
                    lineno = lineno + 1
                else:
                    # print(lineno)
                    line_map[lineno] = lineno + offset
                    lineno = lineno + 1
        if lineno >= file_length:
            break
    return line_map


def get_names_info(reply: str):
    lines = reply.split("\n")
    root_cause = ""
    file_name = ""
    for line in lines:
        if line.startswith("file:"):
            file_name = line.split(":")[-1]
        if line.startswith("Root cause"):
            root_cause = line.split(":")[-1]
    return file_name.strip(), root_cause.strip()


def sort_cid_by_date(cand_cids, git_repo):
    for i in range(len(cand_cids)):
        max_index = i
        max_commit_date = git_repo.commit(cand_cids[i]).committed_datetime
        for j in range(i + 1, len(cand_cids)):
            cur_commit_date = git_repo.commit(cand_cids[j]).committed_datetime
            if cur_commit_date > max_commit_date:
                max_index = j
                max_commit_date = cur_commit_date
        cand_cids[i], cand_cids[max_index] = cand_cids[max_index], cand_cids[i]


def get_reply_result(reply):
    for line in reply.split("\n"):
        line = line.lower()
        if line.startswith("result:") and "yes" in line:
            return True
    return False


def get_r_commits(repo_name, cand_cids):
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


def save_logs(repo_name, cid, log_msgs, file_name, cnt):
    save_path_dir = os.path.join(SAVE_LOG_DIR, repo_name, cid)
    os.makedirs(save_path_dir, exist_ok=True)
    save_path = os.path.join(
        SAVE_LOG_DIR,
        repo_name,
        cid,
        f"{file_name}{cnt}.json",
    )
    with open(save_path, "w") as f:
        json.dump(log_msgs, f)


def get_full_patch_content(repo_path, cid):
    cwd = os.getcwd()
    patch_content = ""
    try:
        os.chdir(repo_path)
        cmd = f"git format-patch {cid} -1 -U100000 --stdout "
        patch_content = subprocess.check_output(cmd, shell=True).decode(
            "utf-8", errors="ignore"
        )
    except:
        pass
    finally:
        os.chdir(cwd)
        return patch_content


def build_line_info_map(patch_file):
    line_info_map = {}
    for patch_hunk in patch_file.get_hunks():
        for patch_line in patch_hunk.get_lines():
            line_str = patch_line.line.strip()
            if len(line_str) == 0:
                continue
            if patch_line.is_del or patch_line.is_bg:
                if line_str.strip() not in line_info_map:
                    line_info_map[line_str.strip()] = []
                    line_info_map[line_str.strip()].append(patch_line)
                else:
                    line_info_map[line_str.strip()].append(patch_line)
    return line_info_map


def contains_letter(s):
    return bool(re.search(r"[a-zA-Z]", s))


def get_line_infos(line_str, line_info_map):
    line_infos = []
    if line_str.startswith("//") or line_str.startswith("/*"):
        return line_infos
    if not contains_letter(line_str):
        return line_infos
    line_str = line_str.strip()
    if line_str.startswith("-"):
        line_str = line_str[1:]
    if line_str in line_info_map:
        for info in line_info_map[line_str]:
            if info.is_del:
                line_infos.clear()
                line_infos.append(info)
        if len(line_infos) == 0:
            line_infos.extend(line_info_map[line_str])
    if len(line_infos) > 0:
        return line_infos

    for key in line_info_map.keys():
        if len(key) < 5:
            continue
        if line_str in key or key in line_str:
            for info in line_info_map[key]:
                if info.is_del:
                    line_infos.clear()
                    line_infos.append(info)
            if len(line_infos) == 0:
                line_infos.extend(line_info_map[key])
    if len(line_infos) != 0:
        return line_infos

    max_ratio = 0
    for key in line_info_map.keys():
        cur_ratio = compute_line_ratio(line_str, key)
        if cur_ratio > max_ratio:
            max_ratio = cur_ratio
            line_infos.clear()
            line_infos.extend(line_info_map[key])
        elif cur_ratio == max_ratio:
            line_infos.extend(line_info_map[key])
    if max_ratio < 0.75:
        line_infos.clear()
    return line_infos


def remove_whitespace(line_str):
    return "".join(line_str.strip().split())


def compute_line_ratio(line_str1, line_str2):
    l1 = remove_whitespace(line_str1)
    l2 = remove_whitespace(line_str2)
    return Levenshtein.ratio(l1, l2)


def get_buggy_stmts(reply):
    lines = reply.split("\n")
    buggy_stmts = []
    lines = lines[1:]
    for line in lines:
        if "Reason:" in line:
            break
        if len(line.strip()) > 0:
            buggy_stmts.append(line.strip())

    return buggy_stmts


def get_fixed_stmts(reply):
    lines = reply.split("\n")
    fixed_stmts = []
    flag = False
    for line in lines:
        if line.startswith("The code statements that fix the bug are:"):
            flag = True
            continue

        if not flag:
            continue

        if "Reason:" in line:
            break

        if len(line.strip()) > 0:
            fixed_stmts.append(line.strip())

    return fixed_stmts


def get_buggy_stmts1(reply):
    lines = reply.split("\n")
    buggy_stmts = []
    lines = lines[1:]
    for line in lines:
        if len(line.strip()) > 0:
            buggy_stmts.append(line.strip())
    return buggy_stmts


def shuffle_files(patch_content, patch):
    files1 = []
    files2 = []
    for patch_file in patch.get_files():
        if patch_file.is_add:
            continue
        if "test" in patch_file.file_name.lower():
            files2.append(patch_file)
        else:
            files1.append(patch_file)

    shuffled_content = ""

    head = patch_content[: patch_content.find("---")]
    random.shuffle(files1)
    random.shuffle(files2)

    for patch_file in files1:
        shuffled_content = shuffled_content + patch_file.get_raw_file_str() + "\n"

    for patch_file in files2:
        shuffled_content = shuffled_content + patch_file.get_raw_file_str() + "\n"

    return head + "\n" + shuffled_content


def get_root_cause_file_names(
    patch, patch_content, test_msgs, log_msgs, repeat_cnt, pipeline, client
):
    file_names = set()
    root_cause = ""
    for _ in range(repeat_cnt):
        test_msgs = []
        shuffle_patch_content = shuffle_files(patch_content, patch)[:15000]
        # print('-----------------------')
        # print(shuffle_patch_content)
        # print('-----------------------')
        test_msgs.append({"role": "system", "content": summary_system_text})
        test_msgs.append({"role": "user", "content": shuffle_patch_content})
        log_msgs.append({"role": "system", "content": summary_system_text})
        log_msgs.append({"role": "user", "content": shuffle_patch_content})
        reply = client.call_llm(test_msgs, log_msgs, pipeline)
        # print(reply)
        test_msgs.append({"role": "assistant", "content": reply})
        log_msgs.append({"role": "assistant", "content": reply})

        test_msgs.append({"role": "user", "content": root_cause_summary_text})
        log_msgs.append({"role": "user", "content": root_cause_summary_text})
        reply = client.call_llm(test_msgs, log_msgs, pipeline)
        # print(reply)

        log_msgs.append({"role": "user", "content": root_cause_summary_text})

        file_name, root_cause = get_names_info(reply)
        for patch_file in patch.get_files():
            patch_file_name = patch_file.file_name
            simple_patch_file_name = patch_file_name.split("/")[-1]
            if file_name in patch_file_name or patch_file_name in file_name:
                file_names.add(patch_file_name)

        if len(patch.get_files()) == 1:
            break

    file_names1 = set()
    for file_name in file_names:
        if "test" not in file_name.lower():
            file_names1.add(file_name)

    if len(file_names1) > 0:
        return file_names1, root_cause
    return file_names, root_cause


def parse_line_ranges(modified_lines):
    """
    Convert impacted lines list to list of modified lines range. In case of single line,
    the range will be the same line as start and end - ['line_num, line_num', 'start, end', ...]

    :param str modified_lines: list of modified lines
    :returns List[str] impacted_lines_ranges
    """
    mod_line_ranges = list()

    if len(modified_lines) > 0:
        start = int(modified_lines[0])
        end = int(modified_lines[0])

        if len(modified_lines) == 1:
            return [f"{start},{end}"]

        for i in range(1, len(modified_lines)):
            line = int(modified_lines[i])
            if line - end == 1:
                end = line
            else:
                mod_line_ranges.append(f"{start},{end}")
                start = line
                end = line

            if i == len(modified_lines) - 1:
                mod_line_ranges.append(f"{start},{end}")

    return mod_line_ranges


def get_introducing_cid1(
    repo,
    rev: str,
    file_path: str,
    modified_line,
    skip_comments: bool = False,
    ignore_revs_list=None,
    ignore_revs_file_path: str = None,
    ignore_whitespaces: bool = False,
    detect_move_within_file: bool = False,
    detect_move_from_other_files: "DetectLineMoved" = None,
):
    """
     Wrapper for Git blame command.
    :param str rev: commit revision
    :param str file_path: path of file to blame
    :param bool modified_lines: list of modified lines that will be converted in line ranges to be used with the param '-L' of git blame
    :param bool ignore_whitespaces: add param '-w' to git blame
    :param bool skip_comments: use a comment parser to identify and exclude line comments and block comments
    :param List[str] ignore_revs_list: specify a list of commits to ignore during blame
    :param bool detect_move_within_file: Detect moved or copied lines within a file
        (-M param of git blame, https://git-scm.com/docs/git-blame#Documentation/git-blame.txt--Mltnumgt)
    :param DetectLineMoved detect_move_from_other_files: Detect lines moved or copied from other files that were modified in the same commit
        (-C param of git blame, https://git-scm.com/docs/git-blame#Documentation/git-blame.txt--Cltnumgt)
    :param str ignore_revs_file_path: specify ignore revs file for git blame to ignore specific commits. The
        file must be in the same format as an fsck.skipList (https://git-scm.com/docs/git-blame)
    :returns Set[BlameData] a set of bug introducing commits candidates, represented by BlameData object
    """
    kwargs = dict()
    if ignore_whitespaces:
        kwargs["w"] = True
    if ignore_revs_file_path:
        kwargs["ignore-revs-file"] = ignore_revs_file_path
    if ignore_revs_list:
        kwargs["ignore-rev"] = list(ignore_revs_list)
    if detect_move_within_file:
        kwargs["M"] = True
    if (
        detect_move_from_other_files
        and detect_move_from_other_files == DetectLineMoved.SAME_COMMIT
    ):
        kwargs["C"] = True
    if (
        detect_move_from_other_files
        and detect_move_from_other_files == DetectLineMoved.PARENT_COMMIT
    ):
        kwargs["C"] = [True, True]
    if (
        detect_move_from_other_files
        and detect_move_from_other_files == DetectLineMoved.ANY_COMMIT
    ):
        kwargs["C"] = [True, True, True]
    bug_introd_commits = []
    mod_line_ranges = parse_line_ranges([modified_line])
    # log.info(f"processing file: {file_path}")

    for entry in repo.blame_incremental(
        **kwargs, rev=rev, L=mod_line_ranges, file=file_path
    ):
        # entry.linenos = input lines to blame (current lines)
        # entry.orig_lineno = output line numbers from blame (previous commit lines from blame)
        for line_num in entry.orig_linenos:
            # source_file_content = repo.git.show(f"{entry.commit.hexsha}:{entry.orig_path}")
            # line_str = source_file_content.split('\n')[line_num - 1].strip()
            # b_data = BlameData(entry.commit, line_num, line_str, entry.orig_path)
            # print(entry.commit)
            # print(line_num)
            # print(entry.orig_path)
            bug_introd_commits.append(entry.commit)

    return bug_introd_commits[0].hexsha


def get_partial_file(file_content, lineno1, lineno2):
    partial_file_content = ""
    file_lines = file_content.split("\n")
    for lineno in range(lineno1, lineno2 + 1):
        if lineno >= 0 and lineno < len(file_lines):
            partial_file_content = partial_file_content + file_lines[lineno] + "\n"

    return partial_file_content


def get_full_patch_lines(patch_file_name, full_patch):
    patch_lines = []
    for full_patch_file in full_patch.get_files():
        if full_patch_file.file_name != patch_file_name:
            continue
        for full_patch_hunk in full_patch_file.get_hunks():
            for patch_line in full_patch_hunk.get_lines():
                patch_lines.append(patch_line)

    return patch_lines


def get_context_range1(patch_lines):
    index1 = -1
    index2 = -1

    for i in range(0, len(patch_lines)):
        if patch_lines[i].is_add:
            index1 = i
            break

    for i in range(len(patch_lines) - 1, -1, -1):
        if patch_lines[i].is_add:
            index2 = i
            break

    index1 = index1 - 1
    index2 = index2 + 1

    pre_min_line = -1
    pre_max_line = -1

    if index1 >= 0:
        pre_min_line = patch_lines[index1].lineno

    if index2 < len(patch_lines):
        pre_max_line = patch_lines[index2].lineno

    return pre_min_line, pre_max_line


def is_buggy_stmts_in_code_snippet(
    buggy_stmts, code_snippet, log_msgs, pipeline, client
):

    for buggy_stmt in buggy_stmts:
        if len(buggy_stmt.strip()) == 0:
            continue

        msgs = []
        msgs.append({"role": "system", "content": "You are a programming expert."})
        msgs.append(
            {
                "role": "user",
                "content": get_stmt_determine_text(buggy_stmt, code_snippet),
            }
        )

        log_msgs.extend(msgs)
        # print(f'len(msgs):{len(msgs)}')
        reply = client.call_llm(msgs, [], pipeline)
        log_msgs.append({"role": "assistant", "content": reply})
        for line in reply.split("\n"):
            line = line.lower()
            if line.startswith("result") and "no" in line:
                return False
    return True


def most_common_item(lst):
    if len(lst) == 0:
        return []

    count_dict = {}

    for item in lst:
        if item in count_dict:
            count_dict[item] += 1
        else:
            count_dict[item] = 1

    max_items = []
    max_count = 0

    for item, count in count_dict.items():
        if count > max_count:
            max_count = count
            max_items.clear()
            max_items.append(item)
        elif count == max_count:
            max_items.append(item)

    return max_items
