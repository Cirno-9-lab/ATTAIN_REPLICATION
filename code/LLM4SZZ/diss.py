# %%
from tree_sitter import Language, Parser
import tree_sitter as ts
from CFG import *
from util import *
import copy
import git
import functools
import Levenshtein
import json
import traceback
import subprocess
import shutil


# %%
def parse_pdg(pdg_content: str, func_name):
    lines = pdg_content.split("\n")
    depend_map1 = {}
    depend_map2 = {}
    id_to_line = {}
    line_to_id = {}
    if (len(lines) == 0) or ("digraph" not in lines[0]) or (func_name not in lines[0]):
        return depend_map1, depend_map2

    for line in lines:
        if "label" in line and "<SUB>" in line and "</SUB>" in line:
            id = line.split(" ")[0][1:-1]
            sub_pos1 = line.find("<SUB>")
            sub_pos2 = line.find("</SUB>")
            sub_pos1 = sub_pos1 + 5
            line_number = int(line[sub_pos1:sub_pos2])

            id_to_line[id] = line_number
            line_to_id[line_number] = id

        if "label" in line and ("DDG" in line or "CDG" in line) and "->" in line:
            id1 = line.split(" ")[2][1:-1]
            id2 = line.split(" ")[4][1:-1]

            if (id1 not in id_to_line) or (id2 not in id_to_line):
                continue
            line1 = id_to_line[id1]
            line2 = id_to_line[id2]

            if line1 not in depend_map1:
                depend_map1[line1] = []
            depend_map1[line1].append(line2)
            if line2 not in depend_map2:
                depend_map2[line2] = []
            depend_map2[line2].append(line1)
    return depend_map1, depend_map2


# enter your JAVA_HOME
os.environ["JAVA_HOME"] = ""
# enter your JAVA_BIN
os.environ["PATH"] = os.environ["PATH"] + ""


# enter your project dir and the dir to save pdg
PROJECT_DIR = ""
PDG_DIR = ""

# enter your path to joern parse and joern export
JOERN_PARSE_PATH = "/data1/lingxiaotang/learn-tree-sitter/joern/joern-parse"
JOERN_EXPORT_PATH = "/data1/lingxiaotang/learn-tree-sitter/joern/joern-export"

# enter your current working directory
CWD = ""

# %%
os.makedirs(PROJECT_DIR, exist_ok=True)
os.makedirs(PDG_DIR, exist_ok=True)

# %%
dataset = []
with open("dataset/dataset_fa.json") as f:
    dataset = json.load(f)

except_infos = []

all_infos = []

for info in dataset:
    os.chdir(CWD)
    C_LANGUAGE = Language("build/my-languages.so", "c")
    c_parser = Parser()
    c_parser.set_language(C_LANGUAGE)
    repo_path = os.path.join(REPOS_DIR, "linux")
    git_repo = git.Repo(repo_path)
    cid = info["fix_commit_hash"]
    print(f"begin to deal with {cid}")
    patch_content = get_patch_content(repo_path, cid)
    patch = Patch(patch_content)
    cid_finder = CidFinder()
    find_cids = set()
    save_info = {}
    save_info["info"] = info
    save_info["find_cids"] = []
    save_info["buggy_lines"] = []
    try:
        buggy_lines = []
        for patch_file in patch.get_files():
            patch_file_name = patch_file.file_name
            print(f"begin to deal with {patch_file_name}")
            if ".c" not in patch_file_name:
                continue
            pre_file_content = get_file_content(repo_path, f"{cid}^1", patch_file_name)
            cur_file_content = get_file_content(repo_path, f"{cid}", patch_file_name)
            with open(os.path.join(PROJECT_DIR, "test.c"), "w") as f:
                f.write(cur_file_content)

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

            _ = subprocess.run(
                [f"{JOERN_PARSE_PATH}", f"{PROJECT_DIR}"],
                capture_output=True,
                text=True,
                env=os.environ,
            )
            _ = subprocess.run(
                [f"{JOERN_EXPORT_PATH}", "--repr", "pdg", "--out", f"{PDG_DIR}"],
                capture_output=True,
                text=True,
                env=os.environ,
            )

            for cur_changed_func in cur_changed_funcs:
                func_name = get_func_name(cur_changed_func, C_LANGUAGE)
                for pdg_file in os.listdir(PDG_DIR):
                    file_content = ""
                    with open(os.path.join(PDG_DIR, pdg_file)) as f:
                        file_content = f.read()
                    line_pdg1, line_pdg2 = parse_pdg(file_content, func_name)

                    for added_line in added_lines:
                        if added_line in line_pdg1:
                            buggy_lines.extend(line_pdg1[added_line])
                            for l in line_pdg1[added_line]:
                                find_cids.add(
                                    cid_finder.get_introducing_cid(
                                        repo_path, cid, patch_file_name, l
                                    )
                                )
                            buggy_lines.extend(line_pdg2[added_line])
                            for l in line_pdg2[added_line]:
                                find_cids.add(
                                    cid_finder.get_introducing_cid(
                                        repo_path, cid, patch_file_name, l
                                    )
                                )

        save_info["find_cids"] = get_r_commits("linux", list(find_cids))
        save_info["buggy_lines"] = buggy_lines
    except:
        except_infos.append(info)
        traceback.print_exc()

    finally:
        shutil.rmtree(PDG_DIR)
        all_infos.append(save_info)
        with open(os.path.join(CWD, "bugins_info.json"), "w") as f:
            json.dump(all_infos, f)


all_info = []
with open("./bugins_info.json") as f:
    all_info = json.load(f)

find_cnt = 0
find_true_cnt = 0
true_cnt = 0

not_find_info = []

for info in all_info:
    find_cids = []
    find_cids = info["find_cids"]
    find_cnt = find_cnt + len(find_cids)
    bug_induce_cids = info["info"]["bug_commit_hash"]
    flag = False
    for cid in find_cids:
        for cid1 in bug_induce_cids:
            if cid == cid1:
                find_true_cnt = find_true_cnt + 1
                flag = True

    if flag == False and len(find_cids) != 0:
        not_find_info.append(info)

    true_cnt = true_cnt + len(bug_induce_cids)

print(find_cnt)
print(find_true_cnt)
print(true_cnt)
