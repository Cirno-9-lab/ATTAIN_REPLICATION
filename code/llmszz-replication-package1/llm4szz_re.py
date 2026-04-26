from constants import *
from llm import *
from parse_patch import *
from prompts import *
from util import *


all_info = []
with open(os.path.join(DATASET_DIR, "final_all_dataset.json")) as f:
    all_info = json.load(f)

print(f"len(all_info):{len(all_info)}")

dealed_infos = []

deal_cids = []
errs_info = []

pipeline = None

for cnt in range(0, 3):
    for info in all_info:
        
        client = Client()
        patch_file_name = ""
        del_lines = []
        msgs = []
        log_msgs = []

        repo_name = info["repo_name"]
        repo_path = os.path.join(REPOS_DIR, repo_name)
        cid = info["bug_fixing_commit"]

        if not os.path.exists(repo_path):
            continue

        try:
            print(f"begin to deal with {repo_path}:{cid}")

            git_repo = git.Repo(repo_path)
            patch_content = get_patch_content(repo_path, cid)
            if len(patch_content) == 0:
                continue
            patch = Patch(patch_content)
            print(patch.cmsg)

            repeat_cnt = 1
            if len(patch.get_files()) > 1:
                repeat_cnt = 3

            patch_file_names, root_cause = get_root_cause_file_names(
                patch, patch_content, [], log_msgs, repeat_cnt, pipeline, client
            )
            print(patch_file_names)
            print(root_cause)

            patch_file_names = list(patch_file_names)
            log_msgs.append({"llm_patch_file_names": patch_file_names})

            llm_file_cand_cids = []
            file_cand_cids = []

            for patch_file in patch.get_files():
                patch_file_info = {}

                context_length = 0
                if patch_file.file_name in patch_file_names:
                    patch_file_name = patch_file.file_name
                    print(f"begin to deal with {patch_file_name}")
                    log_msgs.append(
                        f"begin to deal with {patch_file_name} in strategy1"
                    )
                    lan_str = ""
                    if ".java" in patch_file_name:
                        lan_str = "java"
                    if ".c" in patch_file_name:
                        lan_str = "c"

                    pre_file_content = get_file_content(
                        repo_path, f"{cid}^1", patch_file_name
                    )
                    pre_root_node = get_root_node(pre_file_content, lan_str)
                    cur_file_content = get_file_content(
                        repo_path, f"{cid}", patch_file_name
                    )
                    cur_root_node = get_root_node(cur_file_content, lan_str)
                    pre_methods_and_constructs = get_ts_func_nodes(
                        pre_root_node, lan_str
                    )
                    cur_methods_and_constructs = get_ts_func_nodes(
                        cur_root_node, lan_str
                    )
                    del_lines = []
                    add_lines = []
                    patch_lines = []
                    for patch_hunk in patch_file.get_hunks():
                        for patch_line in patch_hunk.get_lines():
                            if patch_line.is_add:
                                add_lines.append(patch_line.new_lineno)
                            if patch_line.is_del:
                                del_lines.append(patch_line.lineno)
                            patch_lines.append(patch_line)
                    pre_changed_funcs = set()
                    cur_changed_funcs = set()
                    for del_line in del_lines:
                        node = get_node_by_lineno(del_line, pre_methods_and_constructs)
                        if node is not None:
                            pre_changed_funcs.add(node)
                    for add_line in add_lines:
                        node = get_node_by_lineno(add_line, cur_methods_and_constructs)
                        if node is not None:
                            cur_changed_funcs.add(node)

                    pre_retrieve_lines = []
                    cur_retrieve_lines = []
                    pre_line2node = {}
                    pre_node2line = {}
                    cur_line2node = {}
                    cur_node2line = {}

                    for del_line in del_lines:
                        node = get_node_by_lineno(del_line, pre_methods_and_constructs)
                        if node is None:
                            pre_retrieve_lines.extend(
                                [
                                    del_line - 2,
                                    del_line - 1,
                                    del_line,
                                    del_line + 1,
                                    del_line + 2,
                                ]
                            )
                            continue

                        for lineno in range(node.start_point[0], node.end_point[0] + 3):
                            pre_retrieve_lines.append(lineno)
                            pre_line2node[lineno] = node
                            if node not in pre_node2line:
                                pre_node2line[node] = []
                            pre_node2line[node].append(lineno)

                    for add_line in add_lines:
                        node = get_node_by_lineno(add_line, cur_methods_and_constructs)
                        if node is None:
                            cur_retrieve_lines.extend(
                                [
                                    add_line - 2,
                                    add_line - 1,
                                    add_line,
                                    add_line + 1,
                                    add_line + 2,
                                ]
                            )
                            continue
                        for lineno in range(node.start_point[0], node.end_point[0] + 3):
                            cur_retrieve_lines.append(lineno)
                            cur_line2node[lineno] = node
                            if node not in cur_node2line:
                                cur_node2line[node] = []
                            cur_node2line[node].append(lineno)

                    # context expanding, get full context
                    full_patch = Patch(get_full_patch_content(repo_path, cid))
                    full_patch_file = None
                    full_file_patch_content = ""

                    full_context_lines = set()
                    for full_patch_file_ in full_patch.get_files():
                        if full_patch_file_.file_name != patch_file_name:
                            continue
                        full_patch_file = full_patch_file_
                        for full_patch_hunk in full_patch_file_.get_hunks():
                            for patch_line in full_patch_hunk.get_lines():
                                if (patch_line.lineno in pre_retrieve_lines) or (
                                    patch_line.new_lineno in cur_retrieve_lines
                                ):
                                    full_context_lines.add(patch_line.lineno)
                                    full_file_patch_content = (
                                        full_file_patch_content
                                        + patch_line.raw_line
                                        + "\n"
                                    )
                                    if patch_line.lineno != -1:
                                        node = get_node_by_lineno(
                                            patch_line.lineno,
                                            pre_methods_and_constructs,
                                        )
                                        if node is not None:
                                            if node not in pre_node2line:
                                                pre_node2line[node] = []
                                            if (
                                                patch_line.lineno
                                                not in pre_node2line[node]
                                            ):
                                                pre_node2line[node].append(
                                                    patch_line.lineno
                                                )
                                            pre_line2node[patch_line.lineno] = node

                                    if patch_line.new_lineno != -1:
                                        node = get_node_by_lineno(
                                            patch_line.new_lineno,
                                            cur_methods_and_constructs,
                                        )
                                        if node is not None:
                                            if node not in cur_node2line:
                                                cur_node2line[node] = []
                                            if (
                                                patch_line.new_lineno
                                                not in cur_node2line[node]
                                            ):
                                                cur_node2line[node].append(
                                                    patch_line.new_lineno
                                                )
                                            cur_line2node[patch_line.new_lineno] = node

                    full_file_patch_content = full_file_patch_content[:15000]
                    print(f"full_file_patch_content:\n{full_file_patch_content}")
                    log_msgs.append(
                        {
                            "full_context_length": len(
                                full_file_patch_content.split("\n")
                            )
                        }
                    )

                    code_stmts_msg = []
                    code_stmts_msg.extend(
                        [
                            {
                                "role": "system",
                                "content": "You are a programming expert.",
                            },
                            {
                                "role": "user",
                                "content": get_code_stmts_summary_text(
                                    patch.cmsg, root_cause, full_file_patch_content
                                ),
                            },
                        ]
                    )
                    reply = client.call_llm(code_stmts_msg, [], pipeline)
                    print(f"reply:\n{reply}")
                    log_msgs.extend(code_stmts_msg)
                    log_msgs.append({"role": "assistant", "content": reply})

                    buggy_stmts = get_buggy_stmts1(reply)
                    print(f"buggy_stmts:{buggy_stmts}")
                    line_info_map = build_line_info_map(full_patch_file)

                    s1_raw_stmts_infos = []
                    s1_llm_file_cand_cids = []

                    to_rank_stmt_str = ""

                    for buggy_stmt in buggy_stmts:
                        line_infos = get_line_infos(buggy_stmt, line_info_map)
                        if len(line_infos) == 0:
                            continue
                        to_rank_stmt_str = to_rank_stmt_str + buggy_stmt + "\n"

                        for line_info in line_infos:
                            # line_info = line_infos[0]
                            # print(f"line_info.lineno:{line_info.lineno}")

                            # induce_cid = get_introducing_cid(repo_path,f'{cid}^1',patch_file_name,line_info.lineno)
                            induce_cid = get_introducing_cid1(
                                git_repo,
                                f"{cid}^1",
                                patch_file_name,
                                line_info.lineno,
                                ignore_whitespaces=True,
                            )
                            s1_raw_stmts_infos.append(
                                {
                                    "buggy_stmt": buggy_stmt,
                                    "file_name": patch_file.file_name,
                                    "lineno": line_info.lineno,
                                    "induce_cid": induce_cid,
                                }
                            )
                            s1_llm_file_cand_cids.append(induce_cid)

                    s1_llm_file_final_cids = get_r_commits(
                        repo_name, list(s1_llm_file_cand_cids)
                    )

                    log_msgs.append({"s1_raw_stmts_infos": s1_raw_stmts_infos})
                    log_msgs.append({"s1_llm_file_final_cids": s1_llm_file_final_cids})

                    print(f"to_rank_stmt_str:{to_rank_stmt_str}")

                    rank_stmts_msg = []
                    rank_stmts_msg.extend(
                        [
                            {
                                "role": "system",
                                "content": "You are a programming expert.",
                            },
                            {
                                "role": "user",
                                "content": get_code_stmts_ranking_text(
                                    root_cause, to_rank_stmt_str
                                ),
                            },
                        ]
                    )
                    reply = client.call_llm(code_stmts_msg, [], pipeline)
                    log_msgs.extend(rank_stmts_msg)
                    log_msgs.append({"role": "assistant", "content": reply})

                    ranked_buggy_stmts = get_buggy_stmts1(reply)
                    print(f"ranked_buggy_stmts:{ranked_buggy_stmts}")

                    s1_ranked_stmts_infos = []
                    for ranked_buggy_stmt in ranked_buggy_stmts:
                        line_infos = get_line_infos(ranked_buggy_stmt, line_info_map)
                        if len(line_infos) == 0:
                            continue

                        for line_info in line_infos:
                            # line_info = line_infos[0]
                            # print(f"line_info.lineno:{line_info.lineno}")

                            # induce_cid = get_introducing_cid(repo_path,f'{cid}^1',patch_file_name,line_info.lineno)
                            induce_cid = get_introducing_cid1(
                                git_repo,
                                f"{cid}^1",
                                patch_file_name,
                                line_info.lineno,
                                ignore_whitespaces=True,
                            )
                            s1_ranked_stmts_infos.append(
                                {
                                    "buggy_stmt": buggy_stmt,  # deal later
                                    "file_name": patch_file.file_name,
                                    "lineno": line_info.lineno,
                                    "induce_cid": induce_cid,
                                }
                            )

                    log_msgs.append({"s1_ranked_stmts_infos": s1_ranked_stmts_infos})

        except:
            errs_info.append({"cid": cid, "except_info": traceback.format_exc()})
            with open(os.path.join(CWD, "err_infos.json"), "w") as f:
                json.dump(errs_info, f)
            log_msgs.append({"can_determine": False})
            traceback.print_exc()

        finally:
            save_logs(repo_name, cid, log_msgs, "llm4szz_re", cnt)
            dealed_infos.append(info)
            with open(os.path.join(CWD, "deal_infos.json"), "w") as f:
                json.dump(dealed_infos, f)
