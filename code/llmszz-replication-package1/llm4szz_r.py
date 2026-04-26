from constants import *
from llm import *
from parse_patch import *
from prompts import *
from util import *


all_info = []
with open(os.path.join(DATASET_DIR, "final_all_dataset.json")) as f:
    all_info = json.load(f)

print(f"len(all_info):{len(all_info)}")
deal_cids = []
errs_info = []
dealed_infos = []
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


        start_time = time.time()
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
                if patch_file.file_name in patch_file_names:
                    patch_file_name = patch_file.file_name
                    log_msgs.append(
                        f"begin to deal with {patch_file_name} in strategy1"
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
                                    patch.cmsg,
                                    root_cause,
                                    patch_file.get_raw_file_str(),
                                ),
                            },
                        ]
                    )
                    reply = client.call_llm(code_stmts_msg, [], pipeline)
                    log_msgs.extend(code_stmts_msg)
                    log_msgs.append({"role": "assistant", "content": reply})

                    buggy_stmts = get_buggy_stmts1(reply)
                    print(f"buggy_stmts:{buggy_stmts}")
                    line_info_map = build_line_info_map(patch_file)

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

            for patch_file in patch.get_files():
                patch_file_info = {}

                context_length = 0
                if patch_file.file_name in patch_file_names:
                    patch_file_name = patch_file.file_name
                    print(f"begin to deal with {patch_file_name}")
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

                    log_msgs.append(
                        {
                            "full_context_length": len(
                                full_file_patch_content.split("\n")
                            )
                        }
                    )

                    criterion_msgs = []
                    buggy_stmts = []
                    fixed_stmts = []
                    # file_segs = get_full_patch_segments(full_file_patch_content,50)

                    criterion = ""
                    criterion_msgs.append(
                        {"role": "system", "content": f"You are a programming expert."}
                    )
                    log_msgs.append(
                        {"role": "system", "content": f"You are a programming expert."}
                    )

                    criterion_msgs.append(
                        {
                            "role": "user",
                            "content": get_criterion_text(
                                patch.cmsg, root_cause, full_file_patch_content
                            ),
                        }
                    )
                    log_msgs.append(
                        {
                            "role": "user",
                            "content": get_criterion_text(
                                patch.cmsg, root_cause, full_file_patch_content
                            ),
                        }
                    )
                    reply = client.call_llm(criterion_msgs, log_msgs, pipeline)
                    criterion = reply
                    # print(reply)
                    criterion_msgs.append({"role": "assistant", "content": reply})
                    log_msgs.append({"role": "assistant", "content": reply})
                    buggy_stmts.extend(get_buggy_stmts(reply))
                    fixed_stmts.extend(get_fixed_stmts(reply))

                    log_msgs.append({"criterion": criterion})

                    line_info_map = build_line_info_map(full_patch_file)

                    buggy_stmts_infos = []
                    buggy_stmt_linenos = []
                    to_check_buggy_stmts = []
                    for buggy_stmt in buggy_stmts:
                        line_infos = get_line_infos(buggy_stmt, line_info_map)
                        for line_info in line_infos:
                            if line_info.lineno not in full_context_lines:
                                continue

                            buggy_stmts_infos.append(line_info)
                            buggy_stmt_linenos.append(line_info.lineno)

                        if len(line_infos) > 0:
                            if buggy_stmt.startswith("-"):
                                to_check_buggy_stmts.append(buggy_stmt[1:].strip())
                            else:
                                to_check_buggy_stmts.append(buggy_stmt.strip())

                    cand_cids = []
                    # print(f'buggy_stmt_linenos:{buggy_stmt_linenos}')
                    full_context_lines = list(full_context_lines)
                    full_context_lines.sort()
                    log_msgs.append({"full_context_lines": full_context_lines})

                    s2_cand_stmts = []
                    for buggy_stmt_info in buggy_stmts_infos:
                        # cand_cid = get_introducing_cid(repo_path,f'{cid}^1',patch_file_name,buggy_stmt_info.lineno)
                        # cand_cids.append(get_introducing_cid(repo_path,f'{cid}^1',patch_file_name,buggy_stmt_info.lineno))
                        cand_cid = get_introducing_cid1(
                            git_repo,
                            f"{cid}^1",
                            patch_file_name,
                            buggy_stmt_info.lineno,
                            ignore_whitespaces=True,
                        )
                        # log_msgs.append({'buggy_stmt':buggy_stmt_info.line,'file_name':patch_file.file_name,'lineno':buggy_stmt_info.lineno,'induce_cid':cand_cid})
                        s2_cand_stmts.append(
                            {
                                "buggy_stmt": buggy_stmt_info.line,
                                "file_name": patch_file.file_name,
                                "lineno": buggy_stmt_info.lineno,
                                "induce_cid": cand_cid,
                            }
                        )

                        cand_cids.append(cand_cid)
                        # print(f'lineno:{buggy_stmt_info.lineno},cand_cid:{cand_cid}')

                    log_msgs.append({"s2_cand_stmts": s2_cand_stmts})
                    save_logs(repo_name, cid, log_msgs, "llmszz_r", cnt)

                    cand_cids = list(set(cand_cids))
                    log_msgs.append({"s2_cand_cids": cand_cids})

                    sort_cid_by_date(cand_cids, git_repo)
                    print(cand_cids)

                    if len(cand_cids) == 0:
                        log_msgs.append({"can_determine": False})
                        save_logs(repo_name, cid, log_msgs, "llmszz_r", cnt)
                        continue

                    pre_min_lineno = min(buggy_stmt_linenos)
                    pre_max_lineno = max(buggy_stmt_linenos)

                    full_patch_lines = get_full_patch_lines(patch_file_name, full_patch)
                    pre_min_lineno1, pre_max_lineno1 = get_context_range1(
                        full_patch_lines
                    )
                    if pre_min_lineno1 != -1:
                        pre_min_lineno = min([pre_min_lineno, pre_min_lineno1])

                    if pre_max_lineno1 != -1:
                        pre_max_lineno = max([pre_max_lineno, pre_max_lineno1])

                    if pre_min_lineno - 2 > 0:
                        pre_min_lineno = pre_min_lineno - 2
                    print(f"pre_min_lineno:{pre_min_lineno}")

                    if pre_max_lineno + 2 < len(pre_file_content.split("\n")):
                        pre_max_lineno = pre_max_lineno + 2
                    print(f"pre_max_lineno:{pre_max_lineno}")

                    line_map = get_line_map(
                        f"{cid}^1",
                        cid,
                        repo_path,
                        patch_file_name,
                        len(pre_file_content.split("\n")),
                    )

                    while (pre_min_lineno not in line_map) and pre_min_lineno > 0:
                        pre_min_lineno = pre_min_lineno - 1

                    if pre_min_lineno == 0:
                        log_msgs.append({"can_determine": False})
                        save_logs(repo_name, cid, log_msgs, "llmszz_r", cnt)
                        continue
                    cur_min_lineno = line_map[pre_min_lineno]

                    while (pre_max_lineno not in line_map) and pre_max_lineno < len(
                        pre_file_content.split("\n")
                    ) - 1:
                        pre_max_lineno = pre_max_lineno + 1

                    if pre_max_lineno == len(pre_file_content.split("\n")) - 1:
                        log_msgs.append({"can_determine": False})
                        save_logs(repo_name, cid, log_msgs, "llmszz_r", cnt)
                        continue
                    cur_max_lineno = line_map[pre_max_lineno]

                    pre_partial_file_content = get_partial_file(
                        pre_file_content, pre_min_lineno, pre_max_lineno
                    )[:15000]
                    cur_partial_file_content = get_partial_file(
                        cur_file_content, cur_min_lineno, cur_max_lineno
                    )[:15000]

                    # print(f'pre_partial_file_content:\n')
                    # print(pre_partial_file_content)
                    # print('------------------------------')

                    # print(f'cur_partial_file_content:\n')
                    # print(cur_partial_file_content)
                    # print('------------------------------')

                    context_length = pre_max_lineno - pre_min_lineno
                    log_msgs.append({"context_length": context_length})

                    can_determine = False

                    test_msg = []
                    test_msg.append(
                        {"role": "system", "content": "You are a programming expert."}
                    )
                    test_msg.append(
                        {
                            "role": "user",
                            "content": get_determine_text(
                                root_cause, criterion, pre_partial_file_content
                            ),
                        }
                    )
                    # print(f'len(test_msg):{len(test_msg)}')
                    test_reply1 = client.call_llm(test_msg, log_msgs, pipeline)
                    log_msgs.extend(test_msg)
                    log_msgs.append({"role": "assistant", "content": test_reply1})
                    # print()
                    # print()
                    # print(test_reply1)
                    # print()
                    # print()

                    test_msg = []
                    test_msg.append(
                        {"role": "system", "content": "You are a programming expert."}
                    )
                    test_msg.append(
                        {
                            "role": "user",
                            "content": get_determine_text(
                                root_cause, criterion, cur_partial_file_content
                            ),
                        }
                    )
                    test_reply2 = client.call_llm(test_msg, log_msgs, pipeline)
                    log_msgs.extend(test_msg)
                    log_msgs.append({"role": "assistant", "content": test_reply2})
                    # print()
                    # print()
                    # print(test_reply2)
                    # print()
                    # print()

                    if get_reply_result(test_reply1) and (
                        not get_reply_result(test_reply2)
                    ):
                        can_determine = True

                    log_msgs.append({"can_determine": can_determine})
                    if not can_determine:
                        save_logs(repo_name, cid, log_msgs, "llmszz_r", cnt)
                        continue

                    reply1_result = False
                    reply2_result = False

                    s2_final_cid = []
                    for cand_cid in cand_cids:

                        print(f"begin to deal cand_cid {cand_cid}")
                        log_msgs.append(f"begin to deal cand_cid {cand_cid}")

                        cand_file_content = get_file_content(
                            repo_path, f"{cand_cid}", patch_file_name
                        )

                        if len(cand_file_content) == 0:
                            log_msgs.append(
                                {
                                    "reply1_result": reply1_result,
                                    "reply2_result": reply2_result,
                                }
                            )
                            break

                        line_map = get_line_map(
                            f"{cid}^1",
                            cand_cid,
                            repo_path,
                            patch_file_name,
                            len(pre_file_content.split("\n")),
                        )

                        cand_linenos = []
                        for line in range(pre_min_lineno, pre_max_lineno + 1):
                            if line in line_map:
                                cand_linenos.append(line_map[line])

                        cand_min_line = -1
                        cand_max_line = -1

                        if len(cand_linenos) > 0:
                            cand_min_line = min(cand_linenos)
                        if len(cand_linenos) > 0:
                            cand_max_line = max(cand_linenos)

                        cand_code_snippet = ""
                        for cand_lineno in range(cand_min_line, cand_max_line + 1):
                            if cand_lineno >= 0 and cand_lineno < len(
                                cand_file_content.split("\n")
                            ):
                                cand_code_snippet = (
                                    cand_code_snippet
                                    + cand_file_content.split("\n")[cand_lineno]
                                    + "\n"
                                )
                        cand_code_snippet = cand_code_snippet[:15000]
                        # print('-------------------------------------------------------')
                        # print(cand_code_snippet)
                        # print('-------------------------------------------------------')

                        cand_file_content1 = get_file_content(
                            repo_path, f"{cand_cid}^1", patch_file_name
                        )
                        line_map1 = get_line_map(
                            f"{cid}^1",
                            f"{cand_cid}^1",
                            repo_path,
                            patch_file_name,
                            len(pre_file_content.split("\n")),
                        )

                        cand_linenos = []
                        for line in range(pre_min_lineno, pre_max_lineno + 1):
                            if line in line_map1:
                                cand_linenos.append(line_map1[line])

                        pre_cand_min_line = -1
                        pre_cand_max_line = -1

                        if len(cand_linenos) > 0:
                            pre_cand_min_line = min(cand_linenos)
                        if len(cand_linenos) > 0:
                            pre_cand_max_line = max(cand_linenos)

                        pre_cand_code_snippet = ""
                        for cand_lineno in range(
                            pre_cand_min_line, pre_cand_max_line + 1
                        ):
                            if cand_lineno >= 0 and cand_lineno < len(
                                cand_file_content1.split("\n")
                            ):
                                pre_cand_code_snippet = (
                                    pre_cand_code_snippet
                                    + cand_file_content1.split("\n")[cand_lineno]
                                    + "\n"
                                )
                        pre_cand_code_snippet = pre_cand_code_snippet[:15000]
                        # print('-------------------------------------------------------')
                        # print(pre_cand_code_snippet)
                        # print('-------------------------------------------------------')

                        if len(cand_code_snippet.strip()) == 0:
                            reply1_result = False
                        else:
                            reply1_result = False
                            if is_buggy_stmts_in_code_snippet(
                                to_check_buggy_stmts,
                                cand_code_snippet,
                                log_msgs,
                                pipeline,
                                client,
                            ):
                                test_msg = []
                                test_msg.append(
                                    {
                                        "role": "system",
                                        "content": "You are a programming expert.",
                                    }
                                )
                                test_msg.append(
                                    {
                                        "role": "user",
                                        "content": get_determine_text(
                                            root_cause, criterion, cand_code_snippet
                                        ),
                                    }
                                )
                                test_reply1 = client.call_llm(
                                    test_msg, log_msgs, pipeline
                                )
                                reply1_result = get_reply_result(test_reply1)
                                log_msgs.extend(test_msg)
                                log_msgs.append(
                                    {"role": "assistant", "content": test_reply1}
                                )

                        if len(pre_cand_code_snippet.strip()) == 0:
                            reply2_result = False
                        else:
                            reply2_result = False

                            if is_buggy_stmts_in_code_snippet(
                                to_check_buggy_stmts,
                                pre_cand_code_snippet,
                                log_msgs,
                                pipeline,
                                client,
                            ):
                                test_msg = []
                                test_msg.append(
                                    {
                                        "role": "system",
                                        "content": "You are a programming expert.",
                                    }
                                )
                                test_msg.append(
                                    {
                                        "role": "user",
                                        "content": get_determine_text(
                                            root_cause, criterion, pre_cand_code_snippet
                                        ),
                                    }
                                )
                                test_reply2 = client.call_llm(
                                    test_msg, log_msgs, pipeline
                                )
                                reply2_result = get_reply_result(test_reply2)
                                log_msgs.extend(test_msg)
                                log_msgs.append(
                                    {"role": "assistant", "content": test_reply2}
                                )

                        if reply1_result and not reply2_result:
                            s2_final_cid.append(cand_cid)
                            log_msgs.append(
                                {
                                    "reply1_result": reply1_result,
                                    "reply2_result": reply2_result,
                                }
                            )
                            log_msgs.append({"s2_final_cid": s2_final_cid})
                            save_logs(repo_name, cid, log_msgs, "llmszz_r", cnt)
                            break

                        print(f"reply1_result:{reply1_result}")
                        print(f"reply2_result:{reply2_result}")
                        log_msgs.append(
                            {
                                "reply1_result": reply1_result,
                                "reply2_result": reply2_result,
                            }
                        )

                    save_logs(repo_name, cid, log_msgs, "llmszz_r", cnt)

        except:
            errs_info.append({"cid": cid, "except_info": traceback.format_exc()})
            with open(os.path.join(CWD, "err_infos.json"), "w") as f:
                json.dump(errs_info, f)
            log_msgs.append({"can_determine": False})
            traceback.print_exc()

        finally:
            end_time = time.time()
            elapsed_time = end_time - start_time
            log_msgs.append({"token_cost": client.token_cost})
            log_msgs.append({"call_llm_times": client.get_call_cnt()})
            log_msgs.append({"elapsed_time": elapsed_time})
            log_msgs.append({"call_llm_times": client.get_call_cnt()})
            save_logs(repo_name, cid, log_msgs, "llmszz_r", cnt)
            dealed_infos.append(info)
            with open(os.path.join(CWD, "deal_infos.json"), "w") as f:
                json.dump(dealed_infos, f)
