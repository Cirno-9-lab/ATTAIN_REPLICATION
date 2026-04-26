from constants import *
from llm import *
from parse_patch import *
from prompts import *
from util import *


def build_whole_line_info_map(patch):
    line_info_map = {}

    for patch_file in patch.get_files():
        for patch_hunk in patch_file.get_hunks():
            for patch_line in patch_hunk.get_lines():
                line_str = patch_line.line.strip()
                if len(line_str) == 0:
                    continue
                if patch_line.is_del or patch_line.is_bg:
                    if line_str.strip() not in line_info_map:
                        patch_line.set_patch_file_name(patch_file.file_name)
                        line_info_map[line_str.strip()] = []
                        line_info_map[line_str.strip()].append(patch_line)
                    else:
                        patch_line.set_patch_file_name(patch_file.file_name)
                        line_info_map[line_str.strip()].append(patch_line)

    return line_info_map


all_info = []
with open(os.path.join(DATASET_DIR, "final_all_dataset.json")) as f:
    all_info = json.load(f)

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

        try:
            git_repo = git.Repo(repo_path)
            patch_content = get_patch_content(repo_path, cid)
            if len(patch_content) == 0:
                continue
            patch = Patch(patch_content)

            msgs.append(
                {"role": "system", "content": get_root_cause_summary_text(patch_content)}
            )
            log_msgs.append(
                {"role": "system", "content": get_root_cause_summary_text(patch_content)}
            )
            reply = client.call_llm(msgs, log_msgs, pipeline)
            log_msgs.append({"role": "assistant", "content": reply})
            _, root_cause = get_names_info(reply)

            code_stmts_msg = []
            line_info_map = build_whole_line_info_map(patch)

            code_stmts_msg.append(
                {
                    "role": "user",
                    "content": f"{code_stmts_summary_text1}\nRoot cause:\n{root_cause}\nPatch:\n{patch_content}",
                }
            )
            log_msgs.append(
                {
                    "role": "user",
                    "content": f"{code_stmts_summary_text1}\nRoot cause:\n{root_cause}\nPatch:\n{patch_content}",
                }
            )
            reply = client.call_llm(code_stmts_msg, log_msgs, pipeline)
            log_msgs.append({"role": "assistant", "content": reply})
            buggy_stmts = get_buggy_stmts(reply)

            buggy_stmts_infos = []
            llm_file_cand_cids = []
            for buggy_stmt in buggy_stmts:
                line_infos = get_line_infos(buggy_stmt, line_info_map)
                if len(line_infos) == 0:
                    continue
                for line_info in line_infos:

                    # induce_cid = get_introducing_cid(repo_path,f'{cid}^1',patch_file_name,line_info.lineno)
                    induce_cid = get_introducing_cid1(
                        git_repo,
                        f"{cid}^1",
                        line_info.get_patch_file_name(),
                        line_info.lineno,
                        ignore_whitespaces=True,
                    )
                    buggy_stmts_infos.append(
                        {
                            "buggy_stmt": buggy_stmt,
                            "file_name": line_info.get_patch_file_name(),
                            "lineno": line_info.lineno,
                            "induce_cid": induce_cid,
                        }
                    )
                    llm_file_cand_cids.append(induce_cid)

            llm_file_final_cids = get_r_commits(repo_name, list(llm_file_cand_cids))
            log_msgs.append({"buggy_stmts_infos": buggy_stmts_infos})
            log_msgs.append({"llm_file_cand_cids": list(llm_file_cand_cids)})
            log_msgs.append({"llm_file_final_cids": llm_file_final_cids})
        except:
            errs_info.append({"cid": cid, "except_info": traceback.format_exc()})
            with open(os.path.join(CWD, "err_infos_raw.json"), "w") as f:
                json.dump(errs_info, f)
            traceback.print_exc()

        finally:
            save_logs(repo_name, cid, log_msgs, "llm4szz_raw", cnt)
            dealed_infos.append(info)
            with open(os.path.join(CWD, "deal_info_opt1.json"), "w") as f:
                json.dump(dealed_infos, f)
