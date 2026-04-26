import json

def find_common_repos(label_file, bugfix_file):
    try:
        # 加载 label.json (字典格式)
        with open(label_file, 'r', encoding='utf-8') as f1:
            label_data = json.load(f1)
            # label.json 的 key 就是 repo 名
            label_repos = set(label_data.keys())

        # 加载 bugfix_commits_all_java.json (列表格式)
        with open(bugfix_file, 'r', encoding='utf-8') as f2:
            bugfix_data = json.load(f2)
            
        # 提取 bugfix 文件中的 repo 名 (取 / 之后的部分)
        bugfix_repo_map = {}
        for item in bugfix_data:
            full_name = item.get("repo_name", "")
            if "/" in full_name:
                # 获取 / 之后的部分
                short_name = full_name.split("/")[-1]
                # 记录原始全名，方便后续查看
                if short_name not in bugfix_repo_map:
                    bugfix_repo_map[short_name] = set()
                bugfix_repo_map[short_name].add(full_name)
        
        # 找交集
        common_repo_names = label_repos.intersection(bugfix_repo_map.keys())

        # 打印结果
        if not common_repo_names:
            print("没有找到共同的 Repo。")
        else:
            print(f"{'Common Repo Name':<30} | {'Original Full Name (in bugfix file)'}")
            print("-" * 70)
            for repo in sorted(common_repo_names):
                full_names = ", ".join(bugfix_repo_map[repo])
                print(f"{repo:<30} | {full_names}")
            
            print(f"\n统计：共找到 {len(common_repo_names)} 个共同的 Repo。")

    except FileNotFoundError as e:
        print(f"错误: 找不到文件 - {e}")
    except json.JSONDecodeError as e:
        print(f"错误: JSON 解析失败 - {e}")

if __name__ == "__main__":
    # 确保文件名正确
    label_json = 'label.json'
    bugfix_json = 'bugfix_commits_all_java.json'
    
    find_common_repos(label_json, bugfix_json)