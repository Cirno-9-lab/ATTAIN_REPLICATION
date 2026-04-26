import json

def extract_java_repos(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 使用集合去重
        java_repos_full = set()
        java_repos_short = set()

        for item in data:
            # 检查 language 字段是否包含 java (忽略大小写)
            languages = [lang.lower() for lang in item.get("language", [])]
            
            if "java" in languages:
                full_name = item.get("repo_name", "")
                if full_name:
                    java_repos_full.add(full_name)
                    # 提取 / 之后的部分
                    short_name = full_name.split("/")[-1]
                    java_repos_short.add(short_name)

        # 打印结果
        print(f"找到语言包含 Java 的项目共: {len(java_repos_short)} 个 (去重后)")
        print("-" * 40)
        print("提取出的 Repo 列表 (短名称):")
        for name in sorted(java_repos_short):
            print(f"- {name}")
            
        return list(java_repos_short)

    except FileNotFoundError:
        print(f"错误：找不到文件 {file_path}")
    except json.JSONDecodeError:
        print("错误：JSON 格式不正确")

if __name__ == "__main__":
    file_name = 'bugfix_commits_all_java.json'
    extract_java_repos(file_name)