import json

# 1. 定义需要保留的仓库名称列表
target_repos = ["corenlp"]

try:
    # 2. 读取原始的 dataset_o.json 文件
    with open('dataset_o.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 3. 筛选符合条件的条目
    # 只要 repo_name 在我们的目标列表中，就保留该条目
    filtered_data = [item for item in data if item.get("repo_name") in target_repos]

    # 4. 将结果保存到 dataset_o1.json 中
    with open('dataset_o1.json', 'w', encoding='utf-8') as f:
        json.dump(filtered_data, f, indent=4, ensure_ascii=False)

    print(f"处理完成！已从 {len(data)} 条数据中筛选出 {len(filtered_data)} 条，并保存至 dataset_o1.json。")

except FileNotFoundError:
    print("错误：找不到 dataset_o.json 文件，请确保该文件在当前目录下。")
except json.JSONDecodeError:
    print("错误：JSON 文件格式不正确，无法解析。")