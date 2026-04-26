import json
from collections import Counter

# 文件名定义
json_filename = "dataset_o.json"
log_filename = "log copy.txt"
output_filename = "res.txt"
prefix = "begin to deal with /home/xinweimao/alv_evaluate"

def analyze_and_compare():
    # 1. 加载 JSON 数据中的 bug_fixing_commit
    try:
        with open(json_filename, 'r', encoding='utf-8') as f:
            dataset = json.load(f)
        # 提取所有合法的 bug_fixing_commit 到一个集合中（方便快速查找）
        valid_commits = {item["bug_fixing_commit"] for item in dataset}
    except Exception as e:
        print(f"读取 JSON 出错: {e}")
        return

    extracted_hashes = []

    # 2. 提取日志中的 Hash 并写入 res.txt
    try:
        with open(log_filename, 'r', encoding='utf-8') as infile, \
             open(output_filename, 'w', encoding='utf-8') as outfile:
            
            for line in infile:
                clean_line = line.strip()
                if clean_line.startswith(prefix):
                    # 获取冒号后的最后一个 hash
                    h = clean_line.split(':')[-1].strip()
                    if h:
                        extracted_hashes.append(h)
                        outfile.write(h + '\n')
    except FileNotFoundError:
        print(f"找不到日志文件: {log_filename}")
        return

    # 3. 计数逻辑
    # 计数器 A: 匹配上 JSON 的次数
    match_count = 0
    # 计数器 B: 记录每个 hash 出现的频率，用于找出重复项
    hash_counts = Counter(extracted_hashes)
    
    total_duplicates = 0
    
    print("--- 分析报告 ---")
    for h, count in hash_counts.items():
        # 如果在 JSON 中能找到
        if h in valid_commits:
            match_count += 1
        
        # 如果该 hash 出现次数 > 1，计算重复次数
        if count > 1:
            print(f"重复项检测: Hash [{h}] 出现了 {count} 次")
            total_duplicates += (count - 1) # 这里统计的是“额外重复”的次数

    print("----------------")
    print(f"1. 匹配到 JSON 'bug_fixing_commit' 的总行数: {match_count}")
    print(f"2. 提取出的 Hash 总数: {len(extracted_hashes)}")
    print(f"3. 累计重复出现的总次数: {total_duplicates}")

if __name__ == "__main__":
    analyze_and_compare()