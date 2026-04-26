import os
import json
import re
import pandas as pd

# 配置路径（从 code/V-SZZ/ 目录运行）
json_dir = 'affected_version_output'
excel_path = '/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/execution_result.xlsx'


def normalize_version_candidates(ver: str):
    """给一个版本字符串生成一组候选形式，用于模糊匹配 Excel 中的 Version。

    例子：
    - "dom4j-2.0.0-RC1" -> {"dom4j-2.0.0-RC1", "2.0.0-RC1"}
    - "version-2.0.0"    -> {"version-2.0.0", "2.0.0"}
    - "v2.0.0"           -> {"v2.0.0", "2.0.0"}
    """
    if ver is None:
        return []

    s = str(ver).strip()
    if not s:
        return []

    cands = set()
    cands.add(s)

    lower = s.lower()

    # 去掉前缀 "version-"
    if lower.startswith('version-') and len(s) > len('version-'):
        cands.add(s[len('version-'):])

    # 去掉前缀 "v"（常见的 tag 写法，如 v2.0.0）
    if lower.startswith('v') and len(s) > 1 and s[1].isdigit():
        cands.add(s[1:])

    # 去掉 artifact 前缀：取第一个 '-' 之后的部分（如 dom4j-2.0.0-RC1 -> 2.0.0-RC1）
    if '-' in s:
        after_first_dash = s.split('-', 1)[1]
        cands.add(after_first_dash)

    # 用正则提取看起来像版本号的片段（如 2.0.0、2.0.0-RC1）
    m = re.search(r"(\d+\.\d+[^\s]*)", s)
    if m:
        cands.add(m.group(1))

    return list(cands)


def process_vulnerability_data():
    """读取 code/V-SZZ/affected_version_output 下的结果，
    按 (CVE_ID, Version) 维度，使用模糊匹配方式把 V-SZZ 的预测回填到
    dataset/execution_result.xlsx 的 vszz_verdict 列。
    """
    # 1. 遍历并解析所有 JSON 文件，建立一个 (CVE_ID, normalized_version) 的映射集合
    affected_lookup = set()

    if not os.path.exists(json_dir):
        print(f"错误: 找不到目录 {json_dir}")
        return

    for filename in os.listdir(json_dir):
        if not filename.endswith('.json'):
            continue
        file_path = os.path.join(json_dir, filename)
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(f"解析文件 {filename} 出错: {e}")
                continue

        for cve_id, versions in data.items():
            cve = str(cve_id).strip()
            for ver in versions:
                for norm_ver in normalize_version_candidates(ver):
                    affected_lookup.add((cve, norm_ver))

    print(f"从 V-SZZ 输出中汇总得到 (CVE, version) 组合数: {len(affected_lookup)}")

    # 2. 读取 Excel 文件
    if not os.path.exists(excel_path):
        print(f"错误: 找不到 Excel 文件 {excel_path}")
        return

    df = pd.read_excel(excel_path)

    # 3. 匹配逻辑：对 Excel 中每一行 (CVE_ID, Version)，
    # 生成一组归一化版本候选，只要有一个命中 affected_lookup 就视为 affected。
    def check_verdict(row):
        cve = str(row['CVE_ID']).strip()
        ver = str(row['Version']).strip()

        for cand in normalize_version_candidates(ver):
            if (cve, cand) in affected_lookup:
                return 'affected'
        return 'not affected'

    df['vszz_verdict'] = df.apply(check_verdict, axis=1)

    # 4. 保存结果
    try:
        df.to_excel(excel_path, index=False)
        print(f"处理完成！vszz_verdict 已写回: {excel_path}")
    except Exception as e:
        print(f"保存文件失败，请检查文件是否被占用: {e}")


if __name__ == "__main__":
    process_vulnerability_data()
