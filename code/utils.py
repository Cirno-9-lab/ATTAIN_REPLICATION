import re

def normalize_version(version_str):
    """
    将模糊的版本号字符串标准化为 x.y.z 格式。
    支持处理：1_3_2, 1x3x2, 1.3.2.release, v1.3.2 等。
    """
    if not version_str:
        return ""

    # 1. 使用正则匹配所有连续的数字部分
    # \d+ 匹配一个或多个数字
    segments = re.findall(r'\d+', version_str)
    
    # 2. 如果没有找到任何数字，返回原字符串或空值
    if not segments:
        return ""
    
    # 3. 将提取出的数字段用 '.' 拼接
    # 这种做法会自动忽略掉前缀（如 v）、后缀（如 .release）和中间的异形分隔符（如 _ 或 x）
    return ".".join(segments)

# # 测试用例
# if __name__ == "__main__":
#     test_cases = [
#         "1.3.2",
#         "1_3_2",
#         "1x3x2",
#         "1.30.21",
#         "1.3.2.release",
#         "v1.3.2",
#         "version-2_0_4-beta",
#         "2.3"
#     ]
    
#     for case in test_cases:
#         print(f"{case.ljust(20)} -> {normalize_version(case)}")

import requests
from datetime import datetime

def get_release_history(group_id, artifact_id):
    """获取指定 Maven 组件的所有版本发布历史"""
    url = f"https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&core=gav&rows=100&wt=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Error fetching data for {group_id}:{artifact_id} - {e}")
        return []

    docs = data.get("response", {}).get("docs", [])
    release_history = []
    for doc in docs:
        version = doc.get("v")
        ts = doc.get("timestamp") / 1000.0
        # 存储为 datetime 对象方便后续比对
        dt_obj = datetime.fromtimestamp(ts)
        release_history.append({
            "version": version,
            "release_date": dt_obj 
        })
    # 按时间升序排序
    return sorted(release_history, key=lambda x: x['release_date'])

def find_version_by_timestamp(commit_date_str, history):
    """根据时间戳匹配版本"""
    if not commit_date_str or not history:
        return None
    
    # GitHub 时间格式转化: 2023-08-11T14:20:00Z
    commit_dt = datetime.strptime(commit_date_str, '%Y-%m-%dT%H:%M:%SZ')
    
    for item in history:
        if item['release_date'] >= commit_dt:
            return item['version']
    return None

if __name__ == "__main__":
    # group_id = "com.fasterxml.jackson.core"
    # artifact_id = "jackson-databind"
    # group_id = "com.thoughtworks.xstream"
    # artifact_id = "xstream"
    group_id = "org.apache.wicket"
    artifact_id = "wicket-core"
    
    
    history = get_release_history(group_id, artifact_id)
    for item in history:
        print(f"Version: {item['version']}, Release Date: {item['release_date']}")

IGNORE_SET = {
    '.md', '.adoc', '.gitignore', '.gitattributes', 
    '.classpath', '.x', 'VERSION', 'CREDITS','.gradle', '.html', '.xml', '.yml', '.yaml', '.properties', '.vm', 'bazel'
}