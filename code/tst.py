import requests
from datetime import datetime

def get_maven_release_dates(group_id, artifact_id):
    # Maven Central API 地址，rows=100 表示获取最近 100 个版本
    url = f"https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&core=gav&rows=100&wt=json"
    
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to fetch data")
        return

    data = response.json()
    docs = data.get("response", {}).get("docs", [])
    
    print(f"{'Version':<15} | {'Release Date (UTC)':<20}")
    print("-" * 40)
    
    for doc in docs:
        version = doc.get("v")
        # timestamp 单位是毫秒
        timestamp = doc.get("timestamp") / 1000.0
        date_str = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        print(f"{version:<15} | {date_str:<20}")

# 以 Parsson 为例
get_maven_release_dates("org.eclipse.parsson", "parsson")