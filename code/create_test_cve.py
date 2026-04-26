import json

# 创建测试CVE列表（包含漏报的CVE和正确的CVE）
test_cves = {
    "CVE-2016-9879": {"version_pair": [{"BASE_TAG": "3.0.3.RELEASE", "HEAD_TAG": "3.0.4.RELEASE"}]},
    "CVE-2017-4995": {"version_pair": [{"BASE_TAG": "4.1.5.RELEASE", "HEAD_TAG": "4.1.6.RELEASE"}]},
    "CVE-2021-43113": {"version_pair": [{"BASE_TAG": "7.1.11", "HEAD_TAG": "7.1.12"}]},
    "CVE-2023-34453": {"version_pair": [{"BASE_TAG": "1.1.3-M1", "HEAD_TAG": "1.1.3-RC1"}]},
    "CVE-2014-0097": {"version_pair": [{"BASE_TAG": "3.0.8.RELEASE", "HEAD_TAG": "3.0.9.RELEASE"}]},  # 正确的
    "CVE-2013-2055": {"version_pair": [{"BASE_TAG": "wicket-1.5.0", "HEAD_TAG": "wicket-1.5.1"}]},  # 正确的
}

with open("dataset/list/cve_list_test.json", "w") as f:
    json.dump(test_cves, f, indent=2)

print("Created test CVE list with 6 CVEs:")
for cve in test_cves.keys():
    print(f"  - {cve}")
