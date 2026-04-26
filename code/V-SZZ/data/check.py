import json
import re

# 检查 label.json 中的 CWE 格式是否正确

def validate_label_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 正则表达式：匹配 CWE-数字 或 字符串 UnKnown
    pattern = re.compile(r'^(CWE-\d+|Unknown)$')
    
    errors = []
    
    for project, cves in data.items():
        for cve_id, info in cves.items():
            cwe_value = info.get("cwe")
            
            # 检查是否为字符串且符合正则
            if not isinstance(cwe_value, str) or not pattern.match(cwe_value):
                errors.append({
                    "project": project,
                    "cve": cve_id,
                    "invalid_value": cwe_value
                })
    
    if not errors:
        print("✅ 检查通过！所有 CWE 格式均符合规范。")
    else:
        print(f"❌ 发现 {len(errors)} 处格式错误：")
        for err in errors:
            print(f"项目: {err['project']} | CVE: {err['cve']} | 错误值: '{err['invalid_value']}'")

# 执行检查
validate_label_json('label.json')