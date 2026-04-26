#!/usr/bin/env python3
"""详细调试单个commit的检测过程"""
import json
from intro_infer_embedding_v4 import load_intro_context

cve_id = "CVE-2014-3625"
target_hash = "5a1bd20864d9255eafb23d551f7dfe34ed0961e9"

# 加载候选commits
filtered_commits, intro_contexts = load_intro_context(cve_id)
commit_context = intro_contexts[target_hash]

print(f"Commit: {target_hash[:16]}")
print(f"Message: {commit_context.get('message', '')}")
print(f"\n{'='*100}")

for file_path, file_ctx in commit_context.get("files", {}).items():
    added_content = file_ctx.get("modified_added_content", [])
    all_code = "\n".join(added_content)
    all_code_lower = all_code.lower()
    
    print(f"\n文件: {file_path}")
    print(f"  行数: {len(added_content)}")
    
    # 检查各个模式
    print(f"\n  关键词检测:")
    print(f"    'path' in code: {'path' in all_code_lower}")
    print(f"    'request' in code: {'request' in all_code_lower}")
    print(f"    'getattribute' in code: {'getattribute' in all_code_lower}")
    print(f"    'getResource' in code: {'getResource' in all_code}")
    print(f"    'getResources' in code: {'getResources' in all_code}")
    print(f"    'createRelative' in code: {'createRelative' in all_code}")
    
    # 检查安全措施
    security_checks = ["validate", "sanitize", "check", "limit", "bound", "try", "catch", "assert", "verify", "secure", "safe", "clean", "normalize"]
    found_checks = [check for check in security_checks if check in all_code_lower]
    print(f"\n  找到的安全措施: {found_checks}")
    
    # 手动检测关键漏洞模式
    print(f"\n  手动检测关键漏洞模式:")
    
    # 1. 资源操作无验证
    if any(pattern in all_code for pattern in ["getResource", "getResources", "createRelative", "FileInputStream", "FileReader"]):
        if not any(check in all_code_lower for check in ["validate", "check", "sanitize", "clean", "normalize", "verify", "isinvalid", "processpath"]):
            print(f"    ✓ 资源操作无验证")
        else:
            print(f"    ✗ 资源操作有验证")
    
    # 2. 从request获取path无验证
    if "path" in all_code_lower:
        if "request" in all_code_lower or "getattribute" in all_code_lower:
            if not any(check in all_code_lower for check in ["validate", "sanitize", "clean", "normalize", "check", "isinvalid"]):
                print(f"    ✓ 从request获取path无验证")
            else:
                print(f"    ✗ 从request获取path有验证")
        else:
            print(f"    ? 有path但不是从request获取")
    
    # 显示关键代码片段
    print(f"\n  关键代码片段:")
    for i, line in enumerate(added_content):
        if any(keyword in line.lower() for keyword in ["path", "request", "resource", "createRelative"]):
            print(f"    {line}")
            if i > 10:
                break
