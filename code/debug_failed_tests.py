#!/usr/bin/env python3
"""详细调试失败的测试案例"""
import json
from intro_infer_embedding_v4 import (
    load_patch_results,
    load_fix_code_context,
    load_intro_context,
    analyze_candidate_commit
)

def debug_cve(cve_id, expected):
    print(f"\n{'='*100}")
    print(f"调试 CVE: {cve_id}")
    print(f"期望: {expected}")
    print(f"{'='*100}")
    
    # 加载数据
    fix_commits_files = load_patch_results(cve_id)
    fix_security_measures, fix_security_patterns = load_fix_code_context(cve_id, fix_commits_files)
    filtered_commits, intro_contexts = load_intro_context(cve_id)
    
    print(f"候选commits数量: {len(intro_contexts)}")
    
    # 分析每个候选commit
    for commit_hash, commit_context in intro_contexts.items():
        is_intro, confidence, analysis_info, added_lines, security_features = analyze_candidate_commit(
            commit_context, fix_security_patterns, fix_security_measures
        )
        
        print(f"\nCommit: {commit_hash[:16]}")
        print(f"  Message: {commit_context.get('message', '')[:60]}")
        print(f"  添加行数: {added_lines}")
        print(f"  关键漏洞模式数: {len(analysis_info.get('critical_vulnerability_patterns', []))}")
        print(f"  可疑模式数: {len(analysis_info.get('suspicious_patterns', []))}")
        print(f"  是否initial: {analysis_info.get('is_initial_commit', False)}")
        print(f"  是否intro: {is_intro}, 置信度: {confidence:.2%}")

# 调试失败的案例
print("\n" + "#"*100)
print("# 调试失败的测试案例")
print("#"*100)

debug_cve("CVE-2014-0097", "should_find")
debug_cve("CVE-2014-125087", "should_not_find")

# 特别检查CVE-2014-3625的目标commit
print(f"\n{'='*100}")
print("特别检查 CVE-2014-3625 的目标commit: 5a1bd20864d9255e")
print(f"{'='*100}")

fix_commits_files = load_patch_results("CVE-2014-3625")
fix_security_measures, fix_security_patterns = load_fix_code_context("CVE-2014-3625", fix_commits_files)
filtered_commits, intro_contexts = load_intro_context("CVE-2014-3625")

target_hash = "5a1bd20864d9255eafb23d551f7dfe34ed0961e9"
if target_hash in intro_contexts:
    commit_context = intro_contexts[target_hash]
    is_intro, confidence, analysis_info, added_lines, security_features = analyze_candidate_commit(
        commit_context, fix_security_patterns, fix_security_measures
    )
    
    print(f"Commit: {target_hash[:16]}")
    print(f"  Message: {commit_context.get('message', '')}")
    print(f"  添加行数: {added_lines}")
    print(f"  关键漏洞模式: {analysis_info.get('critical_vulnerability_patterns', [])}")
    print(f"  可疑模式数: {len(analysis_info.get('suspicious_patterns', []))}")
    print(f"  是否initial: {analysis_info.get('is_initial_commit', False)}")
    print(f"  是否intro: {is_intro}, 置信度: {confidence:.2%}")
else:
    print("目标commit不在候选列表中")
