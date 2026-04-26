#!/usr/bin/env python3
"""调试CVE-2023-51080"""
import json
from intro_infer_embedding_v4 import (
    load_patch_results,
    load_fix_code_context,
    load_intro_context,
    analyze_candidate_commit
)

cve_id = "CVE-2023-51080"

# 加载数据
fix_commits_files = load_patch_results(cve_id)
print(f"修复commits: {list(fix_commits_files.keys())}")

fix_security_measures, fix_security_patterns = load_fix_code_context(cve_id, fix_commits_files)
print(f"安全措施: {fix_security_patterns}")

filtered_commits, intro_contexts = load_intro_context(cve_id)
print(f"候选commits: {len(filtered_commits)} 个")

# 分析每个候选commit
for commit_hash, commit_context in intro_contexts.items():
    print(f"\n{'='*80}")
    print(f"Commit: {commit_hash[:16]}")
    print(f"Message: {commit_context.get('message', '')}")
    
    is_intro, confidence, analysis_info, added_lines, security_features = analyze_candidate_commit(
        commit_context, fix_security_patterns, fix_security_measures
    )
    
    print(f"是否intro: {is_intro}")
    print(f"置信度: {confidence:.2%}")
    print(f"添加行数: {added_lines}")
    print(f"安全特征: {security_features}")
    print(f"关键漏洞模式: {analysis_info.get('critical_vulnerability_patterns', [])}")
    print(f"可疑模式: {analysis_info.get('suspicious_patterns', [])}")
    print(f"是否initial: {analysis_info.get('is_initial_commit', False)}")
