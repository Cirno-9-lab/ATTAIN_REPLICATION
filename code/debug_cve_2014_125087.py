#!/usr/bin/env python3
"""调试CVE-2014-125087"""
import json
from intro_infer_embedding_v4 import (
    load_patch_results,
    load_fix_code_context,
    load_intro_context,
    analyze_candidate_commit
)

cve_id = "CVE-2014-125087"

# 加载数据
fix_commits_files = load_patch_results(cve_id)
print(f"修复commits: {list(fix_commits_files.keys())}")

fix_security_measures, fix_security_patterns = load_fix_code_context(cve_id, fix_commits_files)
print(f"安全措施: {fix_security_patterns}")

filtered_commits, intro_contexts = load_intro_context(cve_id)
print(f"候选commits: {len(filtered_commits)} 个")

# 分析找到的intro commits
print(f"\n{'='*80}")
print("找到的intro commits:")
print(f"{'='*80}")

# 从结果文件读取
with open("/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/result/intro_contrastive_final_f.json") as f:
    results = json.load(f)
    if "cve-2014-125087" in results:
        intro_commits = results["cve-2014-125087"][0].get("analysis", {})
        for commit_hash in intro_commits.keys():
            print(f"\nCommit: {commit_hash[:16]}")
            if commit_hash in intro_contexts:
                print(f"Message: {intro_contexts[commit_hash].get('message', '')}")
                
                is_intro, confidence, analysis_info, added_lines, security_features = analyze_candidate_commit(
                    intro_contexts[commit_hash], fix_security_patterns, fix_security_measures
                )
                
                print(f"置信度: {confidence:.2%}")
                print(f"添加行数: {added_lines}")
                print(f"关键漏洞模式: {analysis_info.get('critical_vulnerability_patterns', [])[:3]}")
                print(f"是否initial: {analysis_info.get('is_initial_commit', False)}")
