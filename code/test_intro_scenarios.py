#!/usr/bin/env python3
"""
测试脚本：验证不同场景下的intro commit识别
"""
import json
import os

# 导入主脚本的函数
from intro_infer_embedding_v4 import (
    load_patch_results,
    load_fix_code_context,
    load_intro_context,
    analyze_candidate_commit
)

BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"

def test_cve_scenario(cve_id, base_tag, head_tag, expected_result):
    """
    测试单个CVE场景
    expected_result: "should_find" | "should_not_find"
    """
    print(f"\n{'='*100}")
    print(f"测试 CVE: {cve_id}")
    print(f"版本: {base_tag} → {head_tag}")
    print(f"期望: {'应该找到intro commit' if expected_result == 'should_find' else '不应该找到intro commit'}")
    print(f"{'='*100}")
    
    # 步骤2: 获取修复commits
    fix_commits_files = load_patch_results(cve_id)
    if not fix_commits_files:
        print(f"❌ 测试失败: 未找到修复commits")
        return False
    print(f"✓ 找到 {len(fix_commits_files)} 个修复commit")
    
    # 步骤3: 加载修复代码上下文
    fix_security_measures, fix_security_patterns = load_fix_code_context(cve_id, fix_commits_files)
    if fix_security_measures:
        print(f"✓ 提取 {len(fix_security_measures)} 个文件的安全措施")
    else:
        print(f"⚠ 未找到修复代码上下文，使用简化分析")
    
    # 步骤6: 加载候选commits
    filtered_commits, intro_contexts = load_intro_context(cve_id)
    if not filtered_commits:
        if expected_result == "should_not_find":
            print(f"✅ 测试通过: 确实未找到候选commits")
            return True
        else:
            print(f"❌ 测试失败: 未找到候选commits")
            return False
    
    print(f"✓ 筛选出 {len(filtered_commits)} 个候选commits")
    
    # 步骤7: 分析候选commits
    found_intro = False
    intro_commits = []
    
    for commit_hash, commit_context in intro_contexts.items():
        # 检查版本是否匹配
        commit_base = commit_context.get("base_tag", "")
        commit_head = commit_context.get("head_tag", "")
        
        # 分析commit
        is_intro, confidence, analysis_info, added_lines, security_features = analyze_candidate_commit(
            commit_context, fix_security_patterns, fix_security_measures
        )
        
        if is_intro and confidence > 0.5:
            found_intro = True
            intro_commits.append({
                "hash": commit_hash,
                "confidence": confidence,
                "added_lines": added_lines
            })
            print(f"  ⭐ {commit_hash[:16]}: intro commit (confidence={confidence:.2%})")
    
    # 验证结果
    if expected_result == "should_find":
        if found_intro:
            print(f"✅ 测试通过: 找到 {len(intro_commits)} 个intro commit")
            return True
        else:
            print(f"❌ 测试失败: 应该找到intro commit但未找到")
            return False
    else:  # should_not_find
        if not found_intro:
            print(f"✅ 测试通过: 确实未找到intro commit")
            return True
        else:
            print(f"❌ 测试失败: 不应该找到intro commit但找到了 {len(intro_commits)} 个")
            return False


def main():
    print("\n" + "#"*100)
    print("# Intro Commit识别测试")
    print("#"*100)
    
    test_cases = [
        {
            "cve_id": "CVE-2023-51080",
            "base_tag": "5.8.21",
            "head_tag": "5.8.22",
            "expected": "should_find",
            "description": "hutool NumberUtil.toBigDecimal漏洞"
        },
        {
            "cve_id": "CVE-2014-3625",
            "base_tag": "v3.0.3.RELEASE",
            "head_tag": "v3.0.4.RELEASE",
            "expected": "should_find",
            "description": "Spring MVC资源处理器路径遍历漏洞"
        },
        {
            "cve_id": "CVE-2014-0097",
            "base_tag": "v3.0.8.RELEASE",
            "head_tag": "v3.1.0.RELEASE",
            "expected": "should_find",
            "description": "Spring Security漏洞"
        },
        {
            "cve_id": "CVE-2014-125087",
            "base_tag": "v1.0",
            "head_tag": "v1.1",
            "expected": "should_find",
            "description": "XMLBuilder2引入但无XXE防护"
        }
    ]
    
    results = []
    for test_case in test_cases:
        result = test_cve_scenario(
            test_case["cve_id"],
            test_case["base_tag"],
            test_case["head_tag"],
            test_case["expected"]
        )
        results.append({
            "cve": test_case["cve_id"],
            "version": f"{test_case['base_tag']}→{test_case['head_tag']}",
            "expected": test_case["expected"],
            "passed": result
        })
    
    # 输出测试总结
    print(f"\n{'#'*100}")
    print("# 测试总结")
    print(f"{'#'*100}")
    
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    
    for r in results:
        status = "✅ 通过" if r["passed"] else "❌ 失败"
        print(f"{status} | {r['cve']} | {r['version']} | {'找到' if r['expected']=='should_find' else '未找到'}")
    
    print(f"\n总计: {passed}/{total} 通过")
    print(f"{'#'*100}\n")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
