#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试脚本 - 验证对比特征提取系统在特定CVE上的效果
Test Script - Validate Contrastive Feature Extraction System on Specific CVEs

测试目标：
1. cve-2023-51080: 5.8.21到5.8.22 - 应该找到intro commit
2. cve-2014-3625: 3.0.3到3.0.4 - 应该找到intro commit
3. CVE-2014-0097: 3.0.8到3.1.0 - 应该找到intro commit
4. CVE-2014-125087: 1.0到1.1 - 应该不存在intro commit
"""

import json
import os
import sys

# 添加llm.py的路径
sys.path.insert(0, '/home/xinweimao/alv_evaluate/myResearch/workspace/code/llmszz-replication-package1')

from llm import Client
from security_features import (
    is_security_sensitive_code,
    get_security_score,
    SECURITY_PATTERNS,
    get_security_features_by_category
)
from contrastive_inference_engine import ContrastiveInferenceEngine


# ============================================================================
# 配置
# ============================================================================
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
PATCH_RESULTS_PATH = os.path.join(BASE_PATH, "result/patch_only_results.json")
COMMIT_CONTEXT_DIR = os.path.join(BASE_PATH, "commit_context")
INTRO_CONTEXT_PATH = os.path.join(BASE_PATH, "intro_context.json")

# 测试配置
MAX_LLM_CALLS_PER_CVE = 5
RULE_LAYER_THRESHOLD = 0.05
FINAL_SCORE_THRESHOLD = 0.30


# ============================================================================
# 数据加载函数（从intro_infer_v6_contrastive.py复制）
# ============================================================================

def load_cve_list():
    with open(CVE_LIST_PATH, 'r') as f:
        return json.load(f)


def load_patch_results(cve_id):
    try:
        with open(PATCH_RESULTS_PATH, 'r') as f:
            patch_data = json.load(f)

        cve_key = cve_id.upper()
        if cve_key not in patch_data:
            cve_key = cve_id.lower()

        if cve_key not in patch_data:
            return {}

        fix_files = {}
        for version_pair in patch_data[cve_key]:
            analysis = version_pair.get("analysis", {})
            for commit_hash, files in analysis.items():
                for file_path, result in files.items():
                    if result.get("verdict") == "yes":
                        if commit_hash not in fix_files:
                            fix_files[commit_hash] = []
                        fix_files[commit_hash].append({
                            "file": file_path,
                            "score": result.get("score", 0)
                        })

        return fix_files
    except Exception as e:
        print(f"⚠️  加载patch_results失败 {cve_id}: {e}")
        return {}


def load_fix_code_context(cve_id, fix_commits_files):
    try:
        context_file = os.path.join(COMMIT_CONTEXT_DIR, f"{cve_id.lower()}.json")
        with open(context_file, 'r') as f:
            context_data = json.load(f)

        security_measures = {}
        security_patterns = []
        all_added_content = []

        for version_pair in context_data.get(cve_id.lower(), []):
            results = version_pair.get("results", {})

            for commit_hash in fix_commits_files.keys():
                if commit_hash in results:
                    commit_files = results[commit_hash]
                    for file_path, file_context in commit_files.items():
                        added_content = file_context.get("modified_added_content", [])

                        if file_path not in security_measures:
                            security_measures[file_path] = {"added": []}

                        security_measures[file_path]["added"].extend(added_content)
                        all_added_content.extend(added_content)

        # 识别安全模式
        for pattern_name, pattern_list in SECURITY_PATTERNS.items():
            for pattern in pattern_list:
                for content in all_added_content:
                    if pattern.lower() in content.lower():
                        security_patterns.append(f"{pattern_name}:{pattern}")
                        break

        return security_measures, list(set(security_patterns))

    except Exception as e:
        print(f"⚠️  加载fix context失败 {cve_id}: {e}")
        return {}, []


def load_intro_context(cve_id):
    try:
        with open(INTRO_CONTEXT_PATH, 'r') as f:
            intro_data = json.load(f)

        cve_key = cve_id.upper()
        if cve_key not in intro_data:
            cve_key = cve_id.lower()

        if cve_key not in intro_data:
            return {}

        intro_commits = {}
        for version_pair in intro_data[cve_key]:
            results = version_pair.get("results", {})
            for commit_hash, commit_info in results.items():
                intro_commits[commit_hash] = commit_info

        return intro_commits
    except Exception as e:
        print(f"⚠️  加载intro context失败 {cve_id}: {e}")
        return {}


def generate_candidates(intro_commits, fix_commits):
    candidates = []

    for commit_hash, commit_info in intro_commits.items():
        if commit_hash in fix_commits:
            continue

        code_content = ""
        added_lines = []
        for file_path, file_context in commit_info.items():
            if isinstance(file_context, dict):
                added = file_context.get("modified_added_content", [])
                added_lines.extend(added)
                code_content += "\n".join(added)

        candidate = {
            "hash": commit_hash,
            "code": code_content,
            "added_lines": added_lines
        }
        candidates.append(candidate)

    return candidates


# ============================================================================
# LLM调用函数
# ============================================================================

def call_llm(client, prompt):
    """调用LLM"""
    messages = [{"role": "user", "content": prompt}]
    logs = []

    try:
        response = client.call_llm(messages, logs)
        return response
    except Exception as e:
        print(f"  ❌ LLM调用失败: {e}")
        return None


def parse_llm_response(response):
    """解析LLM响应"""
    if not response:
        return {
            "is_intro_commit": False,
            "confidence": 0.5,
            "reasoning": "LLM调用失败",
            "missing_features": [],
            "risk_assessment": "未知"
        }

    try:
        # 尝试提取JSON部分
        import re
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        else:
            return {
                "is_intro_commit": False,
                "confidence": 0.5,
                "reasoning": response[:200],
                "missing_features": [],
                "risk_assessment": "未知"
            }
    except Exception as e:
        print(f"  ⚠️  解析LLM响应失败: {e}")
        return {
            "is_intro_commit": False,
            "confidence": 0.5,
            "reasoning": "解析失败",
            "missing_features": [],
            "risk_assessment": "未知"
        }


# ============================================================================
# 测试单个CVE
# ============================================================================

def test_single_cve(cve_id, base_tag, head_tag, expected_result, llm_client, engine):
    """
    测试单个CVE

    Args:
        cve_id: CVE编号
        base_tag: 起始版本
        head_tag: 结束版本
        expected_result: 预期结果 ("should_find" 或 "should_not_find")
        llm_client: LLM客户端
        engine: 推理引擎

    Returns:
        (是否正确, 详细结果)
    """
    print(f"\n{'='*100}")
    print(f"测试 {cve_id}: {base_tag} → {head_tag}")
    print(f"预期结果: {'✅ 应该找到intro commit' if expected_result == 'should_find' else '❌ 不应该找到intro commit'}")
    print(f"{'='*100}")

    # 加载数据
    fix_commits = load_patch_results(cve_id)
    if not fix_commits:
        print("⚠️  未找到修复commits")
        return (expected_result == "should_not_find", {"reason": "no_fix_commits"})

    print(f"步骤2: 找到 {len(fix_commits)} 个修复commit")

    # 分析修复代码
    security_measures, security_patterns = load_fix_code_context(cve_id, fix_commits)
    if not security_measures:
        print("⚠️  未找到修复代码上下文")
        return (expected_result == "should_not_find", {"reason": "no_fix_context"})

    print(f"步骤3: 提取 {len(security_patterns)} 个安全模式")

    # 提取修复特征
    all_added = []
    for file_path, measures in security_measures.items():
        all_added.extend(measures.get("added", []))

    patch_diff = "\n".join(all_added)
    fix_features = engine.extract_fix_features(patch_diff)

    print(f"修复代码特征: {list(fix_features.keys())}")

    # 加载候选commits
    intro_commits = load_intro_context(cve_id)
    if not intro_commits:
        print("⚠️  未找到候选commits")
        return (expected_result == "should_not_find", {"reason": "no_intro_commits"})

    # 生成候选
    candidates = generate_candidates(intro_commits, fix_commits)
    if not candidates:
        print("⚠️  未找到候选commits")
        return (expected_result == "should_not_find", {"reason": "no_candidates"})

    print(f"步骤6: 筛选出 {len(candidates)} 个候选commits")

    # 规则层过滤
    fix_keywords = [kw for kw in get_security_features_by_category("path").values()]
    fix_keywords.extend([kw for kw in get_security_features_by_category("auth").values()])
    fix_patterns = fix_features.get("security_patterns", [])

    filtered = engine.filter_candidates_by_rules(
        candidates,
        fix_patterns,
        [item for sublist in fix_keywords for item in sublist]
    )

    print(f"步骤7: 规则层过滤后剩余 {len(filtered)} 个候选")

    if not filtered:
        print("❌ 规则层过滤后无候选")
        return (expected_result == "should_not_find", {"reason": "no_filtered_candidates"})

    # LLM层分析
    vulnerability_desc = f"CVE {cve_id} in version {base_tag} to {head_tag}"
    analyzed = []

    for i, candidate in enumerate(filtered[:MAX_LLM_CALLS_PER_CVE]):
        prompt = engine.generate_contrastive_analysis_prompt(
            candidate.get("code", ""),
            fix_features,
            vulnerability_desc
        )

        print(f"\n  🔍 分析候选 {i+1}/{min(len(filtered), MAX_LLM_CALLS_PER_CVE)}: {candidate['hash'][:12]}")

        response = call_llm(llm_client, prompt)
        llm_result = parse_llm_response(response)

        candidate["llm_analysis"] = llm_result

        # 计算最终分数
        llm_conf = llm_result.get("confidence", 0.5)
        rule_score = candidate.get("rule_score", 0.5)
        candidate["final_score"] = 0.4 * rule_score + 0.6 * llm_conf

        # 打印结果
        is_intro = candidate["final_score"] >= FINAL_SCORE_THRESHOLD
        symbol = "⭐" if is_intro else "-"
        print(f"    {symbol} {candidate['hash'][:12]}: score={candidate['final_score']:.2%}, LLM confidence={llm_conf:.2%}")
        print(f"       Reasoning: {llm_result.get('reasoning', 'N/A')[:100]}")

        analyzed.append(candidate)

    # 判断是否找到intro commit
    found_intro = any(c["final_score"] >= FINAL_SCORE_THRESHOLD for c in analyzed)

    result = {
        "found_intro": found_intro,
        "candidates_analyzed": len(analyzed),
        "top_candidate": analyzed[0] if analyzed else None
    }

    # 验证结果
    if expected_result == "should_find":
        if found_intro:
            print(f"\n✅ 测试通过: 成功找到intro commit")
            return (True, result)
        else:
            print(f"\n❌ 测试失败: 应该找到但未找到intro commit")
            return (False, result)
    else:  # should_not_find
        if not found_intro:
            print(f"\n✅ 测试通过: 正确识别为无intro commit")
            return (True, result)
        else:
            print(f"\n❌ 测试失败: 不应该找到但找到了intro commit")
            return (False, result)


# ============================================================================
# 主测试函数
# ============================================================================

def main():
    print("\n" + "#"*100)
    print("# 对比特征提取系统 - 特定CVE测试")
    print("# Test Contrastive Feature Extraction on Specific CVEs")
    print("#"*100 + "\n")

    # 初始化LLM客户端和推理引擎
    print("初始化LLM客户端...")
    llm_client = Client()
    engine = ContrastiveInferenceEngine()
    print("✓ 初始化完成\n")

    # 测试用例
    test_cases = [
        {
            "cve_id": "CVE-2023-51080",
            "base_tag": "5.8.21",
            "head_tag": "5.8.22",
            "expected": "should_find",
            "description": "Apache Commons Text路径遍历漏洞"
        },
        {
            "cve_id": "CVE-2014-3625",
            "base_tag": "3.0.3.RELEASE",
            "head_tag": "3.0.4.RELEASE",
            "expected": "should_find",
            "description": "Spring Security路径遍历漏洞"
        },
        {
            "cve_id": "CVE-2014-0097",
            "base_tag": "3.0.8.RELEASE",
            "head_tag": "3.1.0.RELEASE",
            "expected": "should_find",
            "description": "Spring Security LDAP认证绕过"
        },
        {
            "cve_id": "CVE-2014-125087",
            "base_tag": "v1.0",
            "head_tag": "v1.1",
            "expected": "should_not_find",
            "description": "应该不存在intro commit"
        }
    ]

    # 执行测试
    results = []
    for test_case in test_cases:
        is_correct, detail = test_single_cve(
            test_case["cve_id"],
            test_case["base_tag"],
            test_case["head_tag"],
            test_case["expected"],
            llm_client,
            engine
        )

        results.append({
            "cve_id": test_case["cve_id"],
            "description": test_case["description"],
            "expected": test_case["expected"],
            "is_correct": is_correct,
            "detail": detail
        })

    # 打印测试总结
    print("\n" + "#"*100)
    print("# 测试总结")
    print("#"*100)

    correct_count = sum(1 for r in results if r["is_correct"])
    total_count = len(results)

    for r in results:
        status = "✅ 通过" if r["is_correct"] else "❌ 失败"
        expected_str = "应找到" if r["expected"] == "should_find" else "不应找到"
        print(f"{status} | {r['cve_id']} | {r['description']} | {expected_str}")

    print(f"\n{'='*100}")
    print(f"测试结果: {correct_count}/{total_count} 通过")
    print(f"准确率: {correct_count/total_count*100:.1f}%")
    print(f"{'='*100}\n")

    # LLM调用统计
    print(f"LLM调用次数: {llm_client.get_call_cnt()}")


if __name__ == "__main__":
    main()
