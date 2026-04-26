#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞引入Commit推理系统 - 改进版（结合修复commit特征）
Vulnerability Introductory Commit Inference - Improved Version

核心改进：
1. 只有当修复补丁有明确安全特征时，才进行对比分析
2. 无安全特征时，降低置信度或跳过
3. 在完整数据集intro_context.json上运行
"""

import json
import os
import sys
import re
import time
from datetime import datetime

# 添加llm.py的路径
sys.path.insert(0, '/home/xinweimao/alv_evaluate/myResearch/workspace/code')

from llm import Client
from security_features import get_security_features_by_category, SECURITY_PATTERNS
from contrastive_inference_engine import ContrastiveInferenceEngine


# ============================================================================
# 配置
# ============================================================================
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
PATCH_RESULTS_PATH = os.path.join(BASE_PATH, "result/patch_only_results.json")
COMMIT_CONTEXT_DIR = os.path.join(BASE_PATH, "commit_context")
INTRO_CONTEXT_PATH = os.path.join(BASE_PATH, "intro_context.json")
OUTPUT_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_v6_improved.json")

# 系统配置
USE_LLM_CONFIRMATION = True
MAX_LLM_CALLS_PER_CVE = 5
RULE_LAYER_THRESHOLD = 0.01

# 改进的阈值配置
FINAL_SCORE_THRESHOLD_WITH_FEATURES = 0.30    # 有安全特征时的阈值
FINAL_SCORE_THRESHOLD_WITHOUT_FEATURES = 0.40  # 无安全特征时的阈值（调整为0.40以提升召回率）
MIN_FIX_FEATURES_COUNT = 1                     # 最少需要的安全特征数量


# ============================================================================
# 数据加载函数
# ============================================================================

def load_intro_context():
    """加载intro_context.json"""
    with open(INTRO_CONTEXT_PATH, 'r') as f:
        return json.load(f)


def load_patch_results(cve_id):
    """加载修复commits"""
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
        return {}


def load_fix_code_context(cve_id, fix_commits_files):
    """从commit_context加载修复代码的安全措施"""
    try:
        context_file = os.path.join(COMMIT_CONTEXT_DIR, f"{cve_id.lower()}.json")
        with open(context_file, 'r') as f:
            context_data = json.load(f)

        security_measures = {}
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
        security_patterns = []
        for pattern_name, pattern_list in SECURITY_PATTERNS.items():
            for pattern in pattern_list:
                for content in all_added_content:
                    if pattern.lower() in content.lower():
                        security_patterns.append(f"{pattern_name}:{pattern}")
                        break

        return security_measures, list(set(security_patterns))

    except Exception as e:
        return {}, []


def load_intro_candidates(cve_id, base_tag):
    """从intro_context.json加载候选漏洞引入commit"""
    try:
        with open(INTRO_CONTEXT_PATH, 'r') as f:
            intro_data = json.load(f)

        cve_key = cve_id.upper()
        if cve_key not in intro_data:
            cve_key = cve_id.lower()

        if cve_key not in intro_data:
            return {}

        # 查找匹配base_tag的版本
        for version_pair in intro_data[cve_key]:
            if version_pair.get("base_tag") == base_tag:
                results = version_pair.get("results", {})
                return results

        return {}

    except Exception as e:
        return {}


def generate_candidates_from_intro(intro_commits, fix_commits):
    """从intro_context生成候选commits"""
    candidates = []

    for commit_hash, commit_data in intro_commits.items():
        # 排除修复commit本身
        if commit_hash in fix_commits:
            continue

        # 从files字段提取代码内容
        files = commit_data.get("files", {})
        added_lines = []
        deleted_lines = []  # 新增
        
        for file_path, file_context in files.items():
            if isinstance(file_context, dict):
                added = file_context.get("modified_added_content", [])
                added_lines.extend(added)
                # 提取删除的代码（新增）
                deleted = file_context.get("modified_deleted_content", [])
                deleted_lines.extend(deleted)

        code_content = "\n".join(added_lines)

        candidate = {
            "hash": commit_hash,
            "code": code_content,
            "added_lines": added_lines,
            "deleted_lines": deleted_lines,  # 新增
            "message": commit_data.get("message", "")
        }
        candidates.append(candidate)

    return candidates


# ============================================================================
# LLM调用函数
# ============================================================================

def call_llm(client, prompt):
    """调用LLM (gpt-5-mini)"""
    try:
        response = client.call_llm(prompt)
        if response == "STOP_SIGNAL":
            return None
        return response
    except Exception as e:
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
        return {
            "is_intro_commit": False,
            "confidence": 0.5,
            "reasoning": "解析失败",
            "missing_features": [],
            "risk_assessment": "未知"
        }


# ============================================================================
# 核心推理逻辑（改进版）
# ============================================================================

def has_meaningful_fix_features(fix_features):
    """
    判断修复补丁是否有意义的安全特征
    
    返回: (是否有意义, 特征数量)
    """
    if not fix_features:
        return False, 0
    
    feature_count = 0
    
    # 检查各类安全特征
    if fix_features.get("security_patterns"):
        feature_count += len(fix_features["security_patterns"])
    
    if fix_features.get("added_safety_checks"):
        feature_count += len(fix_features["added_safety_checks"])
    
    if fix_features.get("sanitization_methods"):
        feature_count += len(fix_features["sanitization_methods"])
    
    if fix_features.get("validation_functions"):
        feature_count += len(fix_features["validation_functions"])
    
    return feature_count >= MIN_FIX_FEATURES_COUNT, feature_count


def analyze_candidate_with_adaptive_threshold(
    candidate,
    fix_features,
    has_features,
    vulnerability_desc,
    llm_client,
    engine
):
    """
    自适应阈值分析候选commit
    
    核心改进：
    - 有安全特征：使用较低阈值（0.30），LLM基于对比分析
    - 无安全特征：使用较高阈值（0.65），减少误报
    """
    prompt = engine.generate_contrastive_analysis_prompt(
        candidate.get("code", ""),
        fix_features if fix_features else {
            "security_patterns": [],
            "added_safety_checks": [],
            "sanitization_methods": [],
            "validation_functions": []
        },
        vulnerability_desc
    )

    response = call_llm(llm_client, prompt)
    llm_result = parse_llm_response(response)

    # 计算最终分数
    llm_conf = llm_result.get("confidence", 0.5)
    rule_score = candidate.get("rule_score", 0.5)
    
    if has_features:
        # 有安全特征：LLM权重更高
        final_score = 0.3 * rule_score + 0.7 * llm_conf
        threshold = FINAL_SCORE_THRESHOLD_WITH_FEATURES
    else:
        # 无安全特征：提高阈值，减少误报
        final_score = 0.4 * rule_score + 0.6 * llm_conf
        threshold = FINAL_SCORE_THRESHOLD_WITHOUT_FEATURES

    return {
        "final_score": final_score,
        "threshold": threshold,
        "llm_confidence": llm_conf,
        "rule_score": rule_score,
        "llm_analysis": llm_result,
        "has_fix_features": has_features
    }


def process_single_cve(cve_id, base_tag, head_tag, llm_client, engine, intro_candidates=None):
    """处理单个CVE
    
    Args:
        cve_id: CVE ID
        base_tag: 基础版本标签
        head_tag: 目标版本标签
        llm_client: LLM客户端
        engine: 对比推理引擎
        intro_candidates: 可选的候选intro commits，如果为None则从文件加载
    """
    
    # 步骤1: 加载修复commits
    fix_commits = load_patch_results(cve_id)
    if not fix_commits:
        return "skipped", {}, "no_fix_commits"

    # 步骤2: 分析修复代码，提取安全模式
    security_measures, security_patterns = load_fix_code_context(cve_id, fix_commits)
    
    if not security_measures:
        fix_features = {}
    else:
        # 提取修复特征
        all_added = []
        for file_path, measures in security_measures.items():
            all_added.extend(measures.get("added", []))

        patch_diff = "\n".join(all_added)
        fix_features = engine.extract_fix_features(patch_diff)

    # 判断是否有意义的安全特征
    has_features, feature_count = has_meaningful_fix_features(fix_features)

    # 步骤3: 加载候选intro commits
    if intro_candidates is None:
        intro_commits = load_intro_candidates(cve_id, base_tag)
    else:
        intro_commits = intro_candidates
    
    if not intro_commits:
        return "skipped", {}, "no_intro_candidates"

    # 步骤4: 生成候选列表
    candidates = generate_candidates_from_intro(intro_commits, fix_commits)
    if not candidates:
        return "skipped", {}, "no_candidates"

    # 步骤5: 规则层过滤
    fix_keywords = [kw for kw in get_security_features_by_category("path").values()]
    fix_keywords.extend([kw for kw in get_security_features_by_category("auth").values()])
    fix_patterns = fix_features.get("security_patterns", []) if fix_features else []

    filtered = engine.filter_candidates_by_rules(
        candidates,
        fix_patterns,
        [item for sublist in fix_keywords for item in sublist]
    )

    if not filtered:
        return "no_intro", {}, "no_filtered_candidates"

    # 步骤6: LLM层分析
    vulnerability_desc = f"CVE {cve_id} in version {base_tag} to {head_tag}"
    analyzed = []

    for i, candidate in enumerate(filtered[:MAX_LLM_CALLS_PER_CVE]):
        result = analyze_candidate_with_adaptive_threshold(
            candidate,
            fix_features,
            has_features,
            vulnerability_desc,
            llm_client,
            engine
        )

        candidate.update(result)
        analyzed.append(candidate)

        # 如果LLM调用失败（余额不足），停止
        if result["llm_confidence"] == 0.5 and result["llm_analysis"]["reasoning"] == "LLM调用失败":
            break

    # 判断是否找到intro commit
    intro_commits_found = []
    for candidate in analyzed:
        if candidate["final_score"] >= candidate["threshold"]:
            intro_commits_found.append({
                "hash": candidate["hash"],
                "confidence": candidate["final_score"],
                "method": "contrastive_inference_v6_improved",
                "has_fix_features": candidate["has_fix_features"],
                "feature_count": feature_count
            })

    if intro_commits_found:
        return "found_intro", {"intro_commits": intro_commits_found}, ""
    else:
        return "no_intro", {}, ""


# ============================================================================
# 主函数
# ============================================================================

def main():
    print("\n" + "#"*100)
    print("# 漏洞引入Commit推理系统 - 改进版")
    print("# 结合修复commit特征，自适应阈值判断")
    print("# 直接遍历 intro_context.json")
    print("#"*100 + "\n")

    # 初始化
    print("初始化LLM客户端...")
    try:
        llm_client = Client()
        engine = ContrastiveInferenceEngine()
        print("✓ 初始化完成\n")
    except Exception as e:
        print(f"❌ 初始化失败: {e}")
        return

    # 加载intro_context数据
    print("加载intro_context.json...")
    intro_data = load_intro_context()
    print(f"✓ 共 {len(intro_data)} 个CVE\n")

    # 处理所有CVE
    output_data = {}
    stats = {
        "total_cves": 0,
        "total_version_pairs": 0,
        "found_intro": 0,
        "no_intro": 0,
        "skipped": 0,
        "with_features": 0,
        "without_features": 0
    }

    start_time = time.time()

    for cve_id, version_list in intro_data.items():
        stats["total_cves"] += 1
        
        print(f"\r处理 {stats['total_cves']}/{len(intro_data)}: {cve_id} ({len(version_list)}个版本区间)", end="", flush=True)

        # 处理所有版本区间
        cve_results = []
        
        for version_info in version_list:
            stats["total_version_pairs"] += 1
            base_tag = version_info.get("base_tag", "")
            head_tag = version_info.get("head_tag", "")
            intro_candidates = version_info.get("results", {})
            
            # 处理单个版本区间
            status, cve_analysis, skip_reason = process_single_cve(
                cve_id, base_tag, head_tag, llm_client, engine, intro_candidates
            )
            
            # 保存结果
            output_entry = {
                "base_tag": base_tag,
                "head_tag": head_tag,
                "analysis": cve_analysis
            }

            if status == "skipped":
                stats["skipped"] += 1
                output_entry["note"] = f"skipped: {skip_reason}"
            elif status == "found_intro":
                stats["found_intro"] += 1
                # 统计是否有安全特征
                if cve_analysis.get("intro_commits", []):
                    if cve_analysis["intro_commits"][0].get("has_fix_features"):
                        stats["with_features"] += 1
                    else:
                        stats["without_features"] += 1
            else:
                stats["no_intro"] += 1
                output_entry["note"] = "no_intro_commit_found"
            
            cve_results.append(output_entry)
        
        output_data[cve_id] = cve_results

    # 保存结果
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    elapsed = time.time() - start_time

    # 打印统计
    print(f"\n\n{'#'*100}")
    print(f"✅ 处理完成！")
    print(f"   总计CVE: {stats['total_cves']} 个")
    print(f"   总计版本区间: {stats['total_version_pairs']} 个")
    print(f"   找到intro commit: {stats['found_intro']} 个版本区间")
    print(f"     - 有安全特征: {stats['with_features']} 个")
    print(f"     - 无安全特征: {stats['without_features']} 个")
    print(f"   未找到intro commit: {stats['no_intro']} 个版本区间")
    print(f"   跳过: {stats['skipped']} 个版本区间")
    print(f"   耗时: {elapsed/60:.1f} 分钟")
    print(f"   结果已保存到: {OUTPUT_PATH}")
    print(f"{'#'*100}\n")


def evaluate_with_llm():
    """使用LLM评估规则层 + LLM层性能"""
    import pandas as pd
    from collections import defaultdict
    
    print("\n" + "="*100)
    print("LLM评估 - 规则层 + LLM层")
    print("="*100)
    
    # 加载cve_list.json
    cve_list_path = os.path.join(BASE_PATH, "list/cve_list.json")
    print("\n[1/5] 加载cve_list.json...")
    with open(cve_list_path, 'r') as f:
        cve_data = json.load(f)
    print(f"✓ 共 {len(cve_data)} 个CVE")
    
    # 加载真值
    excel_path = os.path.join(BASE_PATH, "execution_result.xlsx")
    print("\n[2/5] 加载真值数据...")
    df = pd.read_excel(excel_path)
    
    # 构建ground_truth: {cve_id: {version: affected}}
    ground_truth = defaultdict(dict)
    for _, row in df.iterrows():
        cve_id = str(row.get('CVE_ID', '')).lower().strip()
        version = str(row.get('Version', '')).strip()
        true_affected = str(row.get('True Affected Version', '')).strip()
        
        if cve_id and version:
            affected = (true_affected.lower() == 'affected')
            ground_truth[cve_id][version] = affected
    
    print(f"✓ 共 {len(ground_truth)} 个CVE有真值数据")
    
    # 加载intro_context
    print("\n[3/5] 加载intro_context数据...")
    intro_data = load_intro_context()
    print(f"✓ 共 {len(intro_data)} 个CVE")
    
    # 初始化LLM客户端
    print("\n[4/5] 初始化LLM客户端...")
    llm_client = Client()
    engine = ContrastiveInferenceEngine()
    print("✓ 初始化完成")
    
    # 评估函数
    def run_evaluation(use_llm=True, max_llm_calls=100, test_mode=True):
        results = {
            'total': 0,
            'true_positive': 0,
            'true_negative': 0,
            'false_positive': 0,
            'false_negative': 0,
            'llm_calls': 0,
            'details': []  # 添加详细信息
        }
        
        # 测试模式：只测试指定的CVE和版本对
        test_cases = {
            'cve-2023-51080': [('5.8.21', '5.8.22')],
            'cve-2014-3625': [('v3.0.3.RELEASE', 'v3.0.4.RELEASE')],
            'cve-2014-0097': [('3.0.8.RELEASE', '3.1.0.RELEASE')],
            'cve-2014-125087': [('v1.0', 'v1.1')]
        }
        
        # 去重：记录已处理的版本对
        processed_pairs = set()
        
        for cve_id_upper, cve_info in cve_data.items():
            cve_id = cve_id_upper.lower()
            
            # 测试模式：只处理指定的CVE
            if test_mode and cve_id not in test_cases:
                continue
            
            # 检查是否在intro_context和ground_truth中
            if cve_id not in intro_data:
                continue
            if cve_id not in ground_truth:
                continue
            
            # 加载修复commits
            fix_commits = load_patch_results(cve_id)
            if not fix_commits:
                continue
            
            # 分析修复特征
            security_measures, security_patterns = load_fix_code_context(cve_id, fix_commits)
            if security_measures:
                all_added = []
                for file_path, measures in security_measures.items():
                    all_added.extend(measures.get("added", []))
                patch_diff = "\n".join(all_added)
                fix_features = engine.extract_fix_features(patch_diff)
                has_features, _ = has_meaningful_fix_features(fix_features)
            else:
                fix_features = {}
                has_features = False
            
            # 遍历版本对
            for vp in cve_info.get('version_pair', []):
                appears = vp.get('appears', '')
                not_appears = vp.get('not appears', '')
                base_tag = vp.get('BASE_TAG', '')
                head_tag = vp.get('HEAD_TAG', '')
                
                if not not_appears or not base_tag:
                    continue
                
                # 去重：跳过已处理的版本对
                pair_key = (cve_id, base_tag, head_tag)
                if pair_key in processed_pairs:
                    continue
                processed_pairs.add(pair_key)
                
                # 测试模式：只测试指定的版本对
                if test_mode and cve_id in test_cases:
                    if (base_tag, head_tag) not in test_cases[cve_id]:
                        continue
                
                # 直接使用not_appears字段匹配真值
                if not_appears not in ground_truth[cve_id]:
                    continue
                
                results['total'] += 1
                
                # 获取真值
                actual_affected = ground_truth[cve_id][not_appears]
                actual_not_affected = not actual_affected
                
                # 从intro_context获取候选commits
                intro_version_list = intro_data[cve_id]
                intro_candidates = None
                
                for version_info in intro_version_list:
                    if version_info.get('base_tag') == base_tag:
                        intro_candidates = version_info.get('results', {})
                        break
                
                if not intro_candidates:
                    continue
                
                # 生成候选列表
                candidates = generate_candidates_from_intro(intro_candidates, fix_commits)
                
                # 规则层筛选
                fix_keywords = [kw for kw in get_security_features_by_category("path").values()]
                fix_keywords.extend([kw for kw in get_security_features_by_category("auth").values()])
                fix_patterns = fix_features.get("security_patterns", []) if fix_features else []
                
                filtered = engine.filter_candidates_by_rules(
                    candidates,
                    fix_patterns,
                    [item for sublist in fix_keywords for item in sublist]
                )
                
                # LLM层评估
                if use_llm and filtered and results['llm_calls'] < max_llm_calls:
                    # 选择分数最高的候选进行LLM分析
                    best_candidate = max(filtered, key=lambda x: x.get('rule_score', 0))
                    max_score = best_candidate.get('rule_score', 0)  # 记录规则分数
                    
                    # 调用LLM
                    vulnerability_desc = f"CVE {cve_id} vulnerability analysis"
                    llm_result = analyze_candidate_with_adaptive_threshold(
                        best_candidate,
                        fix_features,
                        has_features,
                        vulnerability_desc,
                        llm_client,
                        engine
                    )
                    
                    results['llm_calls'] += 1
                    
                    # 使用LLM结果判断
                    final_score = llm_result['final_score']
                    threshold = llm_result['threshold']  # 使用自适应阈值
                    predicted_has_intro = final_score >= threshold
                else:
                    # 仅使用规则层
                    if filtered:
                        max_score = max(c.get('rule_score', 0) for c in filtered)
                        predicted_has_intro = max_score >= 0.05
                    else:
                        predicted_has_intro = False
                
                # 判断结果
                if predicted_has_intro and actual_not_affected:
                    results['true_positive'] += 1
                    status = 'TP'
                elif not predicted_has_intro and not actual_not_affected:
                    results['true_negative'] += 1
                    status = 'TN'
                elif predicted_has_intro and not actual_not_affected:
                    results['false_positive'] += 1
                    status = 'FP'
                else:
                    results['false_negative'] += 1
                    status = 'FN'
                
                # 记录详细信息
                detail = {
                    'cve_id': cve_id,
                    'base_tag': base_tag,
                    'head_tag': head_tag,
                    'not_appears': not_appears,
                    'actual_affected': actual_affected,
                    'actual_not_affected': actual_not_affected,
                    'predicted_has_intro': predicted_has_intro,
                    'status': status,
                    'rule_score': max_score if 'max_score' in locals() else 0
                }
                
                if use_llm and filtered and results['llm_calls'] > 0:
                    detail['final_score'] = final_score
                    detail['llm_confidence'] = llm_result.get('llm_confidence', 0)
                    detail['threshold'] = threshold
                
                results['details'].append(detail)
                
                # 测试模式：打印详细信息
                if test_mode:
                    print(f"\n  [{cve_id}] {base_tag} -> {head_tag}")
                    print(f"    not_appears: {not_appears}")
                    print(f"    实际状态: {'Not Affected' if actual_not_affected else 'Affected'}")
                    print(f"    预测结果: {'Has Intro' if predicted_has_intro else 'No Intro'}")
                    print(f"    判定: {status}")
                    if use_llm and 'final_score' in detail:
                        print(f"    规则分数: {detail['rule_score']:.4f}")
                        print(f"    LLM置信度: {detail['llm_confidence']:.4f}")
                        print(f"    阈值: {detail['threshold']:.2f}")
                        print(f"    最终分数: {detail['final_score']:.4f}")
                    else:
                        print(f"    规则分数: {detail['rule_score']:.4f}")
        
        return results
    
    # 打印混淆矩阵
    def print_results(results, title):
        tp = results['true_positive']
        tn = results['true_negative']
        fp = results['false_positive']
        fn = results['false_negative']
        total = results['total']
        
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\n" + "="*100)
        print(title)
        print("="*100)
        
        print(f"\n总样本数: {total}")
        print(f"LLM调用次数: {results.get('llm_calls', 0)}")
        
        print("\n混淆矩阵 (Confusion Matrix):")
        print("                        实际: Not Affected    实际: Affected")
        print(f"预测: Has Intro         TP = {tp:>3d}              FP = {fp:>3d}")
        print(f"预测: No Intro          FN = {fn:>3d}              TN = {tn:>3d}")
        
        print("\n性能指标:")
        print(f"  准确率 (Accuracy):  {tp+tn}/{total} = {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  精确率 (Precision): {tp}/{tp+fp} = {precision:.4f} ({precision*100:.2f}%)")
        print(f"  召回率 (Recall):    {tp}/{tp+fn} = {recall:.4f} ({recall*100:.2f}%)")
        print(f"  F1分数:             {f1:.4f}")
        print("="*100)
        
        return {'accuracy': accuracy, 'precision': precision, 'recall': recall, 'f1': f1}
    
    # 仅规则层评估
    print("\n[5/5] 评估中...")
    print("\n--- 规则层评估 (全数据集) ---")
    rule_results = run_evaluation(use_llm=False, test_mode=False)
    rule_metrics = print_results(rule_results, "仅规则层评估结果")
    
    # 规则层 + LLM层评估
    print("\n--- 规则层 + LLM层评估 (全数据集) ---")
    llm_results = run_evaluation(use_llm=True, max_llm_calls=100, test_mode=False)
    llm_metrics = print_results(llm_results, "规则层 + LLM层评估结果")
    
    # 对比
    print("\n" + "="*100)
    print("性能对比")
    print("="*100)
    print(f"\n{'方法':<25} {'准确率':<15} {'精确率':<15} {'召回率':<15} {'F1':<15}")
    print("-" * 100)
    print(f"{'仅规则层':<25} {rule_metrics['accuracy']:<15.4f} {rule_metrics['precision']:<15.4f} {rule_metrics['recall']:<15.4f} {rule_metrics['f1']:<15.4f}")
    print(f"{'规则层 + LLM层':<25} {llm_metrics['accuracy']:<15.4f} {llm_metrics['precision']:<15.4f} {llm_metrics['recall']:<15.4f} {llm_metrics['f1']:<15.4f}")
    print(f"{'提升':<25} {(llm_metrics['accuracy']-rule_metrics['accuracy']):<15.4f} {(llm_metrics['precision']-rule_metrics['precision']):<15.4f} {(llm_metrics['recall']-rule_metrics['recall']):<15.4f} {(llm_metrics['f1']-rule_metrics['f1']):<15.4f}")
    print("="*100)


if __name__ == "__main__":
    # main()  # 原有的main函数
    evaluate_with_llm()  # 新的评估函数
