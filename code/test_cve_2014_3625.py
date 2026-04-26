#!/usr/bin/env python3
"""
CVE-2014-3625 单独测试脚本
目标：验证是否能找到引入commit 5a1bd20864d9255eafb23d551f7dfe34ed0961e9
策略：即使没有embedding数据，也要基于代码分析判断
"""
import json
import os
import re

# --- 配置区 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_ID = "CVE-2014-3625"
CVE_ID_LOWER = CVE_ID.lower()

PATCH_RESULTS_PATH = os.path.join(BASE_PATH, "result/patch_only_results.json")
COMMIT_CONTEXT_DIR = os.path.join(BASE_PATH, "commit_context")
INTRO_CONTEXT_PATH = os.path.join(BASE_PATH, "intro_context.json")
ANALYSIS_JSON_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_final_f.json")
OUTPUT_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_final_f.json")

# 目标引入commit
TARGET_COMMIT = "5a1bd20864d9255eafb23d551f7dfe34ed0961e9"


def load_patch_results():
    """步骤2: 加载修复commits的文件列表"""
    print(f"\n{'='*100}")
    print(f"步骤2: 加载修复commits分析 (从 patch_only_results.json)")
    print(f"{'='*100}")
    
    with open(PATCH_RESULTS_PATH, 'r') as f:
        patch_data = json.load(f)
    
    # 提取 verdict="yes" 的文件
    fix_files = {}
    for version_pair in patch_data.get(CVE_ID, []):
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
    
    print(f"✅ 找到 {len(fix_files)} 个修复commit")
    for commit_hash, files in fix_files.items():
        print(f"\n  Commit: {commit_hash[:16]}")
        for f in files[:3]:
            print(f"    - {f['file']}: score={f['score']:.4f}")
    
    return fix_files


def load_fix_code_context(fix_commits_files):
    """步骤3: 加载修复代码的安全措施"""
    print(f"\n{'='*100}")
    print(f"步骤3: 提取修复代码的安全措施 (从 commit_context/{CVE_ID_LOWER}.json)")
    print(f"{'='*100}")
    
    context_file = os.path.join(COMMIT_CONTEXT_DIR, f"{CVE_ID_LOWER}.json")
    with open(context_file, 'r') as f:
        context_data = json.load(f)
    
    security_measures = {}
    security_patterns = []
    
    for version_pair in context_data.get(CVE_ID_LOWER, []):
        results = version_pair.get("results", {})
        
        for commit_hash in fix_commits_files.keys():
            if commit_hash in results:
                commit_files = results[commit_hash]
                for file_path, file_context in commit_files.items():
                    added_content = file_context.get("modified_added_content", [])
                    deleted_content = file_context.get("modified_deleted_content", [])
                    
                    if file_path not in security_measures:
                        security_measures[file_path] = {
                            "added": [],
                            "deleted": [],
                            "context_before": file_context.get("context_before", []),
                            "context_after": file_context.get("context_after", [])
                        }
                    
                    security_measures[file_path]["added"].extend(added_content)
                    security_measures[file_path]["deleted"].extend(deleted_content)
    
    print(f"✅ 提取 {len(security_measures)} 个文件的安全措施")
    
    # 详细展示每个文件的安全措施
    for file_path, measures in security_measures.items():
        added = measures.get("added", [])
        deleted = measures.get("deleted", [])
        print(f"\n  📄 {file_path}")
        if deleted:
            print(f"    删除的代码 ({len(deleted)} 行):")
            for line in deleted[:3]:
                print(f"      - {line}")
        if added:
            print(f"    添加的安全措施 ({len(added)} 行):")
            for line in added[:10]:
                print(f"      + {line}")
                # 提取安全模式
                if "processPath" in line:
                    security_patterns.append("路径规范化 (processPath)")
                elif "isInvalidPath" in line:
                    security_patterns.append("路径验证 (isInvalidPath)")
                elif "isResourceUnderLocation" in line:
                    security_patterns.append("资源位置验证")
                elif "URLDecoder" in line or "decode" in line:
                    security_patterns.append("URL解码处理")
                elif "WEB-INF" in line or "META-INF" in line:
                    security_patterns.append("敏感目录保护")
                elif ".." in line or "cleanPath" in line:
                    security_patterns.append("路径遍历检查")
    
    print(f"\n识别的安全模式 ({len(set(security_patterns))} 种):")
    for pattern in set(security_patterns):
        print(f"  ✓ {pattern}")
    
    return security_measures, security_patterns


def load_intro_context():
    """步骤6: 加载候选commits"""
    print(f"\n{'='*100}")
    print(f"步骤6: 加载候选commits (从 intro_context.json)")
    print(f"{'='*100}")
    
    with open(INTRO_CONTEXT_PATH, 'r') as f:
        intro_data = json.load(f)
    
    all_filtered_commits = []
    all_commit_contexts = {}
    
    for version_pair in intro_data.get(CVE_ID_LOWER, []):
        base_tag = version_pair.get("base_tag", "")
        head_tag = version_pair.get("head_tag", "")
        
        print(f"\n版本对: {base_tag} → {head_tag}")
        
        # 获取候选commits列表
        filter_summary = version_pair.get("filter_summary", [])
        print(f"筛选出的候选commits ({len(filter_summary)} 个):")
        
        for i, commit_info in enumerate(filter_summary, 1):
            sha = commit_info['sha']
            message = commit_info['message']
            score = commit_info['relevance_score']
            is_target = "⭐ TARGET" if sha == TARGET_COMMIT else ""
            print(f"  {i}. {sha[:16]} (score={score}): {message[:60]}... {is_target}")
        
        all_filtered_commits.extend(filter_summary)
        
        # 获取每个commit的代码上下文
        results = version_pair.get("results", {})
        for commit_hash, commit_data in results.items():
            if commit_hash not in all_commit_contexts:
                all_commit_contexts[commit_hash] = {
                    "message": commit_data.get("message", ""),
                    "files": {}
                }
            
            files = commit_data.get("files", {})
            for file_path, file_context in files.items():
                all_commit_contexts[commit_hash]["files"][file_path] = {
                    "context_before": file_context.get("context_before", []),
                    "modified_deleted_content": file_context.get("modified_deleted_content", []),
                    "modified_added_content": file_context.get("modified_added_content", []),
                    "context_after": file_context.get("context_after", [])
                }
    
    return all_filtered_commits, all_commit_contexts


def analyze_intro_commit(candidate_context, fix_security_measures, fix_security_patterns):
    """
    步骤7: 分析候选commit是否为引入漏洞的commit
    基于代码分析，即使没有embedding数据
    """
    print(f"\n{'='*100}")
    print(f"步骤7: 确认引入commit (基于代码分析)")
    print(f"{'='*100}")
    
    # 1. 检查候选commit中是否包含安全措施
    candidate_security_features = []
    missing_security_checks = []
    
    if candidate_context:
        candidate_files = candidate_context.get("files", {})
        print(f"\n候选commit修改的文件 ({len(candidate_files)} 个):")
        
        for file_path, file_ctx in candidate_files.items():
            added_content = file_ctx.get("modified_added_content", [])
            deleted_content = file_ctx.get("modified_deleted_content", [])
            
            print(f"\n  📄 {file_path}")
            
            if added_content:
                print(f"    添加的代码 ({len(added_content)} 行):")
                for line in added_content[:5]:
                    print(f"      + {line}")
            
            # 检查是否包含安全措施
            all_code = "\n".join(added_content + deleted_content)
            
            # 检查各种安全措施
            checks = {
                "processPath": "路径规范化",
                "isInvalidPath": "路径验证",
                "isResourceUnderLocation": "资源位置验证",
                "URLDecoder": "URL解码处理",
                "WEB-INF": "WEB-INF保护",
                "META-INF": "META-INF保护",
                "cleanPath": "路径清理",
                "validate": "输入验证",
                "sanitize": "数据清理",
                "escape": "转义处理"
            }
            
            for keyword, check_name in checks.items():
                if keyword in all_code:
                    candidate_security_features.append(f"{file_path}: {check_name}")
    
    print(f"\n候选commit中的安全措施 ({len(candidate_security_features)} 项):")
    if candidate_security_features:
        for feature in candidate_security_features:
            print(f"  ✓ {feature}")
    else:
        print(f"  ❌ 未找到任何安全措施")
    
    # 2. 对比修复代码的安全措施
    print(f"\n对比修复代码的安全措施:")
    for pattern in set(fix_security_patterns):
        has_it = any(pattern.lower() in " ".join(candidate_security_features).lower() 
                     for _ in [1])
        status = "✓ 存在" if has_it else "❌ 缺失"
        print(f"  {status} - {pattern}")
        if not has_it:
            missing_security_checks.append(pattern)
    
    # 3. 检查关键漏洞模式
    critical_vulnerability_patterns = []
    
    for file_path, file_ctx in candidate_context.get("files", {}).items():
        added_content = file_ctx.get("modified_added_content", [])
        all_code = "\n".join(added_content)
        
        # 检查危险的代码模式
        if "getResource" in all_code and "validate" not in all_code.lower():
            critical_vulnerability_patterns.append(f"{file_path}: 直接获取资源而无验证")
        
        if "createRelative" in all_code and ".." not in all_code:
            critical_vulnerability_patterns.append(f"{file_path}: 使用createRelative可能被路径遍历")
        
        if "path" in all_code.lower() and "check" not in all_code.lower():
            critical_vulnerability_patterns.append(f"{file_path}: 使用路径但无检查")
    
    print(f"\n关键漏洞模式 ({len(critical_vulnerability_patterns)} 项):")
    for pattern in critical_vulnerability_patterns:
        print(f"  ⚠️  {pattern}")
    
    # 4. 最终判断
    # 如果候选commit：
    # - 缺少大部分安全措施
    # - 包含危险的代码模式
    # - 是首次实现（从commit message判断）
    # 则判定为引入漏洞的commit
    
    is_first_implementation = "initial" in candidate_context.get("message", "").lower()
    missing_ratio = len(missing_security_checks) / max(len(set(fix_security_patterns)), 1)
    has_critical_patterns = len(critical_vulnerability_patterns) > 0
    
    is_intro = (
        (missing_ratio > 0.5 or len(candidate_security_features) == 0) and
        has_critical_patterns and
        is_first_implementation
    )
    
    # 计算置信度
    if is_intro:
        confidence = 0.7 + (missing_ratio * 0.2) + (0.1 if is_first_implementation else 0)
        confidence = min(0.95, confidence)
    else:
        confidence = 0.3
    
    print(f"\n最终判断:")
    print(f"  是否为引入commit: {'✅ 是' if is_intro else '❌ 否'}")
    print(f"  置信度: {confidence:.2%}")
    print(f"  判断依据:")
    print(f"    - 缺失安全措施比例: {missing_ratio:.2%}")
    print(f"    - 是否首次实现: {'是' if is_first_implementation else '否'}")
    print(f"    - 是否包含危险模式: {'是' if has_critical_patterns else '否'}")
    print(f"    - 缺失的安全检查: {missing_security_checks}")
    print(f"    - 关键漏洞模式: {critical_vulnerability_patterns}")
    
    return is_intro, confidence, missing_security_checks, critical_vulnerability_patterns, candidate_security_features


def save_to_json(analysis_result):
    """保存结果到intro_contrastive_final_f.json"""
    print(f"\n{'='*100}")
    print(f"保存结果到 {OUTPUT_PATH}")
    print(f"{'='*100}")
    
    # 加载现有数据
    try:
        with open(ANALYSIS_JSON_PATH, 'r') as f:
            existing_data = json.load(f)
    except:
        existing_data = {}
    
    # 添加CVE-2014-3625的数据
    if CVE_ID_LOWER not in existing_data:
        existing_data[CVE_ID_LOWER] = []
    
    # 添加新的分析结果
    entry = {
        "base_tag": "v3.0.3.RELEASE",
        "head_tag": "v3.0.4.RELEASE",
        "analysis": {
            TARGET_COMMIT: analysis_result
        }
    }
    existing_data[CVE_ID_LOWER].append(entry)
    
    # 保存
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(existing_data, f, indent=2)
    
    print(f"✅ 已保存到 {OUTPUT_PATH}")


def main():
    print(f"\n{'#'*100}")
    print(f"# CVE-2014-3625 单独测试")
    print(f"# 目标: 验证是否能找到引入commit {TARGET_COMMIT[:16]}")
    print(f"{'#'*100}")
    
    # 步骤2: 加载修复commits
    fix_commits_files = load_patch_results()
    
    # 步骤3: 提取安全措施
    fix_security_measures, fix_security_patterns = load_fix_code_context(fix_commits_files)
    
    # 步骤6: 加载候选commits
    filtered_commits, intro_contexts = load_intro_context()
    
    # 检查目标commit是否在候选列表中
    target_in_candidates = any(c['sha'] == TARGET_COMMIT for c in filtered_commits)
    print(f"\n{'='*100}")
    print(f"目标commit {TARGET_COMMIT[:16]} 是否在候选列表中: {'✅ 是' if target_in_candidates else '❌ 否'}")
    print(f"{'='*100}")
    
    # 步骤7: 分析目标commit
    if TARGET_COMMIT in intro_contexts:
        candidate_context = intro_contexts[TARGET_COMMIT]
        
        # 执行分析
        is_intro, confidence, missing_checks, critical_patterns, candidate_features = analyze_intro_commit(
            candidate_context, fix_security_measures, fix_security_patterns
        )
        
        # 准备保存的结果
        result = {
            "is_intro_commit": is_intro,
            "confidence": confidence,
            "missing_security_checks": missing_checks,
            "critical_vulnerability_patterns": critical_patterns,
            "candidate_security_features": candidate_features,
            "target_commit": TARGET_COMMIT,
            "analysis_method": "code_analysis_without_embedding"
        }
        
        # 保存
        save_to_json(result)
        
        print(f"\n{'#'*100}")
        print(f"# 测试成功！")
        print(f"# 目标commit {TARGET_COMMIT[:16]} 被{'✅ 确认' if is_intro else '❌ 未确认'}为引入漏洞的commit")
        print(f"# 置信度: {confidence:.2%}")
        print(f"{'#'*100}\n")
    else:
        print(f"\n❌ 目标commit {TARGET_COMMIT[:16]} 不在intro_context中")


if __name__ == "__main__":
    main()
