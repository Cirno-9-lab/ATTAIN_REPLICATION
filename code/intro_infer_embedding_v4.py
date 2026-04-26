import json
import os

# --- 配置区 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
PATCH_RESULTS_PATH = os.path.join(BASE_PATH, "result/patch_only_results.json")
COMMIT_CONTEXT_DIR = os.path.join(BASE_PATH, "commit_context")
INTRO_CONTEXT_PATH = os.path.join(BASE_PATH, "intro_context.json")
OUTPUT_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_final_f.json")

# 是否使用LLM确认（可选，会增加运行时间）
USE_LLM_CONFIRMATION = True
LLM_MAX_TOKENS = 500  # 限制LLM调用token数


def load_patch_results(cve_id):
    """
    步骤2: 从patch_only_results.json加载修复commits的文件列表
    返回: verdict="yes" 的文件列表
    """
    try:
        with open(PATCH_RESULTS_PATH, 'r') as f:
            patch_data = json.load(f)
        
        cve_key = cve_id.upper()
        if cve_key not in patch_data:
            cve_key = cve_id.lower()
        
        if cve_key not in patch_data:
            return {}
        
        # 提取所有 verdict="yes" 的文件
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
    """
    步骤3: 从commit_context加载修复代码的安全措施
    """
    try:
        context_file = os.path.join(COMMIT_CONTEXT_DIR, f"{cve_id.lower()}.json")
        with open(context_file, 'r') as f:
            context_data = json.load(f)
        
        security_measures = {}
        security_patterns = []
        
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
                        
                        # 提取安全模式
                        all_content = "\n".join(added_content)
                        if "processPath" in all_content:
                            security_patterns.append("路径规范化 (processPath)")
                        if "isInvalidPath" in all_content:
                            security_patterns.append("路径验证 (isInvalidPath)")
                        if "isResourceUnderLocation" in all_content:
                            security_patterns.append("资源位置验证")
                        if "URLDecoder" in all_content or "decode" in all_content:
                            security_patterns.append("URL解码处理")
                        if "WEB-INF" in all_content or "META-INF" in all_content:
                            security_patterns.append("敏感目录保护")
                        if ".." in all_content or "cleanPath" in all_content:
                            security_patterns.append("路径遍历检查")
        
        return security_measures, list(set(security_patterns))
    except Exception as e:
        print(f"⚠️  加载commit_context失败 {cve_id}: {e}")
        return {}, []


def load_intro_context(cve_id):
    """
    步骤6: 从intro_context.json加载候选commits
    """
    try:
        with open(INTRO_CONTEXT_PATH, 'r') as f:
            intro_data = json.load(f)
        
        cve_key = cve_id.lower()
        if cve_key not in intro_data:
            return [], {}
        
        all_filtered_commits = []
        all_commit_contexts = {}
        
        for version_pair in intro_data[cve_key]:
            filter_summary = version_pair.get("filter_summary", [])
            all_filtered_commits.extend(filter_summary)
            
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
    except Exception as e:
        print(f"⚠️  加载intro_context失败 {cve_id}: {e}")
        return [], {}


def analyze_candidate_commit_simple(commit_context):
    """
    简化版的候选commit分析
    只判断是否引入漏洞，不依赖修复代码对比
    """
    if not commit_context:
        return False, 0.0, {}, 0
    
    candidate_files = commit_context.get("files", {})
    critical_vulnerability_patterns = []
    suspicious_patterns = []
    
    # 计算代码变更规模
    total_added_lines = 0
    total_deleted_lines = 0
    
    for file_path, file_ctx in candidate_files.items():
        added_content = file_ctx.get("modified_added_content", [])
        deleted_content = file_ctx.get("modified_deleted_content", [])
        total_added_lines += len(added_content)
        total_deleted_lines += len(deleted_content)
        
        all_code = "\n".join(added_content)
        
        # 检查关键漏洞模式（不安全的代码模式）
        # 1. 输入处理问题
        if any(pattern in all_code for pattern in ["parseNumber", "parse", "parseInt", "parseLong"]):
            if not any(check in all_code for check in ["validate", "check", "limit", "bound"]):
                suspicious_patterns.append(f"{file_path}: 解析输入但无边界检查")
        
        # 2. 资源访问问题
        if "getResource" in all_code or "createRelative" in all_code:
            if not any(check in all_code for check in ["validate", "check", "sanitize", "clean"]):
                critical_vulnerability_patterns.append(f"{file_path}: 资源访问无验证")
        
        # 3. 路径处理问题
        if "path" in all_code.lower() or "file" in all_code.lower():
            if not any(check in all_code for check in ["validate", "sanitize", "clean", "normalize"]):
                critical_vulnerability_patterns.append(f"{file_path}: 路径处理无验证")
        
        # 4. 数据转换问题
        if "BigDecimal" in all_code or "BigInteger" in all_code:
            if not any(check in all_code for check in ["try", "catch", "limit", "bound"]):
                suspicious_patterns.append(f"{file_path}: 数值转换无异常处理")
        
        # 5. 直接使用外部输入
        if any(pattern in all_code for pattern in ["numberStr", "inputStr", "userInput", "request"]):
            if not any(check in all_code for check in ["validate", "sanitize", "check"]):
                suspicious_patterns.append(f"{file_path}: 直接使用外部输入")
    
    # 判断标准（简化版）:
    # 1. 代码变更规模适中（10-3000行）
    # 2. 有可疑的漏洞模式或关键问题
    # 3. 添加的代码比删除的多（新功能引入）
    
    is_intro = (
        10 <= total_added_lines <= 3000 and  # 代码规模适中
        (len(critical_vulnerability_patterns) >= 1 or len(suspicious_patterns) >= 1) and  # 有安全问题
        total_added_lines > total_deleted_lines  # 新增代码为主
    )
    
    # 计算置信度
    if is_intro:
        confidence = 0.5  # 基础置信度
        confidence += min(len(critical_vulnerability_patterns) * 0.1, 0.2)  # 关键漏洞模式
        confidence += min(len(suspicious_patterns) * 0.05, 0.15)  # 可疑模式
        confidence = min(0.9, confidence)
    else:
        confidence = 0.1
    
    analysis_info = {
        "critical_vulnerability_patterns": critical_vulnerability_patterns,
        "suspicious_patterns": suspicious_patterns,
        "total_added_lines": total_added_lines,
        "total_deleted_lines": total_deleted_lines
    }
    
    return is_intro, confidence, analysis_info, total_added_lines


def analyze_candidate_commit(commit_context, fix_security_patterns, fix_security_measures):
    """
    步骤7: 基于代码分析候选commit，返回是否为intro commit和置信度
    改进版：区分输入验证vs断言检查，添加LDAP/AD和XXE漏洞模式
    """
    if not commit_context:
        return False, 0.0, {}, 0, []
    
    candidate_files = commit_context.get("files", {})
    critical_vulnerability_patterns = []
    suspicious_patterns = []
    candidate_security_features = []
    
    # 计算代码变更规模
    total_added_lines = 0
    total_deleted_lines = 0
    
    # 检查是否是initial commit（重要特征）
    commit_message = commit_context.get("message", "").lower()
    is_initial_commit = "initial" in commit_message or "first" in commit_message or "add" in commit_message
    
    for file_path, file_ctx in candidate_files.items():
        added_content = file_ctx.get("modified_added_content", [])
        deleted_content = file_ctx.get("modified_deleted_content", [])
        total_added_lines += len(added_content)
        total_deleted_lines += len(deleted_content)
        
        all_code = "\n".join(added_content)
        all_code_lower = all_code.lower()
        
        # 检查真正的安全措施（改进版）
        # 排除断言检查（Assert.isInstanceOf, Assert.notNull等）
        real_security_checks = []
        
        # 1. 密码/输入长度验证（关键！）
        if "haslength" in all_code_lower or "hasText" in all_code_lower:
            real_security_checks.append("length_validation")
        if "password" in all_code_lower and ("check" in all_code_lower or "validate" in all_code_lower):
            real_security_checks.append("password_validation")
        
        # 2. 路径/输入验证
        if "validate" in all_code_lower:
            # 检查是否是断言
            if "assert" not in all_code_lower or "validate" in all_code_lower.replace("assert", ""):
                real_security_checks.append("validate")
        if "sanitize" in all_code_lower:
            real_security_checks.append("sanitize")
        if "isvalid" in all_code_lower or "isinvalid" in all_code_lower:
            real_security_checks.append("validation")
        
        # 3. 路径处理
        if "processpath" in all_code_lower or "cleanpath" in all_code_lower:
            real_security_checks.append("path_processing")
        if "normalize" in all_code_lower:
            real_security_checks.append("normalize")
        
        # 4. XXE防护（关键！）
        if any(pattern in all_code_lower for pattern in ["setfeature", "disallow-doctype", "external-general-entities", "external-parameter-entities"]):
            real_security_checks.append("xxe_protection")
        
        # 5. 边界检查（排除断言）
        if ("bound" in all_code_lower or "limit" in all_code_lower) and "assert" not in all_code_lower:
            real_security_checks.append("boundary_check")
        
        candidate_security_features.extend(real_security_checks)
        
        # 检查关键漏洞模式
        # 1. LDAP/AD认证无密码验证（CVE-2014-0097）
        if any(pattern in all_code for pattern in ["authenticate", "bindAsUser", "AuthenticationProvider", "LdapAuthenticationProvider", "ActiveDirectoryLdap"]):
            # 检查是否有密码验证（hasLength, password check等）
            if not any(check in real_security_checks for check in ["length_validation", "password_validation", "validate"]):
                critical_vulnerability_patterns.append(f"{file_path}: LDAP/AD认证无密码验证")
        
        # 2. XML解析无XXE防护（CVE-2014-125087）
        if any(pattern in all_code for pattern in ["DocumentBuilder", "SAXParser", "XMLReader", "SAXParserFactory", "DocumentBuilderFactory"]):
            if "xxe_protection" not in real_security_checks:
                critical_vulnerability_patterns.append(f"{file_path}: XML解析无XXE防护")
        
        # 3. 解析/转换操作无验证
        if any(pattern in all_code for pattern in ["parseNumber", "parseInt", "parseLong", "BigDecimal", "BigInteger"]):
            if not any(check in real_security_checks for check in ["validate", "boundary_check"]):
                # try/catch不算安全措施，只是异常处理
                critical_vulnerability_patterns.append(f"{file_path}: 数据解析/转换无验证")
        
        # 4. 资源访问/创建无检查
        if any(pattern in all_code for pattern in ["getResource", "getResources", "createRelative", "FileInputStream", "FileReader"]):
            if not any(check in real_security_checks for check in ["validate", "sanitize", "validation", "path_processing", "normalize"]):
                critical_vulnerability_patterns.append(f"{file_path}: 资源操作无验证")
        
        # 5. 路径操作无检查
        if "path" in all_code_lower:
            if "request" in all_code_lower and "getattribute" in all_code_lower:
                if not any(check in real_security_checks for check in ["validate", "sanitize", "validation", "path_processing", "normalize"]):
                    critical_vulnerability_patterns.append(f"{file_path}: 从request获取path无验证")
            elif not any(check in real_security_checks for check in ["validate", "sanitize", "validation", "path_processing", "normalize"]):
                suspicious_patterns.append(f"{file_path}: 路径操作无验证")
        
        # 6. 文件操作无检查
        if "file" in all_code_lower or "directory" in all_code_lower:
            if not any(check in real_security_checks for check in ["validate", "sanitize", "validation", "path_processing", "normalize"]):
                suspicious_patterns.append(f"{file_path}: 文件操作无验证")
        
        # 7. 直接使用外部输入
        if any(pattern in all_code for pattern in ["numberStr", "inputStr", "userInput", "String str"]):
            if not any(check in real_security_checks for check in ["validate", "sanitize", "validation"]):
                suspicious_patterns.append(f"{file_path}: 直接使用未验证输入")
        
        # 8. Handler/Controller/Servlet模式
        if any(pattern in all_code for pattern in ["Handler", "Controller", "Servlet", "Service"]):
            if not any(check in real_security_checks for check in ["validate", "sanitize", "validation"]):
                suspicious_patterns.append(f"{file_path}: Handler/Controller无验证")
    
    # 判断标准（改进版）
    # 代码规模：5-3000行
    # 关键漏洞模式：至少1个
    # 或者：可疑模式>=3且是initial commit
    
    is_intro = (
        5 <= total_added_lines <= 3000 and
        (
            len(critical_vulnerability_patterns) >= 1 or
            (len(suspicious_patterns) >= 3 and is_initial_commit)
        ) and
        total_added_lines > total_deleted_lines * 0.5
    )
    
    # 计算置信度
    if is_intro:
        confidence = 0.6
        if is_initial_commit:
            confidence += 0.15
        confidence += min(len(critical_vulnerability_patterns) * 0.1, 0.2)
        confidence += min(len(suspicious_patterns) * 0.03, 0.1)
        confidence = min(0.95, confidence)
    else:
        confidence = 0.1
    
    analysis_info = {
        "critical_vulnerability_patterns": critical_vulnerability_patterns,
        "suspicious_patterns": suspicious_patterns,
        "candidate_security_features": candidate_security_features,
        "total_added_lines": total_added_lines,
        "total_deleted_lines": total_deleted_lines,
        "is_initial_commit": is_initial_commit
    }
    
    return is_intro, confidence, analysis_info, total_added_lines, candidate_security_features


def confirm_with_llm(cve_id, commit_hash, analysis_info, candidate_files):
    """
    可选：使用LLM确认是否为intro commit
    仅对最可疑的commit调用，减少token消耗
    直接调用llm.py中的Client类
    """
    try:
        from llm import Client
        
        # 初始化LLM客户端
        client = Client()
        
        # 提取关键信息，减少token
        missing_checks = analysis_info.get("missing_security_checks", [])[:3]
        vuln_patterns = analysis_info.get("critical_vulnerability_patterns", [])[:2]
        has_security = len(analysis_info.get("candidate_security_features", [])) > 0
        is_initial = analysis_info.get("is_first_implementation", False)
        added_lines = analysis_info.get("total_added_lines", 0)
        
        # 构建简洁的prompt
        prompt = f"""判断commit {commit_hash[:16]} 是否为引入漏洞CVE-{cve_id}的commit。

修复代码的安全措施: {', '.join(missing_checks)}
关键漏洞模式: {', '.join(vuln_patterns)}

该commit特点:
- 是否是initial commit: {is_initial}
- 是否包含安全措施: {has_security}
- 代码变更规模: {added_lines} 行

判断标准:
1. 如果是initial commit + 缺失安全措施 + 有关键漏洞模式 → 可能是intro commit
2. 如果不是initial commit 或 包含安全措施 → 不是intro commit
3. 缺失安全措施越多，越可能是intro commit
4. 关键漏洞模式越多，越可能是intro commit

请返回JSON格式:
{{"is_intro_commit": true/false, "confidence": 0.0-1.0, "reason": "简要理由"}}"""

        # 调用LLM
        response_text = client.call_llm(prompt)
        
        # 解析LLM响应
        if "ERROR" in response_text or "STOP_SIGNAL" in response_text:
            return False, 0.3
        
        # 尝试解析JSON
        try:
            result = json.loads(response_text)
            return (
                result.get("is_intro_commit", False),
                float(result.get("confidence", 0.5))
            )
        except:
            # JSON解析失败，根据文本判断
            is_intro = "true" in response_text.lower() and "intro" in response_text.lower()
            return is_intro, 0.5 if is_intro else 0.3
            
    except Exception as e:
        # 出错返回保守结果
        return False, 0.3


def process_cve(cve_id):
    """
    处理单个CVE，执行完整的步骤3和步骤7
    返回: (status, cve_analysis, skip_reason)
        - status: "found_intro" | "no_intro" | "skipped"
        - cve_analysis: 分析结果字典
        - skip_reason: 跳过原因（如果status为skipped）
    """
    print(f"\n{'='*100}")
    print(f"处理 CVE: {cve_id}")
    print(f"{'='*100}")
    
    # 步骤2: 获取修复commits的文件列表
    fix_commits_files = load_patch_results(cve_id)
    if not fix_commits_files:
        print(f"⚠️  未找到修复commits，跳过")
        return "skipped", {}, "no_fix_commits"
    
    print(f"步骤2: 找到 {len(fix_commits_files)} 个修复commit")
    
    # 步骤3: 加载修复代码的安全措施（可选）
    fix_security_measures, fix_security_patterns = load_fix_code_context(cve_id, fix_commits_files)
    if fix_security_measures:
        print(f"步骤3: 提取 {len(fix_security_measures)} 个文件的安全措施")
        if fix_security_patterns:
            print(f"       识别 {len(fix_security_patterns)} 种安全模式")
    else:
        print(f"步骤3: 未找到修复代码上下文，使用简化分析")
    
    # 步骤6: 加载候选commits
    filtered_commits, intro_contexts = load_intro_context(cve_id)
    if not filtered_commits:
        print(f"⚠️  未找到候选commits，跳过")
        return "skipped", {}, "no_candidate_commits"
    
    print(f"步骤6: 筛选出 {len(filtered_commits)} 个候选commits")
    
    # 步骤7: 验证每个候选commit
    candidates_scores = []
    
    print(f"\n步骤7: 分析候选commits")
    
    for commit_hash, commit_context in intro_contexts.items():
        is_intro, confidence, analysis_info, added_lines, security_features = analyze_candidate_commit(
            commit_context, fix_security_patterns, fix_security_measures
        )
        
        # 收集所有候选的评分，即使不是intro
        candidates_scores.append({
            "commit_hash": commit_hash,
            "is_intro": is_intro,
            "confidence": confidence,
            "analysis_info": analysis_info,
            "added_lines": added_lines,
            "security_features": security_features
        })
        
        if is_intro:
            print(f"  ⭐ {commit_hash[:16]}: 可能是intro commit (confidence={confidence:.2%})")
        else:
            print(f"  -  {commit_hash[:16]}: 不是intro commit (confidence={confidence:.2%})")
    
    # 按置信度排序
    candidates_scores.sort(key=lambda x: x["confidence"], reverse=True)
    
    # 选择最可疑的几个commit
    cve_analysis = {}
    
    for candidate in candidates_scores:
        if candidate["is_intro"]:
            commit_hash = candidate["commit_hash"]
            analysis_info = candidate["analysis_info"]
            
            # 可选：使用LLM确认
            if USE_LLM_CONFIRMATION:
                is_llm_confirmed, llm_confidence = confirm_with_llm(
                    cve_id, commit_hash, analysis_info, intro_contexts[commit_hash].get("files", {})
                )
                # 如果LLM确认，取较小的置信度；如果LLM不确认，保留原始代码分析结果
                final_confidence = min(candidate["confidence"], llm_confidence) if is_llm_confirmed else candidate["confidence"]
            else:
                final_confidence = candidate["confidence"]
            
            # 只有置信度 > 0.5 才输出
            if final_confidence > 0.5:
                cve_analysis[commit_hash] = {
                    "is_intro_commit": True,
                    "confidence": final_confidence,
                    "critical_vulnerability_patterns": analysis_info.get("critical_vulnerability_patterns", []),
                    "suspicious_patterns": analysis_info.get("suspicious_patterns", []),
                    "candidate_security_features": analysis_info.get("candidate_security_features", []),
                    "analysis_method": "code_analysis"
                }
    
    if cve_analysis:
        print(f"\n✅ 找到 {len(cve_analysis)} 个引入commit")
        return "found_intro", cve_analysis, None
    else:
        print(f"\n✓ 该版本可能不存在漏洞引入commit")
        return "no_intro", {}, None


def main():
    """
    主流程：完整实现步骤3和步骤7
    """
    print("\n" + "#"*100)
    print("# 思维链推理: 步骤3和步骤7")
    print("# 步骤3: 分析修复代码，提取安全措施")
    print("# 步骤7: 基于代码分析验证候选commit")
    print(f"# LLM确认: {'启用' if USE_LLM_CONFIRMATION else '禁用'}")
    print("#"*100)
    
    # 1. 加载CVE列表
    try:
        with open(CVE_LIST_PATH, 'r') as f: 
            cve_list = json.load(f)
    except Exception as e:
        print(f"❌ 加载失败: {e}")
        return
    
    # 2. 处理每个CVE
    output_data = {}  # 不从原有文件加载，全新开始
    
    stats = {
        "total": 0,
        "found_intro": 0,
        "no_intro": 0,
        "skipped": 0
    }
    
    for cve_id in cve_list.keys():
        stats["total"] += 1
        status, cve_analysis, skip_reason = process_cve(cve_id)
        
        # 所有CVE都输出到结果文件
        cve_key = cve_id.lower()
        version_pairs = cve_list[cve_id].get("version_pair", [])
        
        if version_pairs:
            first_pair = version_pairs[0]
            output_entry = {
                "base_tag": first_pair.get("BASE_TAG", ""),
                "head_tag": first_pair.get("HEAD_TAG", ""),
                "analysis": cve_analysis
            }
            
            if status == "skipped":
                stats["skipped"] += 1
                output_entry["note"] = f"skipped: {skip_reason}"
            elif status == "found_intro":
                stats["found_intro"] += 1
            else:
                stats["no_intro"] += 1
                output_entry["note"] = "no_intro_commit_found"
            
            output_data[cve_key] = [output_entry]
    
    # 3. 保存结果
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'#'*100}")
    print(f"✅ 处理完成！")
    print(f"   总计: {stats['total']} 个CVE")
    print(f"   找到intro commit: {stats['found_intro']} 个")
    print(f"   未找到intro commit: {stats['no_intro']} 个")
    print(f"   跳过: {stats['skipped']} 个")
    print(f"   结果已保存到: {OUTPUT_PATH}")
    print(f"{'#'*100}\n")


if __name__ == "__main__":
    main()
