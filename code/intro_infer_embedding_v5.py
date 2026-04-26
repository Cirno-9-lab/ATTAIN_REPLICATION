import json
import os
import re
import signal
import time

# --- 配置区 ---
BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_PATH = os.path.join(BASE_PATH, "list/cve_list.json")
PATCH_RESULTS_PATH = os.path.join(BASE_PATH, "result/patch_only_results.json")
COMMIT_CONTEXT_DIR = os.path.join(BASE_PATH, "commit_context")
INTRO_CONTEXT_PATH = os.path.join(BASE_PATH, "intro_context.json")
OUTPUT_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_final_f.json")

# 是否使用LLM确认（基于代码特征辅助判断，不使用硬编码CVE列表）
USE_LLM_CONFIRMATION = True
LLM_MAX_TOKENS = 500  # 限制LLM调用token数
CVE_TIMEOUT = 600  # 每个CVE处理超时时间（秒）
MAX_LLM_CALLS_PER_CVE = 5  # v1_f: baseline


class TimeoutError(Exception):
    """自定义超时异常"""
    pass


def timeout_handler(signum, frame):
    """超时处理器"""
    raise TimeoutError(f"CVE processing timeout after {CVE_TIMEOUT} seconds")


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


def analyze_candidate_commit(commit_context, fix_security_patterns, fix_security_measures, base_tag=None):
    """
    步骤7: 基于代码分析候选commit，返回是否为intro commit和置信度
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
    
    # 版本号分析
    is_alpha_version = base_tag and ("alpha" in base_tag.lower() or "beta" in base_tag.lower() or "rc" in base_tag.lower())
    is_early_version = base_tag and (
        any(x in base_tag for x in ["0.", "1.0", "1.1", "1.2", "1.3", "2.0", "2.1", "3.0"])
    )
    
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
    
    # 判断标准（v7平衡版）
    # 代码规模：5-3000行
    # 判断逻辑：
    # 1. 必须有至少1个critical_vulnerability_patterns
    # 2. 如果有真正的安全措施，需要更多的漏洞模式
    # 3. 或者：suspicious_patterns>=4且是initial commit

    # 检查是否有真正的安全措施
    has_real_security_checks = any([
        "xxe_protection" in candidate_security_features,
        "length_validation" in candidate_security_features,
        "password_validation" in candidate_security_features,
        "path_processing" in candidate_security_features,
        "normalize" in candidate_security_features,
        "validate" in candidate_security_features,
        "sanitize" in candidate_security_features,
        "validation" in candidate_security_features
    ])

    # Rules: Only hard constraints (code size, basic security checks)
    # LLM: Handles fuzzy semantic judgment and confidence assessment

    # Hard constraint 1: Code size (very loose constraint)
    if not (5 <= total_added_lines <= 5000):
        analysis_info = {
            "critical_vulnerability_patterns": critical_vulnerability_patterns,
            "suspicious_patterns": suspicious_patterns,
            "candidate_security_features": candidate_security_features,
            "total_added_lines": total_added_lines,
            "total_deleted_lines": total_deleted_lines,
            "is_initial_commit": is_initial_commit,
            "reason": "Code size constraint failed"
        }
        return False, 0.05, analysis_info, total_added_lines, candidate_security_features

    # Hard constraint 2: At least some suspicious or critical patterns
    has_any_patterns = (len(critical_vulnerability_patterns) >= 1 or len(suspicious_patterns) >= 1)
    if not has_any_patterns:
        analysis_info = {
            "critical_vulnerability_patterns": critical_vulnerability_patterns,
            "suspicious_patterns": suspicious_patterns,
            "candidate_security_features": candidate_security_features,
            "total_added_lines": total_added_lines,
            "total_deleted_lines": total_deleted_lines,
            "is_initial_commit": is_initial_commit,
            "reason": "No vulnerability patterns found"
        }
        return False, 0.05, analysis_info, total_added_lines, candidate_security_features

    # Hard constraints passed, mark as candidate, let LLM perform semantic judgment
    is_intro_candidate = True

    # Base confidence (rules part) - baseline
    confidence = 0.45  # v1_f: baseline
    confidence += min(len(critical_vulnerability_patterns) * 0.03, 0.15)  # v1_f: bonus
    confidence = min(confidence, 0.60)  # v1_f: max

    analysis_info = {
        "critical_vulnerability_patterns": critical_vulnerability_patterns,
        "suspicious_patterns": suspicious_patterns,
        "candidate_security_features": candidate_security_features,
        "total_added_lines": total_added_lines,
        "total_deleted_lines": total_deleted_lines,
        "is_initial_commit": is_initial_commit
    }

    return True, confidence, analysis_info, total_added_lines, candidate_security_features


def confirm_with_llm(cve_id, commit_hash, analysis_info, candidate_files, base_tag=None, code_confidence=0.0):
    """
    使用LLM处理模糊语义判断
    LLM负责：判断是否引入漏洞、分析代码语义、提供置信度建议
    规则负责：硬性约束（代码规模、安全性检查等）
    """
    try:
        from llm import Client

        # Initialize LLM client
        client = Client()

        # Extract key information
        critical_patterns = analysis_info.get("critical_vulnerability_patterns", [])[:8]
        suspicious_patterns = analysis_info.get("suspicious_patterns", [])[:8]
        security_features = analysis_info.get("candidate_security_features", [])
        total_added = analysis_info.get("total_added_lines", 0)
        total_deleted = analysis_info.get("total_deleted_lines", 0)
        is_initial = analysis_info.get("is_initial_commit", False)

        # Analyze security features
        has_real_security = any([
            "xxe_protection" in security_features,
            "length_validation" in security_features,
            "password_validation" in security_features,
            "path_processing" in security_features,
            "validate" in security_features,
            "sanitize" in security_features,
            "validation" in security_features
        ])

        # Build detailed prompt for LLM semantic analysis
        prompt = f"""You are a security code audit expert. Analyze whether the following commit INTRODUCES a security vulnerability.

## Basic Code Change Information
- Commit Hash: {commit_hash[:16]}
- Lines Added: {total_added}
- Lines Deleted: {total_deleted}
- Is Initial Commit: {is_initial}
- Version Tag: {base_tag if base_tag else 'unknown'}

## Security Analysis Results (Based on Rules)
### Critical Vulnerability Patterns ({len(critical_patterns)} found)
{chr(10).join(f'  {i+1}. {p}' for i, p in enumerate(critical_patterns[:5]))}

### Suspicious Patterns ({len(suspicious_patterns)} found)
{chr(10).join(f'  {i+1}. {p}' for i, p in enumerate(suspicious_patterns[:5]))}

### Security Features ({len(security_features)} found)
{chr(10).join(f'  {i+1}. {f}' for i, f in enumerate(security_features[:5]))}
Has Real Security Measures: {has_real_security}

## Hard Constraints (Reference Only)
- Code Size: 5-5000 lines ✓ (current: {total_added} lines)
- Has Real Security Measures: {has_real_security}

## Your Task
Please perform semantic judgment to determine if this commit INTRODUCES a security vulnerability.

### KEY DEFINITION
A "vulnerability introduction commit" is a commit that ADDS NEW CODE which CREATES a security vulnerability. This means:
- The vulnerability was NOT present before this commit
- The NEWLY ADDED CODE contains security flaws
- If you look at the ADDED LINES, you can identify a root cause of the vulnerability

### 1. Vulnerability Introduction Characteristics (Set is_intro_commit=true if ANY of these apply)
- Does it ADD NEW CODE that processes user input without validation?
- Does it ADD NEW CODE for resource access without security checks?
- Does it ADD NEW CODE for parsing/conversion logic without boundary checks?
- Does it ADD NEW CODE that handles sensitive data (file paths, resources, credentials) improperly?
- Does it ADDED CODE contain security flaws that were NOT present before?

### 2. Code Semantic Analysis
- What is the main functionality of ADDED CODE?
- Is this the initial implementation of a feature?
- Does the ADDED CODE match typical vulnerability introduction patterns?
- Would a security review flag the ADDED CODE as introducing a vulnerability?

### 3. Confidence Assessment
- Provide a confidence score between 0.0 and 1.0 based on:
  * Number of vulnerability patterns in ADDED CODE (more = higher confidence)
  * Presence of security measures in ADDED CODE (more = lower confidence)
  * Whether it's an initial commit (initial = higher confidence)
  * Code semantics and functionality analysis of ADDED CODE
  * Overall risk assessment of ADDED CODE

### Critical Indicators of VULNERABILITY INTRODUCTION (Set is_intro_commit=true):
- Initial implementation of a feature WITHOUT security considerations
- ADDED CODE directly uses user inputs WITHOUT validation/sanitization
- ADDED CODE missing boundary checks or input validation
- ADDED CODE has insecure resource access patterns
- ADDED CODE performs sensitive operations WITHOUT proper safeguards

### Indicators of Safe Code (Set is_intro_commit=false):
- ADDED CODE includes defensive programming with explicit validation
- ADDED CODE has comprehensive error handling and bounds checking
- ADDED CODE uses security-aware design patterns
- ADDED CODE includes input sanitization and output encoding
- This is a refactoring or bug fix (not adding new vulnerable code)

## Output Format
Please return in JSON format:
{{
  "is_intro_commit": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "Brief analysis (2-3 sentences explaining your decision)",
  "semantic_analysis": "Code semantic analysis (functionality and potential risks)",
  "risk_level": "high/medium/low",
  "vulnerability_type": "type if applicable (e.g., path traversal, injection, XXE, etc.)"
}}

CRITICAL: Set is_intro_commit=true ONLY if the ADDED CODE introduces a NEW vulnerability. If the code just has suspicious patterns but doesn't clearly introduce a new vulnerability, set is_intro_commit=false.

Important: Focus on ADDED CODE semantics and vulnerability introduction characteristics. Do NOT be influenced by the CVE ID."""

        # 调用LLM
        response_text = client.call_llm(prompt)

        # Parse LLM response
        if "ERROR" in response_text or "STOP_SIGNAL" in response_text:
            return False, 0.3, "LLM call failed", ""

        # Try to parse JSON
        try:
            result = json.loads(response_text)
            is_intro = result.get("is_intro_commit", False)
            llm_confidence = float(result.get("confidence", 0.5))
            reasoning = result.get("reasoning", "")
            semantic_analysis = result.get("semantic_analysis", "")
            return is_intro, llm_confidence, reasoning, semantic_analysis
        except Exception as e:
            # JSON parsing failed, try to extract from text
            response_lower = response_text.lower()
            is_intro = False

            # Multiple heuristics to determine if intro commit
            intro_indicators = ["vulnerability", "introduced", "missing validation", "no security", "insecure"]
            not_intro_indicators = ["safe", "secure", "has validation", "proper checks", "defensive"]

            intro_count = sum(1 for ind in intro_indicators if ind in response_lower)
            not_intro_count = sum(1 for ind in not_intro_indicators if ind in response_lower)

            if intro_count > not_intro_count:
                is_intro = True

            # Also check for explicit "true" or "false"
            if '"is_intro_commit": true' in response_lower or "is_intro_commit: true" in response_lower:
                is_intro = True
            elif '"is_intro_commit": false' in response_lower or "is_intro_commit: false" in response_lower:
                is_intro = False

            # Try to extract confidence
            confidence_match = re.search(r'"confidence":\s*([0-9.]+)', response_text)
            if confidence_match:
                llm_confidence = float(confidence_match.group(1))
            else:
                llm_confidence = 0.5

            return is_intro, llm_confidence, "JSON parsing failed, text-based judgment", ""

    except Exception as e:
        # Return conservative result on error
        return False, 0.3, f"Exception: {str(e)}", ""


def process_cve(cve_id, base_tag=None):
    """
    处理单个CVE，执行完整的步骤3和步骤7
    返回: (status, cve_analysis, skip_reason)
        - status: "found_intro" | "no_intro" | "skipped"
        - cve_analysis: 分析结果字典
        - skip_reason: 跳过原因（如果status为skipped）
    """
    print(f"\n{'='*100}")
    print(f"处理 CVE: {cve_id} (base_tag: {base_tag})")
    print(f"{'='*100}")

    # 设置超时
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(CVE_TIMEOUT)
        print(f"⏱️ 设置{CVE_TIMEOUT}s超时")

    try:
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
                commit_context, fix_security_patterns, fix_security_measures, base_tag
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

        # 规则筛选：只对置信度最高的前N个候选commit调用LLM
        # 这样可以减少LLM调用次数，同时保证质量
        top_candidates = candidates_scores[:MAX_LLM_CALLS_PER_CVE]

        # 选择最可疑的几个commit
        cve_analysis = {}

        # LLM + Rules 策略：
        # - 规则：硬性约束（代码规模、安全性检查等）
        # - LLM：处理模糊语义判断
        # - 只对规则筛选出的top N个候选commit使用LLM

        llm_call_count = 0
        for candidate in candidates_scores:
            commit_hash = candidate["commit_hash"]
            analysis_info = candidate["analysis_info"]
            code_confidence = candidate["confidence"]

            # 规则硬性约束：只处理代码规模在合理范围内的
            # 其他硬规则已在analyze_candidate_commit中应用
            if not candidate["is_intro"]:
                # 规则已判断为不是intro，跳过
                continue

            # 规则筛选：只对top N的候选commit调用LLM
            if llm_call_count >= MAX_LLM_CALLS_PER_CVE:
                # 已经调用了MAX_LLM_CALLS_PER_CVE次，剩下的直接用规则
                final_confidence = code_confidence * 0.9  # 稍微降低置信度
                analysis_method = "rules_only_filtered"
                llm_info = {}
            else:
                # 使用LLM处理语义判断（LLM负责模糊语义，规则负责硬性约束）
                if USE_LLM_CONFIRMATION:
                    is_llm_confirmed, llm_confidence, reasoning, semantic_analysis = confirm_with_llm(
                        cve_id, commit_hash, analysis_info,
                        intro_contexts[commit_hash].get("files", {}), base_tag, code_confidence
                    )
                    llm_call_count += 1

                    # LLM + Rules hybrid judgment
                    # Rules ensure hard constraints, LLM provides semantic judgment and confidence adjustment
                    if is_llm_confirmed:
                        # LLM confirmed, combine rule and LLM confidence
                        # Use weighted average: 30% rules + 70% LLM (rely more on LLM semantic judgment)
                        final_confidence = 0.3 * code_confidence + 0.7 * llm_confidence
                        analysis_method = "llm_plus_rules"
                        llm_info = {
                            "llm_confidence": llm_confidence,
                            "llm_reasoning": reasoning,
                            "semantic_analysis": semantic_analysis
                        }
                    else:
                        # LLM not confirmed, significantly reduce confidence (rules passed but LLM disagrees)
                        final_confidence = 0.2 * code_confidence  # Drastically reduce
                        analysis_method = "rules_override_llm"
                        llm_info = {
                            "llm_confidence": llm_confidence,
                            "llm_reasoning": reasoning,
                            "note": "Rules passed but LLM rejected"
                        }
                else:
                    # 不使用LLM，仅使用规则
                    final_confidence = code_confidence
                    analysis_method = "rules_only"
                    llm_info = {}

            # Use baseline threshold
            threshold = 0.30  # v1_f: baseline

            if final_confidence > threshold:
                cve_analysis[commit_hash] = {
                    "is_intro_commit": True,
                    "confidence": final_confidence,
                    "critical_vulnerability_patterns": analysis_info.get("critical_vulnerability_patterns", []),
                    "suspicious_patterns": analysis_info.get("suspicious_patterns", []),
                    "candidate_security_features": analysis_info.get("candidate_security_features", []),
                    "analysis_method": analysis_method,
                    "llm_analysis": llm_info
                }

        # 取消超时
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)

        if cve_analysis:
            print(f"\n✅ 找到 {len(cve_analysis)} 个引入commit")
            return "found_intro", cve_analysis, None
        else:
            print(f"\n✓ 该版本可能不存在漏洞引入commit")
            return "no_intro", {}, None

    except TimeoutError as e:
        # 处理超时
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
        print(f"\n⏰ 处理超时: {e}")
        return "skipped", {}, "timeout"
    except Exception as e:
        # 处理其他异常
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
        print(f"\n❌ 处理异常: {e}")
        return "skipped", {}, f"error: {str(e)}"


def main():
    """
    主流程：完整实现步骤3和步骤7
    """
    print("\n" + "#"*100)
    print("# 思维链推理: 步骤3和步骤7")
    print("# 步骤3: 分析修复代码，提取安全措施")
    print("# 步骤7: 基于代码分析验证候选commit")
    print(f"# LLM确认: {'启用' if USE_LLM_CONFIRMATION else '禁用'}")
    print(f"# 规则筛选: 每个CVE最多{MAX_LLM_CALLS_PER_CVE}个LLM调用")
    print(f"# CVE超时: {CVE_TIMEOUT}s")
    print("#"*100)

    # 1. 加载CVE列表
    try:
        with open(CVE_LIST_PATH, 'r') as f:
            cve_list = json.load(f)
    except Exception as e:
        print(f"❌ 加载失败: {e}")
        return

    # 2. 处理每个CVE
    output_data = {}

    stats = {
        "total": 0,
        "found_intro": 0,
        "no_intro": 0,
        "skipped": 0,
        "timeout": 0
    }

    for cve_id in cve_list.keys():
        stats["total"] += 1
        version_pairs = cve_list[cve_id].get("version_pair", [])
        base_tag = version_pairs[0].get("BASE_TAG", "") if version_pairs else ""
        status, cve_analysis, skip_reason = process_cve(cve_id, base_tag)

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
                if skip_reason == "timeout":
                    stats["timeout"] += 1
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
    print(f"   超时: {stats['timeout']} 个")
    print(f"   结果已保存到: {OUTPUT_PATH}")
    print(f"{'#'*100}\n")


if __name__ == "__main__":
    main()
