# -*- coding: utf-8 -*-
"""
对比推理引擎 - 基于特征提取的候选commit分析
Contrastive Inference Engine - Feature-Based Candidate Analysis

核心思想：
1. 规则层（Rule Layer）: 作为召回（Recall）工具，过滤掉90%明显无关的commit
2. LLM层（LLM Layer）: 作为精确度（Precision）工具，进行语义分析
3. 对比特征提取（Contrastive Feature Extraction）: 分析Patch，回溯查找缺失特征
"""

import re
import json
from typing import Dict, List, Tuple, Optional
from security_features import (
    is_security_sensitive_code,
    get_security_score,
    SECURITY_PATTERNS,
    get_security_keywords
)


class ContrastiveInferenceEngine:
    """
    对比推理引擎

    职责分工：
    - 规则层: 快速过滤，降低计算成本
    - LLM层: 精确判断，提供语义分析
    """

    def __init__(self):
        self.security_keywords = get_security_keywords()

    # ============================================================================
    # 第一阶段：规则层 - 召回（Recall）
    # ============================================================================

    def filter_candidates_by_rules(
        self,
        candidates: List[Dict],
        fix_security_patterns: List[str],
        fix_keywords: List[str]
    ) -> List[Dict]:
        """
        基于规则的候选过滤

        规则层职责：
        - 过滤掉明显无关的commit（如仅修改文档、仅修改配置）
        - 保留可能相关的commit供LLM进一步分析
        - 目标：过滤掉90%的噪音

        Args:
            candidates: 候选commit列表
            fix_security_patterns: 修复代码中发现的安全模式
            fix_keywords: 修复代码中发现的关键词

        Returns:
            过滤后的候选commit列表（已添加rule_score）
        """
        filtered_candidates = []

        for candidate in candidates:
            code_content = candidate.get("code", "").lower()
            added_lines = candidate.get("added_lines", [])
            commit_message = candidate.get("message", "")  # 新增
            
            # 获取删除的代码（新增）
            deleted_lines = candidate.get("deleted_lines", [])

            # 规则1: 硬约束 - 必须有代码修改
            if not added_lines:
                print(f"  [DEBUG] {candidate.get('hash', 'unknown')[:8]}: 无代码修改，跳过")
                continue

            # 规则2: 过滤明显无关的commit
            if self._is_obviously_irrelevant(code_content, added_lines):
                print(f"  [DEBUG] {candidate.get('hash', 'unknown')[:8]}: 明显无关，跳过")
                continue

            # 规则3: 计算规则分数（Rule Score）
            rule_score = self._calculate_rule_score(
                code_content,
                added_lines,
                fix_security_patterns,
                fix_keywords,
                commit_message,  # 新增参数
                deleted_lines    # 新增参数
            )
            
            print(f"  [DEBUG] {candidate.get('hash', 'unknown')[:8]}: rule_score={rule_score:.3f}")

            # 规则4: 保留分数大于阈值的候选（降低阈值）
            if rule_score > 0.01:  # 降低最低阈值，避免过度过滤
                candidate["rule_score"] = rule_score
                filtered_candidates.append(candidate)

        return filtered_candidates

    def _is_obviously_irrelevant(self, code: str, added_lines: List[str]) -> bool:
        """
        判断是否明显无关

        过滤规则（宽松）：
        - 仅修改注释
        - 仅修改文档文件（README, LICENSE等）
        """
        code_lines = [line for line in added_lines if line.strip() and not line.strip().startswith(("#", "//", "/*", "*"))]

        if not code_lines:
            return True

        # 检查是否是文档文件
        doc_keywords = ["README", "LICENSE", "CHANGELOG", "CONTRIBUTING", ".md", ".txt"]
        if any(kw in code for kw in doc_keywords) and len(code_lines) < 5:
            return True

        return False

    def _calculate_rule_score(
        self,
        code: str,
        added_lines: List[str],
        fix_patterns: List[str],
        fix_keywords: List[str],
        commit_message: str = "",
        deleted_lines: List[str] = None
    ) -> float:
        """
        计算规则分数（改进版）

        分数基于：
        - Commit message分析（新增）
        - 安全关键词匹配
        - 漏洞特定模式识别（新增）
        - 与修复模式的相关性
        - 代码复杂度
        - 安全敏感度
        - 删除代码分析（新增）

        Returns:
            规则分数 (0.0 - 1.0)
        """
        if deleted_lines is None:
            deleted_lines = []
            
        score = 0.0
        all_code = " ".join(added_lines).lower()
        
        # 0. Commit message分析（新增，权重0.15）
        message_score = self._analyze_commit_message(commit_message)
        score += message_score * 0.15

        # 1. 安全关键词匹配（降低权重到0.15）
        keyword_matches = 0
        for category, apis in self.security_keywords.items():
            for api in apis:
                if api.lower() in all_code:
                    keyword_matches += 1
        score += min(keyword_matches * 0.02, 0.15)  # 进一步降低权重

        # 2. 漏洞特定模式识别（新增，权重0.25）
        vulnerability_pattern_score = self._detect_vulnerability_patterns(all_code, added_lines)
        score += vulnerability_pattern_score * 0.25

        # 3. 与修复模式的相关性
        pattern_relevance = 0
        for pattern in fix_patterns:
            if pattern.lower() in all_code:
                pattern_relevance += 1
        score += min(pattern_relevance * 0.10, 0.15)  # 降低上限

        # 4. 代码复杂度
        complexity_score = self._calculate_code_complexity(added_lines)
        score += complexity_score * 0.10  # 降低权重

        # 5. 安全敏感度（降低权重）
        security_score = get_security_score(all_code)
        score += security_score * 0.10  # 进一步降低权重

        # 6. 删除代码分析（新增，权重0.25）
        # 如果没有删除代码（纯新增），降低分数
        if not deleted_lines or len(deleted_lines) == 0:
            # 纯新增代码，降低分数
            score -= 0.10
        else:
            # 有删除代码，检查是否删除了安全检查
            deleted_code = " ".join(deleted_lines).lower()
            if any(kw in deleted_code for kw in ["validate", "check", "verify", "sanitize"]):
                # 删除了安全检查，高风险
                score += 0.15

        return min(score, 1.0)

    def _calculate_code_complexity(self, code_lines: List[str]) -> float:
        """
        计算代码复杂度

        复杂度指标：
        - 代码行数
        - 控制流语句数量
        - 函数调用数量

        Returns:
            复杂度分数 (0.0 - 1.0)
        """
        if not code_lines:
            return 0.0

        # 控制流关键词
        control_flow = ["if", "else", "for", "while", "try", "catch", "switch", "case"]

        control_flow_count = sum(
            1 for line in code_lines
            for keyword in control_flow
            if keyword in line
        )

        # 函数调用（简单检测括号）
        function_calls = sum(1 for line in code_lines if "(" in line and ")" in line)

        # 归一化分数
        complexity = (control_flow_count * 0.5 + function_calls * 0.3) / len(code_lines)
        return min(complexity, 1.0)
    
    def _analyze_commit_message(self, message: str) -> float:
        """
        分析commit message（新增）
        
        正向关键词（可能引入漏洞）:
        - fix, bug, issue, problem, 错误, 问题, 转换, 处理
        
        负向关键词（不太可能是intro commit）:
        - refactor, initial, add, implement, 新增, 重构, 优化
        
        Returns:
            message分数 (-1.0 到 1.0)
        """
        if not message:
            return 0.0
        
        message_lower = message.lower()
        score = 0.0
        
        # 正向关键词（修复相关问题，可能暴露漏洞）
        positive_keywords = [
            "fix", "bug", "issue", "problem", "error", "vulnerability",
            "错误", "问题", "转换", "处理", "修复", "解决"
        ]
        for keyword in positive_keywords:
            if keyword in message_lower:
                score += 0.35  # 提高正向分数
        
        # 负向关键词（重构、新增功能）
        # 注意：移除了"initial"，因为"initial implementation"可能是intro commit
        negative_keywords = [
            "refactor", "new feature",
            "重构", "新增", "优化", "改进"
        ]
        for keyword in negative_keywords:
            if keyword in message_lower:
                score -= 0.5  # 适度惩罚
        
        # 特殊处理："initial refactor"（重构）vs "initial implementation"（功能实现）
        if "initial refactor" in message_lower:
            score -= 0.8  # 重构，重惩罚
        elif "initial implementation" in message_lower or "initial commit" in message_lower:
            # 功能首次实现，可能是intro commit，不惩罚或轻微惩罚
            score -= 0.1
        
        return max(-1.0, min(1.0, score))
    
    def _detect_vulnerability_patterns(self, code: str, added_lines: List[str]) -> float:
        """
        检测漏洞特定模式（新增）
        
        检测内容：
        1. 数值转换/类型转换漏洞（如CVE-2023-51080）
        2. 直接使用用户输入而未验证
        3. 删除了安全检查代码
        4. 路径/文件操作相关
        5. XML/JSON解析相关
        
        Returns:
            漏洞模式分数 (0.0 - 1.0)
        """
        score = 0.0
        
        # 1. 数值转换/类型转换模式（高风险）
        number_conversion_patterns = [
            "parseNumber", "toBigDecimal", "toBigInteger", "parseDouble",
            "parseFloat", "parseLong", "parseInt", "parseint",
            "NumberFormat", "DecimalFormat", "BigDecimal", "BigInteger",
            "科学计数法", "exponential", "scientific notation"
        ]
        for pattern in number_conversion_patterns:
            if pattern.lower() in code:
                score += 0.20  # 提高分数
        
        # 2. 直接使用输入模式（高风险）
        direct_input_patterns = [
            "request.getParameter", "args[", "input.read",
            "scanner.next", "buffer.read", "string.valueof",
            "tostring()", "parse("
        ]
        for pattern in direct_input_patterns:
            if pattern.lower() in code:
                score += 0.25  # 提高分数
        
        # 3. 路径/文件操作模式（高风险）
        path_patterns = [
            "getpath", "getfile", "createfile", "new file",
            "fileinputstream", "fileoutputstream", "filereader",
            "path.resolve", "paths.get"
        ]
        for pattern in path_patterns:
            if pattern.lower() in code:
                score += 0.20  # 提高分数
        
        # 4. XML/JSON解析模式（降低权重，避免误判重构）
        parse_patterns = [
            "documentbuilder", "saxparser", "xmlreader", "xmldecoder",
            "jsonobject", "jsonarray", "jsonparser", "objectmapper",
            "jaxbcontext", "unmarshaller"
        ]
        for pattern in parse_patterns:
            if pattern.lower() in code:
                # 只有当包含"parse"或"decode"等关键词时才给分
                if "parse" in code or "decode" in code or "read" in code:
                    score += 0.15  # 降低分数
                else:
                    # 如果是单纯的XML构建（如XMLBuilder），给更低分数
                    score += 0.05
        
        # 5. 删除了验证/检查代码（高风险）
        # 检查是否有删除的代码模式（从modified_deleted_content）
        # 这里简化处理，通过代码特征判断
        if "validate" in code or "check" in code or "verify" in code:
            # 如果同时包含这些词，可能是修复而非引入
            pass
        else:
            # 如果缺少这些检查，可能是引入漏洞
            score += 0.05
        
        return min(score, 1.0)

    # ============================================================================
    # 第二阶段：对比特征提取（Contrastive Feature Extraction）
    # ============================================================================

    def extract_fix_features(self, patch_diff: str) -> Dict:
        """
        从补丁中提取安全特征

        这是本系统的核心创新点：
        通过分析Patch自动识别安全补丁的关键算子，
        并回溯查找候选Commit中是否缺失这些算子。

        Args:
            patch_diff: 补丁差异

        Returns:
            提取的特征字典
        """
        features = {
            "security_patterns": [],
            "added_safety_checks": [],
            "modified_apis": [],
            "sanitization_methods": [],
            "validation_functions": []
        }

        # 1. 识别安全模式
        for pattern_name, pattern_list in SECURITY_PATTERNS.items():
            for pattern in pattern_list:
                if pattern.lower() in patch_diff.lower():
                    features["security_patterns"].append(f"{pattern_name}:{pattern}")

        # 2. 识别新增的安全检查
        safety_checks = re.findall(
            r'(if\s*\([^)]*\.(validate|check|verify|sanitize)[^)]*\))',
            patch_diff,
            re.IGNORECASE
        )
        features["added_safety_checks"] = [check[0] for check in safety_checks]

        # 3. 识别修改的API
        api_patterns = [
            r'([A-Z][a-zA-Z0-9]*\.[a-z][a-zA-Z0-9]*)\(',
            r'([a-z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*)\('
        ]
        for pattern in api_patterns:
            apis = re.findall(pattern, patch_diff)
            features["modified_apis"].extend(apis)

        # 4. 识别清洗/规范化方法
        sanitization_keywords = ["sanitize", "normalize", "canonical", "escape", "encode"]
        for keyword in sanitization_keywords:
            if keyword in patch_diff.lower():
                features["sanitization_methods"].append(keyword)

        # 5. 识别验证函数
        validation_keywords = ["validate", "verify", "check", "isvalid"]
        for keyword in validation_keywords:
            if keyword in patch_diff.lower():
                features["validation_functions"].append(keyword)

        return features

    def generate_contrastive_analysis_prompt(
        self,
        candidate_code: str,
        fix_features: Dict,
        vulnerability_desc: str
    ) -> str:
        """
        生成对比分析提示词

        这个提示词强调"对比特征提取"的思想，
        让LLM基于修复代码的特征来分析候选commit。

        Args:
            candidate_code: 候选commit代码
            fix_features: 修复代码特征
            vulnerability_desc: 漏洞描述

        Returns:
            LLM提示词
        """
        prompt = f"""你是一个安全分析专家。请使用**对比特征提取（Contrastive Feature Extraction）**的方法分析候选commit。

## 漏洞描述
{vulnerability_desc}

## 修复代码分析（参考特征）
系统已分析修复补丁，识别出以下关键安全特征：

### 1. 安全模式
{chr(10).join(f"- {p}" for p in fix_features['security_patterns']) or "无"}

### 2. 新增的安全检查
{chr(10).join(f"- {c}" for c in fix_features['added_safety_checks']) or "无"}

### 3. 清洗/规范化方法
{chr(10).join(f"- {m}" for m in fix_features['sanitization_methods']) or "无"}

### 4. 验证函数
{chr(10).join(f"- {v}" for v in fix_features['validation_functions']) or "无"}

## 候选Commit代码
```python
{candidate_code}
```

## 分析任务
请判断这个commit是否是漏洞的**引入commit**，使用以下方法：

1. **特征对比**: 候选commit是否**缺失**上述修复代码中的安全特征？
   - 如果修复代码添加了`validatePath()`，候选commit是否直接使用路径而缺少验证？
   - 如果修复代码添加了`sanitizeInput()`，候选commit是否直接使用未清洗的输入？

2. **语义分析**: 考虑漏洞的根本原因，候选commit是否引入了不安全的代码模式？

3. **代码时序**: 候选commit的修改是否在漏洞存在的版本范围内？

## 输出格式
请以JSON格式输出你的分析结果：

```json
{{
  "is_intro_commit": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "基于特征对比和语义分析的理由...",
  "missing_features": ["缺失的安全特征1", "缺失的安全特征2"],
  "risk_assessment": "低/中/高风险"
}}
```

注意：
- 置信度应该基于对比分析的结果，而非主观判断
- 如果候选commit已经包含修复代码中的安全特征，则很可能不是引入commit
- 如果候选commit的代码模式与漏洞描述相符且缺少安全防护，则很可能是引入commit
"""

        return prompt

    # ============================================================================
    # 第三阶段：LLM层 - 精确度（Precision）
    # ============================================================================

    def analyze_candidate_with_llm(
        self,
        candidate: Dict,
        fix_features: Dict,
        vulnerability_desc: str,
        llm_client=None
    ) -> Dict:
        """
        使用LLM分析候选commit

        LLM层职责：
        - 进行语义分析
        - 提供详细的推理理由
        - 给出最终判断（基于规则层的候选）

        Args:
            candidate: 候选commit
            fix_features: 修复代码特征
            vulnerability_desc: 漏洞描述
            llm_client: LLM客户端

        Returns:
            分析结果
        """
        if llm_client is None:
            # 如果没有LLM客户端，返回规则分数
            return {
                "is_intro_commit": candidate["rule_score"] > 0.5,
                "confidence": candidate["rule_score"],
                "reasoning": "基于规则分析（无LLM）",
                "missing_features": [],
                "risk_assessment": "基于规则"
            }

        # 生成对比分析提示词
        prompt = self.generate_contrastive_analysis_prompt(
            candidate.get("code", ""),
            fix_features,
            vulnerability_desc
        )

        # 调用LLM
        # 这里需要实际的LLM调用逻辑
        # response = llm_client.generate(prompt)

        # 模拟返回
        return {
            "is_intro_commit": False,
            "confidence": 0.5,
            "reasoning": "需要实际LLM调用",
            "missing_features": [],
            "risk_assessment": "待分析"
        }

    # ============================================================================
    # 完整推理流程
    # ============================================================================

    def infer_intro_commit(
        self,
        candidates: List[Dict],
        patch_diff: str,
        vulnerability_desc: str,
        llm_client=None
    ) -> List[Dict]:
        """
        完整的引入commit推理流程

        流程：
        1. 提取修复代码特征
        2. 规则层过滤（召回）
        3. LLM层分析（精确度）
        4. 综合排序

        Args:
            candidates: 所有候选commit
            patch_diff: 修复补丁
            vulnerability_desc: 漏洞描述
            llm_client: LLM客户端

        Returns:
            排序后的候选commit列表
        """
        # 步骤1: 提取修复代码特征
        fix_features = self.extract_fix_features(patch_diff)

        # 步骤2: 规则层过滤
        filtered = self.filter_candidates_by_rules(
            candidates,
            fix_features["security_patterns"],
            [kw for kw in get_security_keywords()]
        )

        # 步骤3: LLM层分析
        for candidate in filtered:
            llm_result = self.analyze_candidate_with_llm(
                candidate,
                fix_features,
                vulnerability_desc,
                llm_client
            )
            candidate["llm_analysis"] = llm_result

        # 步骤4: 综合排序
        # 综合分数 = 0.4 * 规则分数 + 0.6 * LLM置信度
        for candidate in filtered:
            llm_conf = candidate["llm_analysis"].get("confidence", 0)
            candidate["final_score"] = (
                0.4 * candidate["rule_score"] +
                0.6 * llm_conf
            )

        # 按最终分数排序
        sorted_candidates = sorted(
            filtered,
            key=lambda x: x["final_score"],
            reverse=True
        )

        return sorted_candidates
