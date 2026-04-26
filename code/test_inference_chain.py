#!/usr/bin/env python3
"""
测试思维链推理功能

演示如何使用VulnerabilityCommitInferenceChain来找到引入漏洞的commit
"""

import json
import sys

# 导入必要的模块
import llm
from intro_infer_embedding_v4 import VulnerabilityCommitInferenceChain

def test_cve_2014_3625():
    """
    测试案例: CVE-2014-3625 Spring Framework目录遍历漏洞
    """
    print("=" * 80)
    print("测试案例: CVE-2014-3625 Spring Framework目录遍历漏洞")
    print("=" * 80)
    
    # 初始化LLM客户端和思维链推理引擎
    llm_client = llm.Client()
    inference_chain = VulnerabilityCommitInferenceChain(llm_client)
    
    # 准备项目信息
    project_info = {
        "project_name": "Spring Framework",
        "vuln_description": (
            "Directory traversal vulnerability in Pivotal Spring Framework 3.0.4 through 3.2.x "
            "before 3.2.12, 4.0.x before 4.0.8, and 4.1.x before 4.1.2 allows remote attackers "
            "to read arbitrary files via unspecified vectors related to static resource handling."
        ),
        "cve_id": "CVE-2014-3625",
        "affected_versions": ["3.0.4", "3.1.0", "3.2.0", "3.2.11"],
        "fix_version": "3.2.12",
        "repo_url": "https://github.com/spring-projects/spring-framework",
        "prev_version": "v3.0.3.RELEASE"
    }
    
    print("\n项目信息:")
    print(json.dumps(project_info, indent=2, ensure_ascii=False))
    
    # 执行思维链推理
    print("\n" + "=" * 80)
    print("开始执行思维链推理...")
    print("=" * 80)
    
    result = inference_chain.run_full_chain(project_info)
    
    # 显示推理步骤
    print("\n推理步骤:")
    for i, step in enumerate(result["chain_steps"], 1):
        print(f"\n--- 步骤 {i}: {step['step']} ---")
        print(f"推理: {step['reasoning'][:100]}...")
        if isinstance(step['result'], dict):
            print(f"结果: {json.dumps(step['result'], indent=2, ensure_ascii=False)[:200]}...")
        else:
            print(f"结果: {str(step['result'])[:200]}...")
    
    # 显示最终结果
    print("\n" + "=" * 80)
    print("最终结果:")
    print("=" * 80)
    
    final_result = result["final_result"]["confirmed_commit"]
    print(json.dumps(final_result, indent=2, ensure_ascii=False))
    
    # 显示思维链总结
    print("\n" + "=" * 80)
    print("思维链总结:")
    print("=" * 80)
    print(result["summary"])
    
    # 保存完整结果
    output_file = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/test_inference_result.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n完整结果已保存到: {output_file}")
    
    return result

def test_simple_case():
    """
    简化测试案例 - 不需要实际调用LLM
    """
    print("\n" + "=" * 80)
    print("简化测试案例 - 演示思维链结构")
    print("=" * 80)
    
    # 创建一个简单的模拟推理链
    class SimpleInferenceChain:
        def __init__(self):
            self.steps = []
        
        def log_step(self, step_name, reasoning, result):
            self.steps.append({
                "step": step_name,
                "reasoning": reasoning,
                "result": result
            })
            print(f"✓ 完成: {step_name}")
            return result
        
        def run(self, project_name, vuln_desc):
            # 步骤1
            self.log_step(
                "识别CVE编号",
                "通过搜索引擎查找相关CVE",
                {"cve_id": "CVE-2014-3625"}
            )
            
            # 步骤2
            self.log_step(
                "获取修复信息",
                "从官方安全公告获取修复commits",
                {"fix_commits": ["9beae9ae", "9cef8e30", "3f68cd63"]}
            )
            
            # 步骤3
            self.log_step(
                "分析修复代码",
                "分析修复代码添加的安全措施",
                {"security_measures": ["路径验证", "位置验证", "URL解码"]}
            )
            
            # 步骤4
            self.log_step(
                "确定引入版本",
                "确定漏洞首次出现的版本",
                {"intro_version": "v3.0.4.RELEASE"}
            )
            
            # 步骤5
            self.log_step(
                "检查版本历史",
                "获取版本间的所有commits",
                {"commits_count": 179}
            )
            
            # 步骤6
            self.log_step(
                "筛选相关commits",
                "根据漏洞特征筛选相关commits",
                {"candidates": ["5a1bd208", "ab13e9b5"]}
            )
            
            # 步骤7
            self.log_step(
                "确认引入commit",
                "验证哪个commit缺少安全检查",
                {"confirmed_commit": "5a1bd208"}
            )
            
            return self.steps
    
    # 运行简化测试
    chain = SimpleInferenceChain()
    steps = chain.run("Spring Framework", "Directory traversal in static resource handling")
    
    print("\n推理步骤总数:", len(steps))
    print("最终确认的commit:", steps[-1]["result"]["confirmed_commit"])

def main():
    """
    主函数
    """
    print("\n🧠 思维链推理功能测试")
    print("=" * 80)
    
    # 选择测试模式
    if len(sys.argv) > 1 and sys.argv[1] == "--simple":
        # 简化测试
        test_simple_case()
    else:
        # 完整测试（需要LLM API）
        try:
            test_cve_2014_3625()
        except Exception as e:
            print(f"\n❌ 完整测试失败: {e}")
            print("\n运行简化测试...")
            test_simple_case()
    
    print("\n✨ 测试完成!")

if __name__ == "__main__":
    main()
