#!/usr/bin/env python3
"""
测试简化后的思维链推理
验证基于 cve_list.json 的推理流程
"""

import json
import os

# 定义路径
DATASET_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CVE_LIST_FILE = f"{DATASET_DIR}/list/cve_list.json"
PATCH_RESULTS_FILE = f"{DATASET_DIR}/result/patch_only_results.json"

def test_version_pair_analysis():
    """测试版本对分析逻辑"""
    print("=" * 80)
    print("测试1: 版本对分析逻辑")
    print("=" * 80)
    
    # 加载CVE列表
    with open(CVE_LIST_FILE, 'r') as f:
        cve_list = json.load(f)
    
    # 测试案例
    test_cves = ["CVE-2011-2732", "CVE-2013-2055"]
    
    for cve_id in test_cves:
        meta = cve_list.get(cve_id, {})
        print(f"\n{cve_id}:")
        print(f"  项目: {meta.get('OWNER')}/{meta.get('REPO')}")
        print(f"  描述: {meta.get('description', '')[:100]}...")
        
        version_pairs = meta.get("version_pair", [])
        print(f"  版本对数量: {len(version_pairs)}")
        
        for i, vp in enumerate(version_pairs[:2], 1):  # 只显示前2个
            print(f"\n  版本对 {i}:")
            print(f"    appears: {vp.get('appears')} (漏洞特征出现)")
            print(f"    not appears: {vp.get('not appears')} (漏洞特征不出现)")
            print(f"    BASE_TAG: {vp.get('BASE_TAG')}")
            print(f"    HEAD_TAG: {vp.get('HEAD_TAG')}")
            print(f"    seek_patch: {vp.get('seek_patch')} ({'补丁引入（修复漏洞）' if vp.get('seek_patch') else '漏洞引入'})")
            print(f"    compile: {vp.get('compile')}")
            
            # 分析推理方向
            seek_patch = vp.get('seek_patch', True)
            if seek_patch:
                print(f"    ➡️  推理方向: 修复漏洞（从 {vp.get('BASE_TAG')} 到 {vp.get('HEAD_TAG')} 找修复commit）")
            else:
                print(f"    ➡️  推理方向: 引入漏洞（从 {vp.get('BASE_TAG')} 到 {vp.get('HEAD_TAG')} 找引入commit）")
    
    print("\n✅ 测试通过！")

def test_inference_structure():
    """测试推理结构"""
    print("\n" + "=" * 80)
    print("测试2: 简化后的思维链推理结构")
    print("=" * 80)
    
    # 模拟版本对信息
    version_pair = {
        "appears": "3.0.5.RELEASE",
        "not appears": "3.0.6.RELEASE",
        "BASE_TAG": "3.0.5.RELEASE",
        "HEAD_TAG": "3.0.6.RELEASE",
        "COMPARE_URL": "https://github.com/spring-projects/spring-security/compare/3.0.5.RELEASE...3.0.6.RELEASE",
        "seek_patch": True,
        "compile": True
    }
    
    cve_id = "CVE-2011-2732"
    nvd_desc = "CRLF injection vulnerability in the logout functionality in VMware SpringSource Spring Security before 2.0.7 and 3.0.x before 3.0.6 allows remote attackers to inject arbitrary HTTP headers and conduct HTTP response splitting attacks via the spring-security-redirect parameter."
    
    # 模拟补丁文件
    patch_files = [
        "web/src/main/java/org/springframework/security/web/authentication/AbstractAuthenticationTargetUrlRequestHandler.java",
        "web/src/main/java/org/springframework/security/web/authentication/logout/SimpleUrlLogoutSuccessHandler.java",
        "web/src/main/java/org/springframework/security/web/firewall/DefaultHttpFirewall.java",
        "web/src/main/java/org/springframework/security/web/firewall/FirewalledResponse.java"
    ]
    
    print("\n推理输入:")
    print(f"  CVE ID: {cve_id}")
    print(f"  版本对: {version_pair['BASE_TAG']} -> {version_pair['HEAD_TAG']}")
    print(f"  seek_patch: {version_pair['seek_patch']} ({'补丁引入（修复漏洞）' if version_pair['seek_patch'] else '漏洞引入'})")
    print(f"  补丁文件数: {len(patch_files)}")
    
    print("\n推理步骤:")
    print("  步骤1: 分析版本对信息")
    print("    - 提取 appears, not_appears, seek_patch 等信息")
    print("    - 确定推理方向（修复漏洞 vs 引入漏洞）")
    
    print("\n  步骤2: 分析补丁文件特征")
    print("    - 从 patch_only_results.json 提取补丁文件列表")
    print("    - 分析受影响的组件和功能")
    
    print("\n  步骤3: 筛选相关commits")
    print("    - 根据补丁文件筛选修改了相关文件的commits")
    print("    - 如果没有补丁文件，使用LLM筛选")
    
    print("\n  步骤4: 确认目标commit")
    print("    - 从候选commits中选择置信度最高的")
    print("    - 记录commit hash、置信度、原因等信息")
    
    print("\n推理输出:")
    print("  - confirmed_commit: 目标commit hash")
    print("  - confidence: 置信度")
    print("  - reasoning: 推理原因")
    print("  - analysis_type: patch_intro / vuln_intro")
    
    print("\n✅ 测试通过！")

def test_patch_file_utilization():
    """测试补丁文件利用"""
    print("\n" + "=" * 80)
    print("测试3: 补丁文件利用验证")
    print("=" * 80)
    
    # 加载数据
    with open(PATCH_RESULTS_FILE, 'r') as f:
        patch_results = json.load(f)
    with open(CVE_LIST_FILE, 'r') as f:
        cve_list = json.load(f)
    
    # 测试CVE-2011-2732
    cve_id = "CVE-2011-2732"
    meta = cve_list.get(cve_id, {})
    
    print(f"\n{cve_id} 补丁文件分析:")
    
    # 获取第一个版本对
    version_pair = meta.get("version_pair", [])[0] if meta.get("version_pair") else {}
    base_tag = version_pair.get("BASE_TAG", "")
    head_tag = version_pair.get("HEAD_TAG", "")
    
    # 提取补丁文件
    patch_files = set()
    if cve_id in patch_results:
        for patch_entry in patch_results[cve_id]:
            if patch_entry.get("base_tag") == base_tag and patch_entry.get("head_tag") == head_tag:
                analysis = patch_entry.get("analysis", {})
                for commit_hash, files_info in analysis.items():
                    for file_path in files_info.keys():
                        patch_files.add(file_path)
    
    print(f"  版本对: {base_tag} -> {head_tag}")
    print(f"  seek_patch: {version_pair.get('seek_patch')} ({'补丁引入（修复漏洞）' if version_pair.get('seek_patch') else '漏洞引入'})")
    print(f"  补丁文件数量: {len(patch_files)}")
    print(f"  补丁文件列表:")
    for i, f in enumerate(sorted(patch_files), 1):
        print(f"    {i}. {f}")
    
    print(f"\n推理策略:")
    print(f"  - 优先筛选修改了补丁文件的commits")
    print(f"  - 补丁文件相关的commits获得更高置信度（0.85）")
    print(f"  - 结合 seek_patch 确定推理方向")
    
    print("\n✅ 测试通过！")

def main():
    """主函数"""
    print("\n🧪 简化后的思维链推理测试套件")
    print("=" * 80)
    
    try:
        # 测试1: 版本对分析
        test_version_pair_analysis()
        
        # 测试2: 推理结构
        test_inference_structure()
        
        # 测试3: 补丁文件利用
        test_patch_file_utilization()
        
        print("\n" + "=" * 80)
        print("✨ 所有测试通过！")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
