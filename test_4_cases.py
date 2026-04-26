#!/usr/bin/env python3
"""测试4个案例是否能正确检测"""

import sys
import json
sys.path.insert(0, '/home/xinweimao/alv_evaluate/myResearch/workspace/code')

from intro_infer_v6_improved import process_single_cve, load_intro_context
from llm import Client
from contrastive_inference_engine import ContrastiveInferenceEngine

def test_cases():
    # 初始化
    print("初始化...")
    llm_client = Client()
    engine = ContrastiveInferenceEngine()
    
    # 加载intro_context数据
    intro_data = load_intro_context()
    
    # 测试案例
    test_cases = [
        {
            'cve_id': 'cve-2023-51080',
            'base_tag': '5.8.21',
            'head_tag': '5.8.22',
            'expected': 'should_find',
            'description': '应该找到intro commit'
        },
        {
            'cve_id': 'cve-2014-3625',
            'base_tag': 'v3.0.3.RELEASE',
            'head_tag': 'v3.0.4.RELEASE',
            'expected': 'should_find',
            'description': '应该找到intro commit'
        },
        {
            'cve_id': 'cve-2014-0097',
            'base_tag': '3.0.8.RELEASE',
            'head_tag': '3.1.0.RELEASE',
            'expected': 'should_find',
            'description': '应该找到intro commit'
        },
        {
            'cve_id': 'cve-2014-125087',
            'base_tag': 'v1.0',
            'head_tag': 'v1.1',
            'expected': 'should_not_find',
            'description': '不应该找到intro commit（漏洞在v1.0就存在）'
        }
    ]
    
    results = []
    
    print("\n" + "="*80)
    print("开始测试4个案例")
    print("="*80)
    
    for i, case in enumerate(test_cases, 1):
        cve_id = case['cve_id']
        base_tag = case['base_tag']
        head_tag = case['head_tag']
        expected = case['expected']
        description = case['description']
        
        print(f"\n【测试 {i}/4】 {cve_id.upper()}")
        print(f"版本区间: {base_tag} -> {head_tag}")
        print(f"预期: {description}")
        print("-" * 80)
        
        # 检查是否在intro_context中
        if cve_id not in intro_data:
            print(f"⚠️  CVE不在intro_context.json中，跳过")
            results.append({
                'cve': cve_id,
                'status': 'skipped',
                'reason': 'not_in_intro_context'
            })
            continue
        
        # 查找对应的版本区间
        version_list = intro_data[cve_id]
        intro_candidates = None
        
        for version_info in version_list:
            if version_info.get('base_tag') == base_tag and version_info.get('head_tag') == head_tag:
                intro_candidates = version_info.get('results', {})
                break
        
        if intro_candidates is None:
            print(f"⚠️  版本区间 {base_tag} -> {head_tag} 在intro_context中找不到")
            results.append({
                'cve': cve_id,
                'status': 'skipped',
                'reason': 'version_not_found'
            })
            continue
        
        print(f"候选commit数: {len(intro_candidates)}")
        
        # 处理
        status, analysis, skip_reason = process_single_cve(
            cve_id, base_tag, head_tag, llm_client, engine, intro_candidates
        )
        
        # 分析结果
        if status == "found_intro":
            commits = analysis.get('intro_commits', [])
            print(f"✓ 找到 {len(commits)} 个候选intro commit")
            
            for j, commit in enumerate(commits[:3], 1):  # 只显示前3个
                print(f"  {j}. {commit['hash'][:8]}... (置信度: {commit['confidence']:.4f})")
                print(f"     有修复特征: {commit['has_fix_features']}, 特征数: {commit['feature_count']}")
            
            if expected == 'should_find':
                print(f"✅ 测试通过：预期找到，实际找到了")
                test_result = 'pass'
            else:
                print(f"❌ 测试失败：预期不找，实际找到了")
                test_result = 'fail'
                
        elif status == "no_intro":
            print("✗ 未找到intro commit")
            
            if expected == 'should_not_find':
                print(f"✅ 测试通过：预期不找，实际没找到")
                test_result = 'pass'
            else:
                print(f"❌ 测试失败：预期找到，实际没找到")
                test_result = 'fail'
                
        else:  # skipped
            print(f"⊘ 跳过: {skip_reason}")
            print(f"⚠️  测试未完成")
            test_result = 'skipped'
        
        results.append({
            'cve': cve_id,
            'status': status,
            'expected': expected,
            'result': test_result,
            'analysis': analysis,
            'skip_reason': skip_reason if status == 'skipped' else None
        })
    
    # 总结
    print("\n" + "="*80)
    print("测试总结")
    print("="*80)
    
    pass_count = sum(1 for r in results if r.get('result') == 'pass')
    fail_count = sum(1 for r in results if r.get('result') == 'fail')
    skip_count = sum(1 for r in results if r.get('result') == 'skipped')
    
    print(f"\n总计: {len(results)} 个测试")
    print(f"  ✅ 通过: {pass_count}")
    print(f"  ❌ 失败: {fail_count}")
    print(f"  ⚠️  跳过: {skip_count}")
    
    if fail_count == 0 and skip_count == 0:
        print("\n🎉 所有测试通过！")
    elif fail_count > 0:
        print(f"\n⚠️  有 {fail_count} 个测试失败，需要检查")
    else:
        print(f"\n⚠️  有 {skip_count} 个测试被跳过")
    
    # 保存详细结果
    with open('test_4_cases_results.json', 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n详细结果已保存到: test_4_cases_results.json")

if __name__ == '__main__':
    test_cases()
