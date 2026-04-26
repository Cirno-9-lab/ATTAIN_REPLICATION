#!/usr/bin/env python3
"""快速测试4个案例 - 不调用LLM"""

import sys
import json
sys.path.insert(0, '/home/xinweimao/alv_evaluate/myResearch/workspace/code')

from intro_infer_v6_improved import (
    load_intro_context, load_patch_results, load_fix_code_context,
    has_meaningful_fix_features, generate_candidates_from_intro
)
from contrastive_inference_engine import ContrastiveInferenceEngine
from security_features import get_security_features_by_category

def quick_test():
    # 初始化
    engine = ContrastiveInferenceEngine()
    intro_data = load_intro_context()
    
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
    
    print("\n" + "="*80)
    print("快速测试 - 规则层筛选（不调用LLM）")
    print("="*80)
    
    results = []
    
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
        
        # 步骤1: 加载修复commits
        fix_commits = load_patch_results(cve_id)
        if not fix_commits:
            print("✗ 无修复commit数据")
            results.append({'cve': cve_id, 'status': 'no_fix_commits'})
            continue
        
        print(f"✓ 找到 {len(fix_commits)} 个修复commit")
        
        # 步骤2: 分析修复特征
        security_measures, security_patterns = load_fix_code_context(cve_id, fix_commits)
        
        if not security_measures:
            fix_features = {}
            has_features = False
            feature_count = 0
        else:
            all_added = []
            for file_path, measures in security_measures.items():
                all_added.extend(measures.get("added", []))
            
            patch_diff = "\n".join(all_added)
            fix_features = engine.extract_fix_features(patch_diff)
            has_features, feature_count = has_meaningful_fix_features(fix_features)
        
        print(f"✓ 修复特征: {feature_count} 个 ({'有' if has_features else '无'}安全特征)")
        
        # 步骤3: 加载候选intro commits
        version_list = intro_data[cve_id]
        intro_candidates = None
        for version_info in version_list:
            if version_info.get('base_tag') == base_tag:
                intro_candidates = version_info.get('results', {})
                break
        
        if not intro_candidates:
            print("✗ 无候选intro commit")
            results.append({'cve': cve_id, 'status': 'no_candidates'})
            continue
        
        print(f"✓ 找到 {len(intro_candidates)} 个候选commit")
        
        # 步骤4: 规则层筛选
        candidates = generate_candidates_from_intro(intro_candidates, fix_commits)
        
        fix_keywords = [kw for kw in get_security_features_by_category("path").values()]
        fix_keywords.extend([kw for kw in get_security_features_by_category("auth").values()])
        fix_patterns = fix_features.get("security_patterns", []) if fix_features else []
        
        filtered = engine.filter_candidates_by_rules(
            candidates,
            fix_patterns,
            [item for sublist in fix_keywords for item in sublist]
        )
        
        print(f"✓ 规则筛选后: {len(filtered)} 个候选")
        
        if filtered:
            print("\n  前3个候选 (按规则分数排序):")
            for j, cand in enumerate(sorted(filtered, key=lambda x: x.get('rule_score', 0), reverse=True)[:3], 1):
                print(f"    {j}. {cand['hash'][:8]}... (规则分数: {cand.get('rule_score', 0):.4f})")
            
            if expected == 'should_find':
                print(f"\n✅ 测试通过：预期找到，规则筛选后有候选")
                test_result = 'pass'
            else:
                print(f"\n⚠️  注意：预期不找，但规则筛选后有候选")
                print(f"   需要LLM进一步判断（使用高阈值0.65）")
                test_result = 'need_llm'
        else:
            print("\n✗ 规则筛选后无候选")
            
            if expected == 'should_not_find':
                print(f"✅ 测试通过：预期不找，规则筛选后无候选")
                test_result = 'pass'
            else:
                print(f"❌ 测试失败：预期找到，但规则筛选后无候选")
                test_result = 'fail'
        
        results.append({
            'cve': cve_id,
            'expected': expected,
            'result': test_result,
            'has_fix_features': has_features,
            'feature_count': feature_count,
            'candidates_before_filter': len(candidates),
            'candidates_after_filter': len(filtered)
        })
    
    # 总结
    print("\n" + "="*80)
    print("测试总结")
    print("="*80)
    
    pass_count = sum(1 for r in results if r.get('result') == 'pass')
    need_llm_count = sum(1 for r in results if r.get('result') == 'need_llm')
    fail_count = sum(1 for r in results if r.get('result') == 'fail')
    
    print(f"\n总计: {len(results)} 个测试")
    print(f"  ✅ 通过: {pass_count}")
    print(f"  ⚠️  需要LLM判断: {need_llm_count}")
    print(f"  ❌ 失败: {fail_count}")
    
    print("\n详细结果:")
    for r in results:
        print(f"  {r['cve'].upper()}: {r.get('result', 'unknown')} "
              f"(修复特征:{r.get('feature_count', 0)}, "
              f"候选:{r.get('candidates_before_filter', 0)}->{r.get('candidates_after_filter', 0)})")
    
    # 保存结果
    with open('quick_test_results.json', 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n详细结果已保存到: quick_test_results.json")

if __name__ == '__main__':
    quick_test()
