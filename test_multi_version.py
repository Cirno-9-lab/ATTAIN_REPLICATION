#!/usr/bin/env python3
"""测试多个版本区间的CVE处理"""

import sys
import json
sys.path.insert(0, '/home/xinweimao/alv_evaluate/myResearch/workspace/code')

from intro_infer_v6_improved import process_single_cve
from llm import Client
from contrastive_inference_engine import ContrastiveInferenceEngine

def test_multi_version_cves():
    # 加载CVE列表
    with open('dataset/intro_url.json', 'r') as f:
        cve_list = json.load(f)
    
    # 选择几个有多个版本区间的CVE进行测试
    test_cves = [
        'CVE-2014-3625',   # 3个版本区间
        'CVE-2019-16869',  # 8个版本区间
        'CVE-2022-22978',  # 3个版本区间
    ]
    
    # 初始化
    llm_client = Client()
    engine = ContrastiveInferenceEngine()
    
    results = {}
    
    for cve_id in test_cves:
        if cve_id not in cve_list:
            print(f"跳过 {cve_id}: 不在列表中")
            continue
        
        version_pairs = cve_list[cve_id].get("version_pair", [])
        print(f"\n{'='*80}")
        print(f"测试 {cve_id} ({len(version_pairs)}个版本区间)")
        print(f"{'='*80}")
        
        cve_results = []
        for idx, version_pair in enumerate(version_pairs):
            base_tag = version_pair.get("BASE_TAG", "")
            head_tag = version_pair.get("HEAD_TAG", "")
            
            print(f"\n版本区间 {idx+1}/{len(version_pairs)}: {base_tag} -> {head_tag}")
            
            # 处理单个版本区间
            status, analysis, skip_reason = process_single_cve(
                cve_id, base_tag, head_tag, llm_client, engine
            )
            
            output_entry = {
                "base_tag": base_tag,
                "head_tag": head_tag,
                "analysis": analysis
            }
            
            if status == "skipped":
                output_entry["note"] = f"skipped: {skip_reason}"
                print(f"  状态: 跳过 - {skip_reason}")
            elif status == "found_intro":
                commits_count = len(analysis.get("intro_commits", []))
                print(f"  状态: 找到 {commits_count} 个候选commit")
                if analysis.get("intro_commits"):
                    for commit in analysis["intro_commits"][:3]:  # 只显示前3个
                        print(f"    - {commit['hash'][:8]}... (置信度: {commit['confidence']:.4f})")
            else:
                output_entry["note"] = "no_intro_commit_found"
                print(f"  状态: 未找到intro commit")
            
            cve_results.append(output_entry)
        
        results[cve_id.lower()] = cve_results
    
    # 保存测试结果
    output_path = 'test_multi_version_results.json'
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*80}")
    print(f"测试完成！结果已保存到: {output_path}")
    print(f"{'='*80}")

if __name__ == '__main__':
    test_multi_version_cves()
