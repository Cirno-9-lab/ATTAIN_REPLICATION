#!/usr/bin/env python3
"""
快速测试脚本：验证 v4 改进效果
只测试 cve-2023-51080 这个案例
"""
import os
import json
import sys

# 设置环境
os.environ["CUDA_VISIBLE_DEVICES"] = "6"

# 导入改进后的模块
import intro_infer_embedding_v4 as v4

def test_single_cve():
    print("=== 测试改进后的 v4 模块 ===\n")
    
    # 加载数据
    with open(v4.CONTEXT_FILE, 'r') as f:
        data = json.load(f)
    
    # 只测试 cve-2023-51080
    test_cve = "cve-2023-51080"
    if test_cve not in data:
        print(f"❌ 未找到 {test_cve}")
        return
    
    print(f"✓ 找到测试案例: {test_cve}")
    
    # 初始化审计器
    print("\n🚀 初始化审计器...")
    auditor = v4.DeepSeekStructuralAuditor()
    
    # 处理单个 CVE
    from tqdm import tqdm
    test_data = {test_cve: data[test_cve]}
    
    print(f"\n🔍 开始分析...")
    with tqdm(total=1) as pbar:
        auditor.process_cve_group(list(test_data.items()), pbar)
    
    # 输出结果
    result = auditor.results.get(test_cve, [])
    
    print(f"\n=== 分析结果 ===")
    print(f"CVE: {test_cve}")
    print(f"结果数量: {len(result)}")
    
    if result:
        for i, entry in enumerate(result, 1):
            print(f"\n--- Entry {i} ---")
            print(f"Base tag: {entry.get('base_tag')}")
            print(f"Head tag: {entry.get('head_tag')}")
            print(f"Analysis: {len(entry.get('analysis', {}))} commits")
            
            for c_hash, files in entry.get('analysis', {}).items():
                print(f"\n  Commit {c_hash[:8]}:")
                for f_path, analysis in files.items():
                    print(f"    File: {f_path.split('/')[-1]}")
                    print(f"      Method: {analysis.get('focal_method')}")
                    print(f"      V-score: {analysis.get('vule_score', 0):.4f}")
                    print(f"      S-score: {analysis.get('safe_score', 0):.4f}")
                    print(f"      Margin: {analysis.get('margin', 0):.4f}")
                    print(f"      LLM boost: {analysis.get('llm_boost', 0):.4f}")
                    print(f"      Verdict: {analysis.get('verdict')}")
    else:
        print("⚠️  结果为空")
    
    # 保存结果
    output_file = f"/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/test_{test_cve}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({test_cve: result}, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 结果已保存到: {output_file}")

if __name__ == "__main__":
    try:
        test_single_cve()
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
