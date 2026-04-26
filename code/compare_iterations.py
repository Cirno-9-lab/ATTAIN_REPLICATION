#!/usr/bin/env python3
"""
批量评估不同迭代的结果并生成对比报告
"""
import pandas as pd
import json
import os
from datetime import datetime

BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

# 定义不同迭代的结果文件
ITERATIONS = {
    "v1_f": "result/intro_contrastive_final_f.json",  # baseline: 68.29%
    "v2_g": "result/intro_contrastive_final_g.json",  # 第2次迭代
    # 未来添加更多迭代
}

def load_ground_truth():
    """加载Excel真值数据"""
    df = pd.read_excel(EXCEL_PATH)
    df['True Affected Version'] = df['True Affected Version'].str.lower()
    df['CVE_ID'] = df['CVE_ID'].str.lower()

    ground_truth = {}
    for _, row in df.iterrows():
        cve_id = row['CVE_ID']
        version = row['Version']
        true_affected = row['True Affected Version']
        key = (cve_id, version)
        ground_truth[key] = true_affected
    return ground_truth

def evaluate_iteration(result_path, ground_truth):
    """评估单个迭代的结果"""
    if not os.path.exists(result_path):
        return None, None, None

    with open(result_path, 'r') as f:
        data = json.load(f)

    model_results = {}
    for cve_id, entries in data.items():
        for entry in entries:
            base_tag = entry.get('base_tag', '')
            analysis = entry.get('analysis', {})
            has_intro = len(analysis) > 0
            key = (cve_id.lower(), base_tag)
            model_results[key] = {
                'has_intro': has_intro,
                'note': entry.get('note', '')
            }

    # 统计
    correct = 0
    total = 0
    errors = []

    for (cve_id, base_tag), model_result in model_results.items():
        key = (cve_id, base_tag)
        if key not in ground_truth:
            continue

        true_affected = ground_truth[key]
        has_intro = model_result['has_intro']
        expected_has_intro = (true_affected == "not affected")
        is_correct = (has_intro == expected_has_intro)

        if is_correct:
            correct += 1
        else:
            errors.append((cve_id, base_tag, true_affected, has_intro, f"Expected: {expected_has_intro}"))
        total += 1

    accuracy = correct / total if total > 0 else 0

    # 分析错误类型
    false_positive = sum(1 for e in errors if "Expected: False" in str(e[4]))
    false_negative = sum(1 for e in errors if "Expected: True" in str(e[4]))

    return accuracy, len(errors), {'FP': false_positive, 'FN': false_negative}

def generate_report():
    """生成对比报告"""
    print("="*100)
    print(f"迭代优化对比报告 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*100)

    ground_truth = load_ground_truth()
    print(f"\n基准数据: {len(ground_truth)} 条记录")
    print(f"目标准确率: 80%")
    print("-"*100)

    # 评估所有迭代
    results = []
    for name, path in ITERATIONS.items():
        accuracy, error_count, error_types = evaluate_iteration(os.path.join(BASE_PATH, path), ground_truth)
        if accuracy is not None:
            results.append({
                'name': name,
                'accuracy': accuracy,
                'errors': error_count,
                'FP': error_types['FP'],
                'FN': error_types['FN']
            })

    # 打印对比表格
    print(f"\n{'迭代':<15} {'准确率':<12} {'错误数':<10} {'FP':<8} {'FN':<8} {'状态'}")
    print("-"*70)

    for r in results:
        status = "✅ 达标" if r['accuracy'] >= 0.80 else ("⚠️  未达标" if r['accuracy'] >= 0.70 else "❌ 需优化")
        print(f"{r['name']:<15} {r['accuracy']*100:>5.2f}%     {r['errors']:<10} {r['FP']:<8} {r['FN']:<8} {status}")

    # 生成详细分析
    print(f"\n{'='*100}")
    print("详细分析")
    print(f"{'='*100}")

    # 按准确率排序
    results.sort(key=lambda x: x['accuracy'], reverse=True)

    for i, r in enumerate(results):
        print(f"\n迭代 {i+1}: {r['name']}")
        print(f"  准确率: {r['accuracy']*100:.2f}%")
        print(f"  错误数: {r['errors']}")
        print(f"  误报 (FP): {r['FP']} - 真值是affected，模型误判为有intro commit")
        print(f"  漏报 (FN): {r['FN']} - 真值是not affected，模型漏判为无intro commit")

        if r['accuracy'] >= 0.80:
            print(f"  ✅ 已达到目标！")
        elif r['accuracy'] >= 0.75:
            print(f"  ⚠️  接近目标，建议继续优化")
        else:
            print(f"  ❌ 需要大幅优化")

    # 推荐下一步
    print(f"\n{'='*100}")
    print("优化建议")
    print(f"{'='*100}")

    best_result = results[0]
    if best_result['accuracy'] >= 0.80:
        print("✅ 已达到目标准确率80%！")
        print("   可以停止迭代，或继续优化以提高性能。")
    else:
        gap = 0.80 - best_result['accuracy']
        print(f"⚠️  当前最佳准确率 {best_result['accuracy']*100:.2f}%，距离目标还有 {gap*100:.2f}%")

        if best_result['FN'] > best_result['FP']:
            print(f"\n主要问题: 漏报过多 ({best_result['FN']} > {best_result['FP']})")
            print("建议:")
            print("  1. 降低threshold (例如: 0.25 → 0.22 → 0.20)")
            print("  2. 增加MAX_LLM_CALLS_PER_CVE (例如: 7 → 10)")
            print("  3. 提高base confidence (例如: 0.48 → 0.50)")
            print("  4. 优化LLM prompt以减少误判")
        else:
            print(f"\n主要问题: 误报过多 ({best_result['FP']} > {best_result['FN']})")
            print("建议:")
            print("  1. 提高threshold (例如: 0.25 → 0.30)")
            print("  2. 优化规则筛选逻辑，减少false positives")
            print("  3. 优化LLM prompt以更好区分intro commit和refactoring")
            print("  4. 增加代码变更规模的下限")

    print(f"\n{'='*100}\n")

    return results

if __name__ == "__main__":
    generate_report()
