#!/usr/bin/env python3
"""评估规则层准确率并与真值对比"""

import pandas as pd
import json
import sys
from collections import defaultdict

sys.path.insert(0, '/home/xinweimao/alv_evaluate/myResearch/workspace/code')

from intro_infer_v6_improved import (
    load_intro_context, load_patch_results, load_fix_code_context,
    has_meaningful_fix_features, generate_candidates_from_intro
)
from contrastive_inference_engine import ContrastiveInferenceEngine
from security_features import get_security_features_by_category

def load_ground_truth(excel_path):
    """加载真值数据"""
    df = pd.read_excel(excel_path)
    
    # 创建字典：{cve_id: {base_tag: affected_status}}
    ground_truth = defaultdict(dict)
    
    for _, row in df.iterrows():
        cve_id = str(row.get('CVE_ID', '')).lower().strip()
        version = str(row.get('Version', '')).strip()
        true_affected = str(row.get('True Affected Version', '')).strip().lower()
        
        if not cve_id or not version:
            continue
        
        # True Affected Version字段：
        # - "affected"：该版本受漏洞影响
        # - "not affected"：该版本不受影响
        affected = (true_affected == 'affected')
        
        ground_truth[cve_id][version] = {
            'affected': affected,
            'true_affected_version': true_affected
        }
    
    return ground_truth

def evaluate_rule_layer(ground_truth, intro_data, rule_threshold=0.01):
    """评估规则层性能"""
    engine = ContrastiveInferenceEngine()
    
    results = {
        'total': 0,
        'true_positive': 0,   # 预测有intro commit，实际not affected
        'true_negative': 0,   # 预测无intro commit，实际affected
        'false_positive': 0,  # 预测有intro commit，实际affected
        'false_negative': 0,  # 预测无intro commit，实际not affected
        'details': []
    }
    
    for cve_id, version_list in intro_data.items():
        # 加载修复commits
        fix_commits = load_patch_results(cve_id)
        if not fix_commits:
            continue
        
        # 分析修复特征
        security_measures, security_patterns = load_fix_code_context(cve_id, fix_commits)
        if security_measures:
            all_added = []
            for file_path, measures in security_measures.items():
                all_added.extend(measures.get("added", []))
            patch_diff = "\n".join(all_added)
            fix_features = engine.extract_fix_features(patch_diff)
            has_features, _ = has_meaningful_fix_features(fix_features)
        else:
            fix_features = {}
            has_features = False
        
        for version_info in version_list:
            base_tag = version_info.get('base_tag', '')
            if not base_tag:
                continue
            
            # 检查是否有真值
            if cve_id not in ground_truth or base_tag not in ground_truth[cve_id]:
                continue
            
            results['total'] += 1
            
            # 获取真值
            truth = ground_truth[cve_id][base_tag]
            actual_not_affected = not truth['affected']  # True表示漏洞在这个版本引入
            
            # 获取候选commits
            intro_candidates = version_info.get('results', {})
            if not intro_candidates:
                continue
            
            # 生成候选列表
            candidates = generate_candidates_from_intro(intro_candidates, fix_commits)
            
            # 规则层筛选
            fix_keywords = [kw for kw in get_security_features_by_category("path").values()]
            fix_keywords.extend([kw for kw in get_security_features_by_category("auth").values()])
            fix_patterns = fix_features.get("security_patterns", []) if fix_features else []
            
            filtered = engine.filter_candidates_by_rules(
                candidates,
                fix_patterns,
                [item for sublist in fix_keywords for item in sublist]
            )
            
            # 找到最高分数的候选
            if filtered:
                max_score = max(c.get('rule_score', 0) for c in filtered)
                predicted_has_intro = max_score >= rule_threshold
            else:
                max_score = 0.0
                predicted_has_intro = False
            
            # 判断结果
            if predicted_has_intro and actual_not_affected:
                results['true_positive'] += 1
                status = 'TP'
            elif not predicted_has_intro and not actual_not_affected:
                results['true_negative'] += 1
                status = 'TN'
            elif predicted_has_intro and not actual_not_affected:
                results['false_positive'] += 1
                status = 'FP'
            else:
                results['false_negative'] += 1
                status = 'FN'
            
            # 保存详细信息
            results['details'].append({
                'cve_id': cve_id,
                'base_tag': base_tag,
                'actual_not_affected': actual_not_affected,
                'predicted_has_intro': predicted_has_intro,
                'max_rule_score': max_score,
                'status': status,
                'has_fix_features': has_features,
                'true_affected_version': truth['true_affected_version']
            })
    
    return results

def find_optimal_threshold(ground_truth, intro_data, thresholds=None):
    """寻找最佳阈值"""
    if thresholds is None:
        thresholds = [0.01, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    
    print("\n" + "="*100)
    print("阈值扫描 - 寻找最佳阈值")
    print("="*100)
    
    best_threshold = 0.01
    best_f1 = 0.0
    all_results = []
    
    for threshold in thresholds:
        results = evaluate_rule_layer(ground_truth, intro_data, threshold)
        
        tp = results['true_positive']
        tn = results['true_negative']
        fp = results['false_positive']
        fn = results['false_negative']
        total = results['total']
        
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        all_results.append({
            'threshold': threshold,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'tp': tp,
            'tn': tn,
            'fp': fp,
            'fn': fn
        })
        
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
    
    # 打印结果表格
    print(f"\n{'阈值':<10} {'准确率':<10} {'精确率':<10} {'召回率':<10} {'F1':<10} {'TP':<6} {'TN':<6} {'FP':<6} {'FN':<6}")
    print("-" * 100)
    for r in all_results:
        print(f"{r['threshold']:<10.2f} {r['accuracy']:<10.4f} {r['precision']:<10.4f} {r['recall']:<10.4f} {r['f1']:<10.4f} {r['tp']:<6} {r['tn']:<6} {r['fp']:<6} {r['fn']:<6}")
    
    print(f"\n最佳阈值: {best_threshold:.2f} (F1 = {best_f1:.4f})")
    
    return best_threshold, all_results

def main():
    excel_path = '/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/execution_result.xlsx'
    
    print("\n" + "="*100)
    print("规则层评估 - 与真值对比")
    print("="*100)
    
    # 加载真值
    print("\n[1/4] 加载真值数据...")
    ground_truth = load_ground_truth(excel_path)
    print(f"✓ 共 {len(ground_truth)} 个CVE有真值数据")
    
    # 加载intro数据
    print("\n[2/4] 加载intro_context数据...")
    intro_data = load_intro_context()
    print(f"✓ 共 {len(intro_data)} 个CVE")
    
    # 寻找最佳阈值
    print("\n[3/4] 寻找最佳阈值...")
    best_threshold, all_threshold_results = find_optimal_threshold(ground_truth, intro_data)
    
    # 使用最佳阈值进行最终评估
    print("\n[4/4] 使用最佳阈值进行最终评估...")
    final_results = evaluate_rule_layer(ground_truth, intro_data, best_threshold)
    
    tp = final_results['true_positive']
    tn = final_results['true_negative']
    fp = final_results['false_positive']
    fn = final_results['false_negative']
    total = final_results['total']
    
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\n" + "="*100)
    print("最终结果（最佳阈值 = {:.2f}）".format(best_threshold))
    print("="*100)
    print(f"\n总计测试样本: {total}")
    print(f"  True Positive (TP): {tp}  (预测有intro，实际not affected)")
    print(f"  True Negative (TN): {tn}  (预测无intro，实际affected)")
    print(f"  False Positive (FP): {fp}  (预测有intro，实际affected)")
    print(f"  False Negative (FN): {fn}  (预测无intro，实际not affected)")
    
    print(f"\n性能指标:")
    print(f"  准确率 (Accuracy): {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  精确率 (Precision): {precision:.4f} ({precision*100:.2f}%)")
    print(f"  召回率 (Recall): {recall:.4f} ({recall*100:.2f}%)")
    print(f"  F1分数: {f1:.4f}")
    
    # 保存详细结果
    output = {
        'best_threshold': best_threshold,
        'metrics': {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        },
        'confusion_matrix': {
            'tp': tp,
            'tn': tn,
            'fp': fp,
            'fn': fn
        },
        'threshold_scan': all_threshold_results,
        'details': final_results['details']
    }
    
    output_path = '/home/xinweimao/alv_evaluate/myResearch/workspace/rule_layer_evaluation.json'
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n详细结果已保存到: {output_path}")
    print("="*100)

if __name__ == '__main__':
    main()
