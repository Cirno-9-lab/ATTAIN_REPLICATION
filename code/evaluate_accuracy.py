#!/usr/bin/env python3
import pandas as pd
import json
import os

BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")
RESULT_PATH = os.path.join(BASE_PATH, "result/intro_contrastive_final_f.json")

def load_ground_truth():
    """加载Excel真值数据"""
    df = pd.read_excel(EXCEL_PATH)
    
    # 标准化列名
    df['True Affected Version'] = df['True Affected Version'].str.lower()
    df['CVE_ID'] = df['CVE_ID'].str.lower()
    
    # 构建查找字典: (cve_id, base_tag) -> true_affected
    ground_truth = {}
    for _, row in df.iterrows():
        cve_id = row['CVE_ID']
        version = row['Version']
        true_affected = row['True Affected Version']
        
        key = (cve_id, version)
        ground_truth[key] = true_affected
    
    return ground_truth

def load_model_results():
    """加载模型输出结果"""
    with open(RESULT_PATH, 'r') as f:
        data = json.load(f)
    
    results = {}
    for cve_id, entries in data.items():
        for entry in entries:
            base_tag = entry.get('base_tag', '')
            analysis = entry.get('analysis', {})
            
            # 如果analysis为空或note包含skipped，则没有找到intro commit
            has_intro = len(analysis) > 0
            
            key = (cve_id.lower(), base_tag)
            results[key] = {
                'has_intro': has_intro,
                'note': entry.get('note', '')
            }
    
    return results

def evaluate():
    """评估准确率"""
    print("加载真值数据...")
    ground_truth = load_ground_truth()
    print(f"真值记录数: {len(ground_truth)}")
    
    print("\n加载模型结果...")
    model_results = load_model_results()
    print(f"模型结果记录数: {len(model_results)}")
    
    # 统计
    correct = 0
    total = 0
    errors = []
    
    print("\n评估结果:")
    print(f"{'CVE':<20} {'Base Tag':<20} {'真值':<15} {'模型输出':<10} {'结果':<10}")
    print("=" * 80)
    
    for (cve_id, base_tag), model_result in model_results.items():
        key = (cve_id, base_tag)
        
        if key not in ground_truth:
            errors.append((cve_id, base_tag, "No ground truth", model_result['has_intro'], "Missing"))
            continue
        
        true_affected = ground_truth[key]
        has_intro = model_result['has_intro']
        
        # 判断逻辑：
        # - 如果真值是 "not affected"，说明该版本受漏洞影响，应该找到intro commit
        # - 如果真值是 "affected"，说明该版本不受漏洞影响，不应该找到intro commit
        expected_has_intro = (true_affected == "not affected")
        
        is_correct = (has_intro == expected_has_intro)
        
        if is_correct:
            correct += 1
            status = "✓"
        else:
            status = "✗"
            errors.append((cve_id, base_tag, true_affected, has_intro, f"Expected: {expected_has_intro}"))
        
        total += 1
        
        model_output = "yes" if has_intro else "no"
        print(f"{cve_id:<20} {base_tag:<20} {true_affected:<15} {model_output:<10} {status:<10}")
    
    accuracy = correct / total if total > 0 else 0
    
    print(f"\n{'='*80}")
    print(f"准确率: {accuracy:.2%} ({correct}/{total})")
    print(f"目标: 70%")
    print(f"差距: {accuracy - 0.70:.2%}")
    print(f"{'='*80}")
    
    if errors:
        print(f"\n错误列表 ({len(errors)}):")
        print(f"{'CVE':<20} {'Base Tag':<20} {'真值':<15} {'模型输出':<10} {'错误信息'}")
        print("-" * 80)
        for cve_id, base_tag, true_affected, has_intro, error_info in errors[:20]:  # 只显示前20个
            model_output = "yes" if has_intro else "no"
            print(f"{cve_id:<20} {base_tag:<20} {true_affected:<15} {model_output:<10} {error_info}")
    
    # 分析错误类型
    false_positive = sum(1 for e in errors if "Expected: False" in str(e[4]))  # 真值是affected，但模型输出yes
    false_negative = sum(1 for e in errors if "Expected: True" in str(e[4]))  # 真值是not affected，但模型输出no
    
    print(f"\n错误分析:")
    print(f"- 误报 (FP): {false_positive} - 真值是affected，模型误判为有intro commit")
    print(f"- 漏报 (FN): {false_negative} - 真值是not affected，模型漏判为无intro commit")
    
    return accuracy, errors

if __name__ == "__main__":
    accuracy, errors = evaluate()
    
    if accuracy < 0.70:
        print(f"\n⚠️  当前准确率 ({accuracy:.2%}) 未达到目标 (70%)")
        print("需要调整intro_infer_embedding_v5.py的判断逻辑")
    else:
        print(f"\n✅ 准确率 ({accuracy:.2%}) 已达到目标 (70%)")
