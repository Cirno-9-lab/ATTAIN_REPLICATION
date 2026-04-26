#!/usr/bin/env python3
"""
自动化迭代脚本 - 持续优化直到达到80%准确率
"""
import os
import json
import time
import subprocess
import shutil
from datetime import datetime

BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CODE_PATH = "/home/xinweimao/env/anaconda3/bin/python"
MAIN_SCRIPT = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/intro_infer_embedding_v5.py"
EVALUATE_SCRIPT = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/evaluate_accuracy.py"

# 迭代配置序列
ITERATIONS = [
    {
        "name": "v1_f",
        "output": "intro_contrastive_final_f.json",
        "threshold": 0.30,
        "base_confidence": 0.45,
        "bonus_multiplier": 0.03,
        "bonus_max": 0.15,
        "rules_max": 0.60,
        "max_llm_calls": 5,
        "description": "Baseline configuration"
    },
    {
        "name": "v2_g",
        "output": "intro_contrastive_final_g.json",
        "threshold": 0.25,
        "base_confidence": 0.48,
        "bonus_multiplier": 0.035,
        "bonus_max": 0.18,
        "rules_max": 0.65,
        "max_llm_calls": 7,
        "description": "Lower threshold, increase calls"
    },
    {
        "name": "v3_h",
        "output": "intro_contrastive_final_h.json",
        "threshold": 0.30,
        "base_confidence": 0.45,
        "bonus_multiplier": 0.03,
        "bonus_max": 0.15,
        "rules_max": 0.60,
        "max_llm_calls": 5,
        "description": "Revert to baseline"
    },
    {
        "name": "v4_i",
        "output": "intro_contrastive_final_i.json",
        "threshold": 0.28,
        "base_confidence": 0.46,
        "bonus_multiplier": 0.032,
        "bonus_max": 0.16,
        "rules_max": 0.62,
        "max_llm_calls": 6,
        "description": "Balanced approach"
    },
    {
        "name": "v5_j",
        "output": "intro_contrastive_final_j.json",
        "threshold": 0.32,
        "base_confidence": 0.47,
        "bonus_multiplier": 0.032,
        "bonus_max": 0.16,
        "rules_max": 0.62,
        "max_llm_calls": 5,
        "description": "Higher threshold to reduce FP"
    },
    {
        "name": "v6_k",
        "output": "intro_contrastive_final_k.json",
        "threshold": 0.35,
        "base_confidence": 0.50,
        "bonus_multiplier": 0.03,
        "bonus_max": 0.15,
        "rules_max": 0.60,
        "max_llm_calls": 5,
        "description": "Conservative: high threshold"
    },
    {
        "name": "v7_l",
        "output": "intro_contrastive_final_l.json",
        "threshold": 0.30,
        "base_confidence": 0.50,
        "bonus_multiplier": 0.035,
        "bonus_max": 0.18,
        "rules_max": 0.65,
        "max_llm_calls": 5,
        "description": "High base confidence"
    },
    {
        "name": "v8_m",
        "output": "intro_contrastive_final_m.json",
        "threshold": 0.33,
        "base_confidence": 0.48,
        "bonus_multiplier": 0.033,
        "bonus_max": 0.17,
        "rules_max": 0.63,
        "max_llm_calls": 6,
        "description": "Medium-high threshold"
    },
    {
        "name": "v9_n",
        "output": "intro_contrastive_final_n.json",
        "threshold": 0.30,
        "base_confidence": 0.48,
        "bonus_multiplier": 0.035,
        "bonus_max": 0.18,
        "rules_max": 0.65,
        "max_llm_calls": 8,
        "description": "More LLM calls, higher bonus"
    },
    {
        "name": "v10_o",
        "output": "intro_contrastive_final_o.json",
        "threshold": 0.31,
        "base_confidence": 0.49,
        "bonus_multiplier": 0.034,
        "bonus_max": 0.175,
        "rules_max": 0.64,
        "max_llm_calls": 7,
        "description": "Fine-tuned parameters"
    }
]

TARGET_ACCURACY = 0.80

def get_accuracy(result_path):
    """获取指定结果的准确率"""
    if not os.path.exists(result_path):
        return None, None, None

    # 运行评估脚本
    cmd = f"{CODE_PATH} {EVALUATE_SCRIPT}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout

    # 解析准确率
    import re
    match = re.search(r'准确率:\s*([\d.]+)%\s*\((\d+)/(\d+)\)', output)
    if match:
        accuracy = float(match.group(1)) / 100
        correct = int(match.group(2))
        total = int(match.group(3))

        # 解析FP和FN
        fp_match = re.search(r'误报 \(FP\):\s*(\d+)', output)
        fn_match = re.search(r'漏报 \(FN\):\s*(\d+)', output)
        fp = int(fp_match.group(1)) if fp_match else None
        fn = int(fn_match.group(1)) if fn_match else None

        return accuracy, {'FP': fp, 'FN': fn, 'correct': correct, 'total': total}
    else:
        return None, None, None

def apply_parameters(config):
    """应用参数到主脚本"""
    with open(MAIN_SCRIPT, 'r') as f:
        content = f.read()

    # 替换参数
    # 1. Output path
    content = re.sub(
        r'OUTPUT_PATH = os\.path\.join\(BASE_PATH, "result/intro_contrastive_final_[^"]+\.json"\)',
        f'OUTPUT_PATH = os.path.join(BASE_PATH, "result/{config["output"]}")',
        content
    )

    # 2. MAX_LLM_CALLS_PER_CVE
    content = re.sub(
        r'MAX_LLM_CALLS_PER_CVE = \d+',
        f'MAX_LLM_CALLS_PER_CVE = {config["max_llm_calls"]}',
        content
    )

    # 3. Base confidence
    content = re.sub(
        r'confidence = [\d.]+\s+# Base confidence',
        f'confidence = {config["base_confidence"]}  # Base confidence',
        content
    )

    # 4. Critical patterns bonus
    content = re.sub(
        r'\* 0\.\d+, 0\.\d+\)\s+# Critical patterns bonus',
        f'* {config["bonus_multiplier"]}, {config["bonus_max"]})  # Critical patterns bonus',
        content
    )

    # 5. Rules part max
    content = re.sub(
        r'confidence = min\(confidence, [\d.]+\)\s+# Rules part max',
        f'confidence = min(confidence, {config["rules_max"]})  # Rules part max',
        content
    )

    # 6. Threshold
    content = re.sub(
        r'threshold = [\d.]+\s+# Lower threshold',
        f'threshold = {config["threshold"]}  # Threshold',
        content
    )

    # 保存
    with open(MAIN_SCRIPT, 'w') as f:
        f.write(content)

    # 更新评估脚本
    eval_script = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/evaluate_accuracy.py"
    with open(eval_script, 'r') as f:
        eval_content = f.read()

    eval_content = re.sub(
        r'RESULT_PATH = os\.path\.join\(BASE_PATH, "result/intro_contrastive_final_[^"]+\.json"\)',
        f'RESULT_PATH = os.path.join(BASE_PATH, "result/{config["output"]}")',
        eval_content
    )

    with open(eval_script, 'w') as f:
        f.write(eval_content)

def run_iteration(config):
    """运行一次迭代"""
    print(f"\n{'='*100}")
    print(f"开始迭代: {config['name']}")
    print(f"描述: {config['description']}")
    print(f"参数:")
    print(f"  threshold: {config['threshold']}")
    print(f"  base_confidence: {config['base_confidence']}")
    print(f"  bonus_multiplier: {config['bonus_multiplier']}, max: {config['bonus_max']}")
    print(f"  rules_max: {config['rules_max']}")
    print(f"  max_llm_calls: {config['max_llm_calls']}")
    print(f"{'='*100}\n")

    # 应用参数
    print("✓ 应用参数...")
    apply_parameters(config)

    # 运行主脚本
    print("✓ 运行主脚本...")
    log_file = f"/tmp/intro_infer_v5_{config['name'][-1]}.log"
    cmd = f"nohup {CODE_PATH} {MAIN_SCRIPT} > {log_file} 2>&1 &"
    os.system(cmd)

    # 等待完成
    print("✓ 等待完成...")
    result_path = os.path.join(BASE_PATH, "result", config['output'])

    while True:
        time.sleep(30)  # 每30秒检查一次

        # 检查结果文件
        if os.path.exists(result_path):
            print("✓ 结果文件已生成")

            # 评估结果
            print("✓ 评估准确率...")
            accuracy, metrics = get_accuracy(result_path)

            if accuracy is not None:
                print(f"\n{'='*100}")
                print(f"迭代 {config['name']} 完成")
                print(f"准确率: {accuracy*100:.2f}%")
                if metrics:
                    print(f"正确: {metrics['correct']}/{metrics['total']}")
                    print(f"误报 (FP): {metrics['FP']}")
                    print(f"漏报 (FN): {metrics['FN']}")

                if accuracy >= TARGET_ACCURACY:
                    print(f"\n🎉 达到目标准确率 {TARGET_ACCURACY*100}%！")
                    return True
                else:
                    gap = TARGET_ACCURACY - accuracy
                    print(f"\n⚠️  未达标，差距 {gap*100:.2f}%")

                print(f"{'='*100}\n")
                return False
            else:
                print("⚠️  评估失败，跳过此迭代")
                return False

        # 检查进程
        ps_cmd = "ps aux | grep intro_infer_embedding_v5.py | grep -v grep"
        ps_result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
        if ps_result.stdout.strip() == "":
            print("✓ 脚本已结束")
            time.sleep(10)
            if os.path.exists(result_path):
                continue
            else:
                print("⚠️  结果文件未生成，可能出错")
                return False

def auto_iterate(start_index=2):
    """自动迭代直到达到目标"""
    print("="*100)
    print(f"自动化迭代开始 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"目标准确率: {TARGET_ACCURACY*100}%")
    print(f"起始迭代: {ITERATIONS[start_index]['name']}")
    print("="*100)

    results = []

    for i in range(start_index, len(ITERATIONS)):
        config = ITERATIONS[i]

        # 运行迭代
        success = run_iteration(config)

        if success:
            # 达到目标
            print("\n✅ 成功达到目标准确率！")
            print(f"总迭代次数: {i - start_index + 1}")
            print(f"最终配置: {config['name']}")
            break

        # 记录结果
        result_path = os.path.join(BASE_PATH, "result", config['output'])
        accuracy, metrics = get_accuracy(result_path)
        results.append({
            'name': config['name'],
            'accuracy': accuracy,
            'metrics': metrics,
            'config': config
        })

    # 生成报告
    generate_report(results)

def generate_report(results):
    """生成迭代报告"""
    print(f"\n{'='*100}")
    print("迭代报告")
    print(f"{'='*100}")

    print(f"\n{'迭代':<10} {'准确率':<12} {'FP':<8} {'FN':<8} {'阈值':<10} {'描述'}")
    print("-"*100)

    for r in results:
        if r['accuracy'] is not None:
            fp = r['metrics']['FP'] if r['metrics'] else '-'
            fn = r['metrics']['FN'] if r['metrics'] else '-'
            threshold = r['config']['threshold']
            desc = r['config']['description']

            print(f"{r['name']:<10} {r['accuracy']*100:>6.2f}%     {fp:<8} {fn:<8} {threshold:<10} {desc}")

    # 找出最佳结果
    valid_results = [r for r in results if r['accuracy'] is not None]
    if valid_results:
        best = max(valid_results, key=lambda x: x['accuracy'])
        print(f"\n{'='*100}")
        print(f"最佳结果:")
        print(f"  迭代: {best['name']}")
        print(f"  准确率: {best['accuracy']*100:.2f}%")
        print(f"  配置: {best['config']['description']}")
        print(f"  参数: threshold={best['config']['threshold']}, base_conf={best['config']['base_confidence']}")
        print(f"{'='*100}")

if __name__ == "__main__":
    import sys

    start_index = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    auto_iterate(start_index)
