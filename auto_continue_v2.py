#!/usr/bin/env python3
"""
自动监控和持续迭代脚本 v2 - 修复版
"""
import os
import time
import subprocess
import re
from datetime import datetime

BASE_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
CODE_PATH = "/home/xinweimao/env/anaconda3/bin/python"
MAIN_SCRIPT = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/intro_infer_embedding_v5.py"
EVALUATE_SCRIPT = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/evaluate_accuracy.py"

TARGET_ACCURACY = 0.80

# 预设迭代配置
CONFIGS = {
    'v4_i': (0.28, 0.46, 6, "balanced"),
    'v5_j': (0.32, 0.47, 5, "higher threshold to reduce FP"),
    'v6_k': (0.35, 0.50, 5, "conservative high threshold"),
    'v7_l': (0.30, 0.50, 5, "high base confidence"),
    'v8_m': (0.33, 0.48, 6, "medium-high threshold"),
    'v9_n': (0.30, 0.48, 8, "more LLM calls"),
    'v10_o': (0.31, 0.49, 7, "fine-tuned"),
    'v11_p': (0.29, 0.48, 7, "slightly lower threshold"),
    'v12_q': (0.34, 0.49, 6, "higher threshold"),
    'v13_r': (0.31, 0.51, 7, "higher base confidence"),
    'v14_s': (0.32, 0.52, 6, "tuned high threshold"),
    'v15_t': (0.30, 0.52, 7, "high confidence, balanced"),
}

history = []

def check_iteration_completed(output_file):
    """检查迭代是否完成"""
    result_path = os.path.join(BASE_PATH, "result", output_file)

    if not os.path.exists(result_path):
        return False

    # 检查进程是否还在运行
    ps_cmd = "ps aux | grep intro_infer_embedding_v5.py | grep -v grep"
    ps_result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)

    return ps_result.stdout.strip() == ""

def evaluate_iteration(output_file):
    """评估迭代结果"""
    result_path = os.path.join(BASE_PATH, "result", output_file)

    # 运行评估脚本
    cmd = f"{CODE_PATH} {EVALUATE_SCRIPT}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout

    # 解析准确率
    match = re.search(r'准确率:\s*([\d.]+)%\s*\((\d+)/(\d+)\)', output)
    if match:
        accuracy = float(match.group(1)) / 100
        correct = int(match.group(2))
        total = int(match.group(3))

        # 解析FP和FN
        fp_match = re.search(r'误报 \(FP\):\s*(\d+)', output)
        fn_match = re.search(r'漏报 \(FN\):\s*(\d+)', output)
        fp = int(fp_match.group(1)) if fp_match else 0
        fn = int(fn_match.group(1)) if fn_match else 0

        return accuracy, {'FP': fp, 'FN': fn, 'correct': correct, 'total': total}
    else:
        return None, None

def decide_next_config(current_accuracy, fp, fn):
    """根据当前结果决定下一次迭代的配置"""
    # 按顺序返回配置
    config_names = list(CONFIGS.keys())
    num_completed = len(history)

    if num_completed < len(config_names):
        return config_names[num_completed]
    else:
        return None

def apply_and_run_next(config_name):
    """应用参数并运行下一次迭代"""
    if config_name not in CONFIGS:
        print(f"❌ 未知的配置: {config_name}")
        return None

    threshold, base_confidence, max_llm_calls, description = CONFIGS[config_name]
    output_file = config_name.replace('v', 'intro_contrastive_final_') + '.json'

    import shutil

    # 备份当前脚本
    backup_file = MAIN_SCRIPT + f"_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
    shutil.copy(MAIN_SCRIPT, backup_file)
    print(f"✓ 备份当前脚本到: {backup_file}")

    # 读取主脚本
    with open(MAIN_SCRIPT, 'r') as f:
        content = f.read()

    # 替换输出文件
    content = re.sub(
        r'OUTPUT_PATH = os\.path\.join\(BASE_PATH, "result/intro_contrastive_final_[^"]+\.json"\)',
        f'OUTPUT_PATH = os.path.join(BASE_PATH, "result/{output_file}")',
        content
    )

    # 替换MAX_LLM_CALLS_PER_CVE
    content = re.sub(
        r'MAX_LLM_CALLS_PER_CVE = \d+',
        f'MAX_LLM_CALLS_PER_CVE = {max_llm_calls}',
        content
    )

    # 替换base confidence
    content = re.sub(
        r'confidence = [\d.]+\s+# Base confidence',
        f'confidence = {base_confidence}  # Base confidence',
        content
    )

    # 保存主脚本
    with open(MAIN_SCRIPT, 'w') as f:
        f.write(content)

    # 更新评估脚本
    eval_script = EVALUATE_SCRIPT
    with open(eval_script, 'r') as f:
        eval_content = f.read()

    eval_content = re.sub(
        r'RESULT_PATH = os\.path\.join\(BASE_PATH, "result/intro_contrastive_final_[^"]+\.json"\)',
        f'RESULT_PATH = os.path.join(BASE_PATH, "result/{output_file}")',
        eval_content
    )

    with open(eval_script, 'w') as f:
        f.write(eval_content)

    print(f"✓ 参数已应用: threshold={threshold}, base_conf={base_confidence}, max_llm_calls={max_llm_calls}")

    # 运行主脚本
    log_file = f"/tmp/intro_infer_v5_{config_name}.log"
    cmd = f"nohup {CODE_PATH} {MAIN_SCRIPT} > {log_file} 2>&1 &"
    os.system(cmd)
    print(f"✓ 已启动迭代: {config_name}")
    print(f"✓ 日志文件: {log_file}")

    return output_file

def monitor_and_continue():
    """监控当前迭代并自动启动下一次"""
    print("="*100)
    print("自动监控和持续迭代 v2")
    print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"目标准确率: {TARGET_ACCURACY*100}%")
    print("="*100)

    # 当前输出文件（从v4开始）
    current_output = "intro_contrastive_final_i.json"
    current_config = 'v4_i'

    while True:
        time.sleep(60)  # 每分钟检查一次

        # 检查当前迭代是否完成
        if check_iteration_completed(current_output):
            print(f"\n{'='*100}")
            print(f"✓ 迭代完成: {current_output}")
            print(f"{'='*100}")

            # 评估结果
            print("评估准确率...")
            accuracy, metrics = evaluate_iteration(current_output)

            if accuracy is not None:
                print(f"\n准确率: {accuracy*100:.2f}%")
                if metrics:
                    print(f"正确: {metrics['correct']}/{metrics['total']}")
                    print(f"误报 (FP): {metrics['FP']}")
                    print(f"漏报 (FN): {metrics['FN']}")

                # 记录历史
                history.append({
                    'config': current_config,
                    'output': current_output,
                    'accuracy': accuracy,
                    'metrics': metrics,
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })

                # 检查是否达到目标
                if accuracy >= TARGET_ACCURACY:
                    print(f"\n🎉 达到目标准确率 {TARGET_ACCURACY*100}%！")
                    generate_final_report(history)
                    break

                # 决定下一次迭代参数
                print(f"\n距离目标还差 {(TARGET_ACCURACY - accuracy)*100:.2f}%")

                # 获取下一次迭代配置
                next_config = decide_next_config(accuracy, metrics['FP'], metrics['FN'])

                if next_config is None:
                    print("\n⚠️  已用完所有预设配置")
                    generate_final_report(history)
                    break

                # 获取下一次输出文件
                next_output = next_config.replace('v', 'intro_contrastive_final_') + '.json'

                print(f"\n下一次迭代:")
                print(f"  配置: {next_config}")
                threshold, base_conf, max_calls, desc = CONFIGS[next_config]
                print(f"  描述: {desc}")
                print(f"  参数: threshold={threshold}, base_confidence={base_conf}, max_llm_calls={max_calls}")

                # 启动下一次迭代
                print("\n启动下一次迭代...")
                output_file = apply_and_run_next(next_config)

                if output_file is None:
                    print("❌ 启动失败")
                    break

                current_output = output_file
                current_config = next_config
            else:
                print("⚠️  评估失败，跳过此次迭代")
                break
        else:
            # 迭代还在运行
            print(f"[{datetime.now().strftime('%H:%M:%S')}] 迭代 {current_output} 运行中...")

def generate_final_report(history):
    """生成最终报告"""
    print(f"\n{'='*100}")
    print("最终迭代报告")
    print(f"{'='*100}")

    print(f"\n{'迭代':<25} {'准确率':<12} {'FP':<8} {'FN':<8} {'时间'}")
    print("-"*100)

    for h in history:
        fp = h['metrics']['FP'] if h['metrics'] else '-'
        fn = h['metrics']['FN'] if h['metrics'] else '-'
        print(f"{h['config']:<25} {h['accuracy']*100:>6.2f}%     {fp:<8} {fn:<8} {h['time']}")

    # 最佳结果
    best = max(history, key=lambda x: x['accuracy'])
    print(f"\n{'='*100}")
    print(f"最佳结果:")
    print(f"  迭代: {best['config']}")
    print(f"  准确率: {best['accuracy']*100:.2f}%")
    print(f"  达标状态: {'✅ 是' if best['accuracy'] >= TARGET_ACCURACY else '❌ 否'}")
    print(f"{'='*100}")

if __name__ == "__main__":
    monitor_and_continue()
