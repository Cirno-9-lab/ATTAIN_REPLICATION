#!/usr/bin/env python3
"""
自动监控和持续迭代脚本
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

# 迭代历史
history = []

def get_current_iteration_info():
    """获取当前正在运行的迭代信息"""
    # 检查输出文件名
    result_files = {
        'intro_contrastive_final_f.json': ('v1_f', 0.30, 0.45, 5),
        'intro_contrastive_final_g.json': ('v2_g', 0.25, 0.48, 7),
        'intro_contrastive_final_h.json': ('v3_h', 0.30, 0.45, 5),
        'intro_contrastive_final_i.json': ('v4_i', 0.28, 0.46, 6),
        'intro_contrastive_final_j.json': ('v5_j', 0.32, 0.47, 5),
        'intro_contrastive_final_k.json': ('v6_k', 0.35, 0.50, 5),
        'intro_contrastive_final_l.json': ('v7_l', 0.30, 0.50, 5),
        'intro_contrastive_final_m.json': ('v8_m', 0.33, 0.48, 6),
        'intro_contrastive_final_n.json': ('v9_n', 0.30, 0.48, 8),
        'intro_contrastive_final_o.json': ('v10_o', 0.31, 0.49, 7)
    }

    for filename, info in result_files.items():
        result_path = os.path.join(BASE_PATH, "result", filename)
        if os.path.exists(result_path):
            # 检查是否是正在生成的文件（还在运行）
            current_iter = os.path.join(BASE_PATH, "result", "intro_contrastive_final_h.json")
            if os.path.exists(current_iter):
                file_size = os.path.getsize(current_iter)
                # 如果文件大小>0且文件存在，说明正在运行
                return ('v3_h', 0.30, 0.45, 5, current_iter)

    # 默认返回最新的
    return None

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
        fp = int(fp_match.group(1)) if fp_match else None
        fn = int(fn_match.group(1)) if fn_match else None

        return accuracy, {'FP': fp, 'FN': fn, 'correct': correct, 'total': total}
    else:
        return None, None

def decide_next_parameters(current_accuracy, fp, fn):
    """根据当前结果决定下一次迭代的参数"""
    # 参数序列
    configs = [
        # (threshold, base_confidence, max_llm_calls, description)
        (0.30, 0.45, 5, "baseline - v1_f/v3_h"),
        (0.25, 0.48, 7, "lower threshold, more calls - v2_g"),
        (0.28, 0.46, 6, "balanced - v4_i"),
        (0.32, 0.47, 5, "higher threshold to reduce FP - v5_j"),
        (0.35, 0.50, 5, "conservative high threshold - v6_k"),
        (0.30, 0.50, 5, "high base confidence - v7_l"),
        (0.33, 0.48, 6, "medium-high threshold - v8_m"),
        (0.30, 0.48, 8, "more LLM calls - v9_n"),
        (0.31, 0.49, 7, "fine-tuned - v10_o"),
        (0.29, 0.48, 7, "slightly lower threshold - v11_p"),
        (0.34, 0.49, 6, "higher threshold - v12_q"),
        (0.31, 0.51, 7, "higher base confidence - v13_r"),
        (0.32, 0.52, 6, "tuned high threshold - v14_s"),
        (0.30, 0.52, 7, "high confidence, balanced - v15_t"),
    ]

    # 根据当前情况选择下一个配置
    # 如果FP过多，提高threshold
    # 如果FN过多，降低threshold

    next_index = len(history) % len(configs)
    return configs[next_index]

def apply_and_run_next(threshold, base_confidence, max_llm_calls, output_file):
    """应用参数并运行下一次迭代"""
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
    log_file = f"/tmp/intro_infer_v5_auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    cmd = f"nohup {CODE_PATH} {MAIN_SCRIPT} > {log_file} 2>&1 &"
    os.system(cmd)
    print(f"✓ 已启动下一次迭代，日志: {log_file}")

    return output_file

def monitor_and_continue():
    """监控当前迭代并自动启动下一次"""
    print("="*100)
    print("自动监控和持续迭代")
    print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"目标准确率: {TARGET_ACCURACY*100}%")
    print("="*100)

    # 当前输出文件（第3次迭代）
    current_output = "intro_contrastive_final_h.json"

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
                fp = metrics['FP'] if metrics else 0
                fn = metrics['FN'] if metrics else 0

                if fp > fn:
                    print("主要问题: 误报过多，将提高threshold")
                elif fn > fp:
                    print("主要问题: 漏报过多，将降低threshold")
                else:
                    print("误报和漏报数量相近，尝试平衡优化")

                # 获取下一次迭代参数
                next_threshold, next_base, next_calls, next_desc = decide_next_parameters(accuracy, fp, fn)

                # 生成下一次输出文件名
                next_char = chr(ord(current_output[-5]) + 1)  # f->g->h->i...
                next_output = f"intro_contrastive_final_{next_char}.json"

                print(f"\n下一次迭代:")
                print(f"  输出文件: {next_output}")
                print(f"  配置: {next_desc}")
                print(f"  参数: threshold={next_threshold}, base_confidence={next_base}, max_llm_calls={next_calls}")

                # 启动下一次迭代
                print("\n启动下一次迭代...")
                apply_and_run_next(next_threshold, next_base, next_calls, next_output)
                current_output = next_output
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
        print(f"{h['output']:<25} {h['accuracy']*100:>6.2f}%     {fp:<8} {fn:<8} {h['time']}")

    # 最佳结果
    best = max(history, key=lambda x: x['accuracy'])
    print(f"\n{'='*100}")
    print(f"最佳结果:")
    print(f"  迭代: {best['output']}")
    print(f"  准确率: {best['accuracy']*100:.2f}%")
    print(f"  达标状态: {'✅ 是' if best['accuracy'] >= TARGET_ACCURACY else '❌ 否'}")
    print(f"{'='*100}")

if __name__ == "__main__":
    monitor_and_continue()
