import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

# --- 配置 ---
MINING_REPORT_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/full_mining_report.xlsx"
OUTPUT_CWE_PLOT = "cwe_performance_analysis.png"

def plot_cwe_distribution():
    if not os.path.exists(MINING_REPORT_PATH):
        print("❌ 找不到报告文件")
        return

    df = pd.read_excel(MINING_REPORT_PATH)
    
    # 1. 数据预处理：清理 CWE 列（防止有空格或空值）
    df['CWE'] = df['CWE'].fillna('Unknown').astype(str).str.strip()
    
    # 2. 统计各 CWE 下 TP, TN, FP, FN 的数量
    # 使用 groupby 统计并重置索引，方便 Seaborn 绘图
    cwe_stats = df.groupby(['CWE', 'Result_Type']).size().reset_index(name='Count')

    # 3. 绘图设置
    sns.set_theme(style="whitegrid")
    # 根据 CWE 的数量动态调整画布高度，防止标签重叠
    num_cwes = len(cwe_stats['CWE'].unique())
    plt.figure(figsize=(12, max(6, num_cwes * 0.5)))

    # 使用横向柱状图 (y='CWE')
    sns.barplot(
        data=cwe_stats, 
        y='CWE', 
        x='Count', 
        hue='Result_Type', 
        palette={'TP': '#55a868', 'TN': '#4c72b0', 'FP': '#c44e52', 'FN': '#8172b3'}, # 保持色系一致
        hue_order=['TP', 'TN', 'FP', 'FN']
    )

    plt.title('Performance Breakdown by CWE Type', fontsize=15)
    plt.xlabel('Number of Cases')
    plt.ylabel('CWE ID')
    plt.legend(title='Result Type', loc='lower right')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_CWE_PLOT)
    print(f"✅ CWE 统计图已生成: {OUTPUT_CWE_PLOT}")

    # 4. 打印数值汇总表（方便快速查阅）
    pivot_table = cwe_stats.pivot(index='CWE', columns='Result_Type', values='Count').fillna(0).astype(int)
    # 计算每个 CWE 的准确率
    pivot_table['Accuracy'] = (pivot_table.get('TP', 0) + pivot_table.get('TN', 0)) / pivot_table.sum(axis=1)
    print("\n📊 CWE 性能汇总表：")
    print(pivot_table.sort_values(by='Accuracy', ascending=False))

if __name__ == "__main__":
    plot_cwe_distribution()