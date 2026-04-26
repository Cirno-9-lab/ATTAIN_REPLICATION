import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import os

# --- 配置 ---
MINING_REPORT_PATH = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/full_mining_report.xlsx"
OUTPUT_PLOT_PATH = "mining_contrastive_6plots.png"

def draw_custom_analysis():
    if not os.path.exists(MINING_REPORT_PATH):
        print("❌ 找不到报告文件")
        return

    df = pd.read_excel(MINING_REPORT_PATH)
    # 确保数值类型
    for col in ['Winning_Margin', 'Vule_Score', 'Safe_Score']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # --- 分组逻辑 ---
    # 第一组：模型判定为 Affected 的案例 (TP 是对的，FP 是错的)
    affected_pred_group = df[df['Result_Type'].isin(['TP', 'FP'])]
    # 第二组：模型判定为 Not Affected 的案例 (TN 是对的，FN 是错的)
    not_affected_pred_group = df[df['Result_Type'].isin(['TN', 'FN'])]

    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(2, 3, figsize=(22, 12))

    # --- 第一行：TP vs FP (判定为 Affected 的对比) ---
    # 1. Margin 分布
    sns.boxplot(data=affected_pred_group, x='Result_Type', y='Winning_Margin', ax=axes[0, 0], palette='Oranges')
    axes[0, 0].set_title('TP vs FP: Winning Margin', fontsize=14)
    axes[0, 0].axhline(0, color='black', linestyle='--', alpha=0.3)

    # 2. 决策空间散点图
    sns.scatterplot(data=affected_pred_group, x='Vule_Score', y='Safe_Score', hue='Result_Type', s=100, ax=axes[0, 1])
    axes[0, 1].plot([0, 1], [0, 1], 'r--', alpha=0.5)
    axes[0, 1].set_title('TP vs FP: Vule vs Safe Space', fontsize=14)

    # 3. 评分均值
    df_af_melt = affected_pred_group.melt(id_vars=['Result_Type'], value_vars=['Vule_Score', 'Safe_Score'])
    sns.barplot(data=df_af_melt, x='Result_Type', y='value', hue='variable', ax=axes[0, 2], palette='Oranges_d')
    axes[0, 2].set_title('TP vs FP: Mean Scores', fontsize=14)

    # --- 第二行：TN vs FN (判定为 Not Affected 的对比) ---
    # 4. Margin 分布
    sns.boxplot(data=not_affected_pred_group, x='Result_Type', y='Winning_Margin', ax=axes[1, 0], palette='Blues')
    axes[1, 0].set_title('TN vs FN: Winning Margin', fontsize=14)
    axes[1, 0].axhline(0, color='black', linestyle='--', alpha=0.3)

    # 5. 决策空间散点图
    sns.scatterplot(data=not_affected_pred_group, x='Vule_Score', y='Safe_Score', hue='Result_Type', s=100, ax=axes[1, 1])
    axes[1, 1].plot([0, 1], [0, 1], 'r--', alpha=0.5)
    axes[1, 1].set_title('TN vs FN: Vule vs Safe Space', fontsize=14)

    # 6. 评分均值
    df_na_melt = not_affected_pred_group.melt(id_vars=['Result_Type'], value_vars=['Vule_Score', 'Safe_Score'])
    sns.barplot(data=df_na_melt, x='Result_Type', y='value', hue='variable', ax=axes[1, 2], palette='Blues_d')
    axes[1, 2].set_title('TN vs FN: Mean Scores', fontsize=14)

    plt.tight_layout()
    plt.savefig(OUTPUT_PLOT_PATH)
    print(f"✅ 对比分析图已生成: {OUTPUT_PLOT_PATH}")

if __name__ == "__main__":
    draw_custom_analysis()