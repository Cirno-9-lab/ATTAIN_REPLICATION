import pandas as pd
import re
import matplotlib.pyplot as plt
from wordcloud import WordCloud, STOPWORDS
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

# --- 配置 ---
FILE_NAME = 'execution_result.xlsx'
OUTPUT_NAME = 'analyzed_results.xlsx'

# 如果你发现词云里有些词没意义（比如 ERROR, FAILED），可以在这里添加
custom_stopwords = set(STOPWORDS)
custom_stopwords.update(['error', 'failed', 'exception', 'cause']) 

def clean_text(text):
    # 1. 处理空值
    if pd.isna(text) or str(text).strip() == '':
        return "empty_record"
    
    # 2. 强制转小写 (忽略大小写核心步骤)
    text = str(text).lower()
    
    # 3. 只保留字母，过滤标点和堆栈地址
    text = re.sub(r'[^a-z\s]', ' ', text)
    
    # 4. 分词并过滤停用词
    words = [w for w in text.split() if w not in custom_stopwords and len(w) > 2]
    
    return " ".join(words) if words else "other_issue"

def main():
    print("Reading Excel...")
    df = pd.read_excel(FILE_NAME)
    
    # 统一列名引用，防止 Excel 里是 'CAUSE' 或 'Cause'
    target_col = None
    for col in df.columns:
        if col.lower() == 'cause':
            target_col = col
            break
            
    if not target_col:
        print("Error: Could not find 'Cause' column.")
        return

    # 处理数据
    df['cleaned_text'] = df[target_col].apply(clean_text)
    
    # --- 生成词云 ---
    print("Generating Word Cloud...")
    all_text = " ".join(df['cleaned_text'])
    wc = WordCloud(
        background_color='white',
        width=1000, height=600,
        stopwords=custom_stopwords,
        colormap='viridis'
    ).generate(all_text)
    
    plt.figure(figsize=(10, 6))
    plt.imshow(wc, interpolation='bilinear')
    plt.axis('off')
    plt.title("Standardized Cause Analysis (Case-Insensitive)")
    plt.show()

    # --- 聚类分析 ---
    print("Clustering...")
    vectorizer = TfidfVectorizer(max_features=500)
    X = vectorizer.fit_transform(df['cleaned_text'])
    
    # 聚类数量建议：根据数据量调整，这里设为 5
    km = KMeans(n_clusters=5, random_state=42, n_init='auto')
    df['cluster_group'] = km.fit_predict(X)

    # 打印每个类的关键词
    order_centroids = km.cluster_centers_.argsort()[:, ::-1]
    terms = vectorizer.get_feature_names_out()
    
    print("\n--- Cluster Summary ---")
    for i in range(5):
        top_words = [terms[ind] for ind in order_centroids[i, :5]]
        print(f"Cluster {i}: {', '.join(top_words)}")

    # 保存结果
    df.to_excel(OUTPUT_NAME, index=False)
    print(f"\nDone! Saved to {OUTPUT_NAME}")

if __name__ == "__main__":
    main()