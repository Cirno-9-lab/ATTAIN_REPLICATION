import json
import os
import time
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI

# --- 模仿您的 Client 类 ---
class JavaCodeClient:
    def __init__(self):
        self.api_key = os.getenv("CHATANYWHERE_API_KEY")
        self.base_url = "https://api.chatanywhere.tech/v1"
        self.lock = Lock()
        if not self.api_key:
            raise ValueError("❌ 错误：未检测到环境变量 CHATANYWHERE_API_KEY。")
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def call_llm(self, prompt):
        with self.lock:
            try:
                time.sleep(0.3) 
                res = self.client.chat.completions.create(
                    model="deepseek-v3", 
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3, # 稍微降低温度，确保生成的代码结构严谨
                    timeout=60
                )
                return res.choices[0].message.content.strip()
            except Exception as e:
                err_str = str(e).lower()
                if any(kw in err_str for kw in ["insufficient", "402", "credit", "balance", "money"]):
                    return "STOP_SIGNAL"
                return f"ERROR: {e}"

# --- 全局变量与结果集 ---
final_results = {}
results_lock = Lock()
stop_all = False

# 定义多样化的安全场景，避免生成的样本过于单一
SAFE_SCENARIOS = [
    "safe numeric parsing with length limits",
    "bounded recursion or safe loop iteration",
    "input validation and sanitization",
    "safe object instantiation with null checks",
    "secure string manipulation avoiding memory exhaustion",
    "safe file path resolution",
    "secure mathematical operation avoiding overflow",
    "robust exception handling without leaking sensitive data",
    "safe list/array access with boundary checks",
    "secure type casting with instanceof checks"
]

def worker(task_id, client):
    """
    生成单个健壮的 Java 安全示例
    """
    global stop_all
    if stop_all:
        return None

    scenario = SAFE_SCENARIOS[(task_id - 1) % len(SAFE_SCENARIOS)]
    
    # 核心修改：要求生成具有防御性编程语义的完整方法
    prompt = (
        f"Write a robust and secure Java method (around 5-10 lines) demonstrating {scenario}. "
        f"Rules: "
        f"1. Output ONLY the raw Java code. "
        f"2. Strictly NO explanations, NO comments, and NO markdown formatting (do not use ```java). "
        f"3. The code MUST include defensive programming practices (e.g., boundary checks, safe defaults, or proper try-catch)."
    )

    print(f"📡 正在生成安全示例 #{task_id} [{scenario}]...")
    response = client.call_llm(prompt)

    if response == "STOP_SIGNAL":
        stop_all = True
        return None

    if "ERROR" in response:
        return f"❌ 示例 {task_id} 失败: {response}"

    # 清洗代码：移除可能残留的 Markdown 标记，保留完整方法体，而不是粗暴截断 3 行
    clean_code = response.replace('```java', '').replace('```', '').strip()

    # 安全地写入全局字典
    with results_lock:
        final_results[f"example_{task_id}"] = clean_code
    return f"✅ 示例 {task_id} 处理完成。"

def main():
    llm_client = JavaCodeClient()
    
    print(f"🚀 开始并发生成 10 个健壮的 Java 安全基准代码...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(worker, i, llm_client): i for i in range(1, 11)}
        
        for future in as_completed(futures):
            res = future.result()
            if res:
                print(res)
            if stop_all:
                print("🛑 检测到余额不足，正在停止所有线程...")
                break

    output_file = 'java_code_samples.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(final_results, f, ensure_ascii=False, indent=4)
    
    print(f"\n✨ 安全基准构建完成！结果已保存至 {output_file}")

if __name__ == "__main__":
    main()