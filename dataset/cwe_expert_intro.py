import json
import os
import time
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI

# --- 您提供的 Client 类 ---
class Client:
    def __init__(self):
        self.api_key = os.getenv("CHATANYWHERE_API_KEY")
        self.base_url = "https://api.chatanywhere.tech/v1"
        self.lock = Lock()
        if not self.api_key:
            raise ValueError("❌ 错误：未检测到环境变量 CHATANYWHERE_API_KEY。")
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def call_llm(self, prompt):
        # 使用锁确保在某些极端频率限制下请求的有序性
        with self.lock:
            try:
                time.sleep(0.2) 
                res = self.client.chat.completions.create(
                    model="deepseek-v3", # 保持您原有的模型配置
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1, # 稍微调高一点温度(从0.0到0.1)，有助于生成更自然的语义描述
                    timeout=120
                )
                return res.choices[0].message.content.strip()
            except Exception as e:
                err_str = str(e).lower()
                if any(kw in err_str for kw in ["insufficient", "402", "credit", "balance", "money"]):
                    return "STOP_SIGNAL"
                return f"ERROR: {e}"

# --- 全局变量与结果锁 ---
final_results = {}
results_lock = Lock()
stop_all = False

def worker(cwe_id, client):
    """单个 CWE 的处理函数"""
    global stop_all
    if stop_all:
        return None

    # 核心修改：将提示词从“索要代码”改为“索要行为语义描述”
    prompt = (
        f"As a cybersecurity expert, provide a concise behavioral description (2 to 3 sentences) of {cwe_id}. "
        f"Focus on the logical root cause, how the vulnerability manifests during software execution, "
        f"and specifically how it typically appears in Java (e.g., Uncontrolled Recursion, OOM, Exception handling flaws). "
        f"Rules: "
        f"1. Output ONLY the descriptive text. "
        f"2. Strictly NO code snippets. "
        f"3. NO introductory or conversational phrases (like 'Here is the description...')."
    )

    response = client.call_llm(prompt)

    if response == "STOP_SIGNAL":
        stop_all = True
        return None
    
    if "ERROR" in response:
        return f"{cwe_id} failed: {response}"

    # 清洗逻辑修改：移除对前 3 行的截断，仅清理可能出现的 markdown 符号或换行
    clean_text = response.replace('```text', '').replace('```', '').replace('\n', ' ').strip()
    # 进一步清理模型可能强行加上的前缀
    if clean_text.lower().startswith(f"{cwe_id.lower()}:"):
        clean_text = clean_text[len(cwe_id)+1:].strip()

    # 安全地写入全局字典
    with results_lock:
        final_results[cwe_id] = clean_text
    return f"✅ {cwe_id} processed."

def main(input_file):
    # 1. 提取所有唯一的 CWE
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    all_cwes = set()
    for info in data.values():
        cwes = info.get('cwe', [])
        if isinstance(cwes, list):
            for c in cwes:
                if c and "CWE-" in str(c): all_cwes.add(c.strip())
        elif isinstance(cwes, str) and "CWE-" in cwes:
            all_cwes.add(cwes.strip())
    
    unique_cwes = sorted(list(all_cwes))
    print(f"📦 发现 {len(unique_cwes)} 个唯一的 CWE，准备启动 10 个线程构建语义知识库...")

    # 2. 初始化客户端
    llm_client = Client()

    # 3. 使用线程池进行并发处理
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(worker, cwe, llm_client): cwe for cwe in unique_cwes}
        
        for future in as_completed(futures):
            res = future.result()
            if res:
                print(res)
            if stop_all:
                print("🛑 检测到余额不足，正在停止所有线程...")
                break

    # 4. 保存最终字典
    output_file = 'cwe_expert_intro.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(final_results, f, ensure_ascii=False, indent=4)
    
    print(f"\n✨ 语义知识库构建完成！结果已保存至 {output_file}")

if __name__ == "__main__":
    main('cve_ghrepo.json')