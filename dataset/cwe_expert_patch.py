import json
import os
import time
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI

class Client:
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
                time.sleep(0.2) 
                res = self.client.chat.completions.create(
                    model="gpt-4o", # 也可以使用 gpt-3.5-turbo 
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0,
                    timeout=120
                )
                return res.choices[0].message.content.strip()
            except Exception as e:
                err_str = str(e).lower()
                if any(kw in err_str for kw in ["insufficient", "402", "credit", "balance"]):
                    return "STOP_SIGNAL"
                # 使用特殊前缀避免与 Java 代码中的 "ERROR" 常量冲突
                return f"SYSTEM_API_ERROR: {e}"

final_patches = {}
results_lock = Lock()
stop_all = False

def worker(cwe_id, client):
    global stop_all
    if stop_all: return None

    # 修改 Prompt：强制要求输出 Java 修复代码
    prompt = (
        f"As a cybersecurity expert, provide a typical Java code snippet (maximum 3 lines) "
        f"that demonstrates the correct fix (patch) for {cwe_id}. "
        f"Rules: 1. Output ONLY the Java code; 2. No explanations; 3. Maximum 3 lines; "
        f"4. Focus on the most common Java mitigation for this specific CWE."
    )

    response = client.call_llm(prompt)

    if response == "STOP_SIGNAL":
        stop_all = True
        return None
    
    # 修改后的判断条件：只有当前缀匹配时才视为失败
    if response.startswith("SYSTEM_API_ERROR:"):
        return f"❌ {cwe_id} failed: {response}"

    # 清洗代码：去除 Markdown 标签
    lines = [line for line in response.split('\n') if "```" not in line]
    clean_patch = "\n".join(lines[:3]).strip()

    with results_lock:
        final_patches[cwe_id] = clean_patch
    return f"🛡️ {cwe_id} Java patch generated."

def main(input_file):
    if not os.path.exists(input_file):
        print(f"❌ 找不到文件: {input_file}")
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 提取唯一的 CWE ID
    all_cwes = set()
    for info in data.values():
        cwes = info.get('cwe', [])
        if isinstance(cwes, list):
            for c in cwes:
                if c and "CWE-" in str(c): all_cwes.add(c.strip())
        elif isinstance(cwes, str) and "CWE-" in cwes:
            all_cwes.add(cwes.strip())

    unique_cwes = sorted(list(all_cwes))
    print(f"📦 发现 {len(unique_cwes)} 个 CWE，准备生成 Java 补丁...")

    llm_client = Client()

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(worker, cwe, llm_client): cwe for cwe in unique_cwes}
        for future in as_completed(futures):
            res = future.result()
            if res: print(res)
            if stop_all:
                print("🛑 停止处理...")
                break

    output_file = 'cwe_expert_patch.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(final_patches, f, ensure_ascii=False, indent=4)
    print(f"\n✨ 处理完成！结果已保存至 {output_file}")

if __name__ == "__main__":
    main('cve_ghrepo.json')