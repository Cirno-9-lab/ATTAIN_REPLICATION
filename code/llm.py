import os
import time
from threading import Lock
from openai import OpenAI

class Client:
    """
    GPT-5-MINI (via ChatAnywhere) 客户端封装
    用于处理安全补丁审计的 LLM 请求
    """
    def __init__(self):
        # 从操作系统环境变量中获取 API Key
        self.api_key = os.getenv("CHATANYWHERE_API_KEY")
        # 设置 API 代理地址 (ChatAnywhere)
        self.base_url = "https://api.chatanywhere.tech/v1"
        self.lock = Lock()
        
        # 检查 Key 是否存在
        if not self.api_key:
            raise ValueError("❌ 错误：未检测到环境变量 CHATANYWHERE_API_KEY。请先执行 export 设置它。")
            
        # 初始化 OpenAI 兼容客户端
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def call_llm(self, prompt):
        """
        调用 LLM 进行审计，包含频率限制和错误处理
        """
        try:
            # 强制休息 0.1 秒，防止请求过快触发 Rate Limit
            time.sleep(0.1)
            
            res = self.client.chat.completions.create(
                model="gpt-5-mini",  # 指向 DeepSeek-Chat 模型
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,       # 设置为 0 保证审计判定结果的确定性
                timeout=120            # 增加超时阈值，给 V3 充足的思考时间
            )
            return res.choices[0].message.content
        except Exception as e:
            err_str = str(e).lower()
            # 自动检测余额不足或配额限制错误 (402)
            if any(kw in err_str for kw in ["insufficient", "402", "credit", "balance", "money"]):
                return "STOP_SIGNAL"
            return f"ERROR: {e}"