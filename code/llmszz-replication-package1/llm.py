from openai import OpenAI
import tiktoken

class Client:
    def __init__(self) -> None:
        self.call_cnt = 0
        self.token_cost = 0
        self.client = OpenAI(
            api_key="sk-b8eb99dacfdb4ed88cdda166f79dd042",
            base_url="https://api.deepseek.com"
        )

    def call_llm(self, all_msgs, log_msgs, pipeline=None, openai_key=None):
        self.call_cnt = self.call_cnt + 1
        
        while len(str(all_msgs)) > 30000:
            all_msgs = all_msgs[1:]

        try:
            completion = self.client.chat.completions.create(
                model="deepseek-chat",  # 修改为 DeepSeek 模型
                messages=all_msgs, 
                temperature=0.0,
                stream=False
            )
            
            reply = completion.choices[0].message.content
    

            if log_msgs is not None:
                log_msgs.append({"role": "assistant", "content": reply})
                
            return reply
            
        except Exception as e:
            print(f"Error calling DeepSeek API: {e}")
            return ""

    def get_call_cnt(self):
        return self.call_cnt

# if __name__ == "__main__":
#     # 1. 初始化客户端
#     my_client = Client()
    
#     # 2. 准备测试消息
#     # 注意：messages 必须符合 OpenAI 的 chat 格式列表
#     messages = [
#         {"role": "system", "content": "You are a helpful assistant."},
#         {"role": "user", "content": "你好，请用简短的一句话介绍一下DeepSeek。"}
#     ]
    
#     # 用于存储对话记录的列表
#     logs = []

#     print("正在发送请求给 DeepSeek...")

#     # 3. 调用函数
#     response = my_client.call_llm(messages, logs)

#     # 4. 打印结果
#     print("\n" + "="*20 + " 模型回复 " + "="*20)
#     print(response)
#     print("="*50)

#     # 5. 打印统计信息
#     print(f"\n当前调用次数: {my_client.get_call_cnt()}")
    
#     # 验证 logs 是否被更新
#     print(f"Logs列表长度: {len(logs)}")
#     if len(logs) > 0:
#         print(f"最新Log内容: {logs[-1]}")