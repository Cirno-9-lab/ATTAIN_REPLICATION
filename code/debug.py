# 保存为 debug_import.py 并运行：python debug_import.py
try:
    import torch
    print(f"1. Torch version: {torch.__version__}")
    import transformers
    from transformers.modeling_utils import PreTrainedModel
    print("2. PreTrainedModel 导入成功")
except Exception as e:
    import traceback
    print("❌ 捕获到真实错误详情：")
    traceback.print_exc()