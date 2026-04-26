import torch
import torchvision
import torchaudio

print(f"Python Version: {torch.__version__}")
print(f"CUDA Available: {torch.cuda.is_available()}")
print(f"CUDA Version in Torch: {torch.version.cuda}")

try:
    # 核心检查：验证 torchvision 算子是否正常
    from torchvision.ops import nms
    test_box = torch.rand(1, 4).cuda()
    test_score = torch.tensor([0.9]).cuda()
    nms(test_box, test_score, 0.5)
    print("✅ 算子检查通过：torchvision::nms 运行正常！")
except Exception as e:
    print(f"❌ 算子检查失败: {e}")

try:
    from sentence_transformers import SentenceTransformer
    print("✅ 导入检查通过：SentenceTransformer 加载正常！")
except Exception as e:
    print(f"❌ 导入检查失败: {e}")