import os
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
from huggingface_hub import snapshot_download

# 执行下载（模型会自动下载到当前目录下的 'my_model' 文件夹）
snapshot_download(repo_id="Qwen/Qwen2.5-Coder-7B-Instruct", local_dir="./my_model", local_dir_use_symlinks=False)