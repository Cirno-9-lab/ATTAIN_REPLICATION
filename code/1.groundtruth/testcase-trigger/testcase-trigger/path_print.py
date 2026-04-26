import os
import pandas as pd

# 1. 替换为您的实际目录路径
directory_path = './testcase-trigger' 

# 2. 读取所有首级文件夹名称
try:
    # 筛选出目录（文件夹）名称
    folder_names = [
        name for name in os.listdir(directory_path) 
        if os.path.isdir(os.path.join(directory_path, name))
    ]
except FileNotFoundError:
    print(f"错误：找不到目录 {directory_path}。请检查路径是否正确。")
    exit()

# 3. 创建一个 DataFrame，并按列存储
# 这里将列表转换为 Pandas Series，使其按列存储
df = pd.DataFrame(folder_names, columns=['CVE_ID'])

# 4. 存储到 a.xlsx 文件
output_file = 'a.xlsx'
try:
    df.to_excel(output_file, index=False)
    print(f"成功将 {len(folder_names)} 个文件夹名称存储到 {output_file} 文件中。")
except Exception as e:
    print(f"写入 Excel 文件时发生错误: {e}")