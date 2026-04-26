import pandas as pd

# 文件路径
file_path = '/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/execution_result.xlsx'

try:
    df = pd.read_excel(file_path)

    # 统计 'Library' 列中不重复的值
    library_count = df['Library'].nunique()

    print(f"文件中的不重复 Library 数量为: {library_count}")
    
    # 如果你想看具体的列表，可以取消下面这行的注释：
    # print(df['Library'].unique())

except KeyError:
    print("错误：文件中未找到名为 'Library' 的列，请检查表头名称。")
except Exception as e:
    print(f"读取文件时出错: {e}")