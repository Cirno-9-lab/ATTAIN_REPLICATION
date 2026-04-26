import pandas as pd
import settings

def update_excel_verdict():
    # 1. 获取路径
    file_path = getattr(settings, 'EXCEL_FILE', None)
    
    if not file_path:
        print("错误：未在 settings.py 中找到 EXCEL_FILE 配置。")
        return

    try:
        # 2. 读取 Excel 文件
        # 根据文件后缀自动选择引擎 (openpyxl 适用于 .xlsx)
        df = pd.read_excel(file_path)

        # 3. 检查列是否存在，并填充数据
        # 无论该列是否存在，直接覆盖赋值为 'No_Data'
        df['LLM_Verdict'] = 'No_Data'

        # 4. 保存回原路径，不保存索引
        df.to_excel(file_path, index=False)
        print(f"成功更新文件：{file_path}")

    except FileNotFoundError:
        print(f"错误：找不到文件 {file_path}")
    except Exception as e:
        print(f"处理过程中出现异常：{e}")

if __name__ == "__main__":
    update_excel_verdict()