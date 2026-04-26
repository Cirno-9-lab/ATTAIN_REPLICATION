import os

def check_folders():
    # 获取当前目录下所有的文件夹
    items = [f for f in os.listdir('.') if os.path.isdir(f)]
    
    # 统计文件夹名称（不区分大小写），用于第二次判断
    lower_counts = {}
    for item in items:
        name_lower = item.lower()
        lower_counts[name_lower] = lower_counts.get(name_lower, 0) + 1

    print(f"{'文件夹名称':<30} | {'状态':<10} | {'备注'}")
    print("-" * 60)

    for folder in items:
        # 判断是否为空 (ls -A 逻辑：没有任何文件或子目录)
        is_empty = len(os.listdir(folder)) == 0
        status = "空" if is_empty else "不为空"
        note = ""

        # 第二次判断：如果文件夹为空，且存在另一个忽略大小写同名的文件夹
        if is_empty and lower_counts[folder.lower()] > 1:
            note = "⚠️ 存在同名(忽略大小写)的文件夹"
        
        print(f"{folder:<30} | {status:<10} | {note}")

if __name__ == "__main__":
    check_folders()