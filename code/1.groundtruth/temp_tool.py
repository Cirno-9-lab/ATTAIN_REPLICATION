import os
import re

def rename_target_directories(base_dir):
    """
    递归查找并更改符合特定模式的文件夹名称。
    将路径中 'src/test/java/' 的部分更改为 'src/main/java/'。

    Args:
        base_dir (str): 开始查找和更改的根目录。
    """
    if not os.path.isdir(base_dir):
        print(f"错误: 基础目录 '{base_dir}' 不存在。")
        return

    # 定义目标模式的正则表达式
    # 注意：这里的 '{}-{}' 是指CVE后面的数字或字符，我们可以匹配任意字符
    # 实际匹配时，我们只需要关注 'src/test/java/' 这部分。
    # pattern = re.compile(r'testcase-trigger/testcase-trigger/CVE-\w+-\d+/src/test/java/(.*)')
    
    # 遍历 base_dir 中的所有子目录
    for root, dirs, files in os.walk(base_dir, topdown=False): # topdown=False 确保先处理子目录
        for dir_name in dirs:
            current_path = os.path.join(root, dir_name)
            
            # 构建相对路径，以便我们能识别模式
            # 例如，如果 root 是 '/a/b/testcase-trigger/testcase-trigger/CVE-XXXX-YYYY/src/test/java'
            # 我们需要检查 '/CVE-XXXX-YYYY/src/test/java' 这段
            
            # 找到包含 'src/test/java/' 的路径
            if "src/test/java" in current_path:
                # 检查它是否是我们要修改的特定模式
                # 完整的模式是：testcase-trigger/testcase-trigger/CVE-{}-{}/src/test/java/{}
                # 我们需要确保 'src/test/java/' 是在正确的父级结构下
                
                # 更好的方式是直接替换路径字符串中固定不变的部分
                old_segment = os.path.join("src", "test", "java")
                new_segment = os.path.join("src", "main", "java")
                
                if old_segment in current_path:
                    # 构建新的路径
                    new_path = current_path.replace(old_segment, new_segment)
                    
                    if new_path != current_path:
                        try:
                            # 确保目标新目录的父目录存在
                            os.makedirs(os.path.dirname(new_path), exist_ok=True)
                            
                            # 只有当旧路径是目录且新路径不存在时才进行移动
                            if os.path.isdir(current_path) and not os.path.exists(new_path):
                                print(f"正在重命名: \n  '{current_path}' \n  到 \n  '{new_path}'")
                                os.rename(current_path, new_path)
                                # 由于 os.walk 在遍历时会缓存 dirs 列表，
                                # 重命名后需要确保后续遍历不会再次尝试访问旧路径
                                # 但由于 topdown=False，我们从底层往上处理，这通常不是问题。
                                # 如果 topdown=True，需要从 dirs 列表中移除 dir_name。
                            elif os.path.exists(new_path):
                                print(f"警告: 目标路径 '{new_path}' 已存在，跳过重命名 '{current_path}'。")
                            else:
                                print(f"信息: '{current_path}' 不是一个有效的目录，跳过。")
                        except OSError as e:
                            print(f"错误: 无法重命名 '{current_path}' 到 '{new_path}' - {e}")
                    else:
                        # 这种情况通常不会发生，除非替换字符串与原字符串完全相同
                        print(f"信息: 路径 '{current_path}' 未发生变化。")

# --- 使用示例 ---
if __name__ == "__main__":
    # 请将这里的 'your_base_directory' 替换为你的实际根目录
    # 例如，如果你的 testcase-trigger 目录位于当前脚本所在的目录，可以使用 '.'
    # 如果它在 /home/user/my_project，则使用 '/home/user/my_project'
    
    # 示例：假设 testcase-trigger 目录与此脚本在同一级
    base_directory_to_scan = './testcase-trigger' 
    # 或者如果你知道具体上级目录，例如：
    # base_directory_to_scan = '/home/xinweimao/alv_evaluate/vision-version.github.io-main/Vision/1.groundtruth/testcase-trigger'

    print(f"开始扫描目录 '{base_directory_to_scan}'...")
    rename_target_directories(base_directory_to_scan)
    print("重命名操作完成。")