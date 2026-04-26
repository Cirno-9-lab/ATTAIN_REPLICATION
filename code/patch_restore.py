import re

def parse_git_patch(patch_content):
    """
    解析Git Patch内容，分离出修改前和修改后的代码行。

    Args:
        patch_content (str): 包含 Git diff 信息的文本。

    Returns:
        tuple: (list_of_original_lines, list_of_resulting_lines)
    """
    # 提取 "patch" 字段内的字符串内容，并处理转义字符
    match = re.search(r'"patch":\s*"([^"]*)"', patch_content)
    if not match:
        return "错误：未找到有效的 'patch' 内容。", "错误：未找到有效的 'patch' 内容。"

    patch_text = match.group(1)
    # 替换转义的换行符和制表符
    patch_text = patch_text.replace(r'\n', '\n').replace(r'\t', '\t')

    # 将文本按行分割
    lines = patch_text.split('\n')

    original_lines = []
    resulting_lines = []
    
    # 缩进字符串（使用4个空格代替\t）
    INDENT = '    ' 

    for line in lines:
        # 忽略 Git diff 的头部信息行，如 @@ ... @@
        if line.startswith('@@'):
            continue
        
        # 移除行首的制表符，并转换为4个空格
        cleaned_line = line.replace('\t', INDENT)

        if cleaned_line.startswith('-'):
            # 修改前（Original）的代码行
            # 移除行首的 '- ' 标记
            original_lines.append(cleaned_line[1:].strip())
            # 对于 'resulting_lines'，需要保留上下文行
            # 这里的处理方式是：修改前的代码在修改后的代码中被删除，所以不添加到 resulting_lines。
            
        elif cleaned_line.startswith('+'):
            # 修改后（Resulting）的代码行
            # 移除行首的 '+ ' 标记
            resulting_lines.append(cleaned_line[1:].strip())
            # 对于 'original_lines'，修改后的代码是新增的，不属于原始代码。
            
        elif cleaned_line.startswith(' '):
            # 上下文（Context）代码行，修改前后都存在
            # 移除行首的 ' ' 标记
            context_line = cleaned_line[1:].strip()
            original_lines.append(context_line)
            resulting_lines.append(context_line)

    # 简单清理：去除可能是空行的内容
    original_lines = [line for line in original_lines if line]
    resulting_lines = [line for line in resulting_lines if line]

    return original_lines, resulting_lines

# 输入文本
commit_text = """
"patch": "@@ -2240,19 +2240,14 @@ public static BigDecimal toBigDecimal(String numberStr) {\n \t\t\treturn BigDecimal.ZERO;\n \t\t}\n \n-\t\ttry {\n-\t\t\t// 支持类似于 1,234.55 格式的数字\n-\t\t\tfinal Number number = parseNumber(numberStr);\n-\t\t\tif (number instanceof BigDecimal) {\n-\t\t\t\treturn (BigDecimal) number;\n-\t\t\t} else {\n-\t\t\t\treturn new BigDecimal(number.toString());\n-\t\t\t}\n-\t\t} catch (Exception ignore) {\n+\t\ttry{\n+\t\t\treturn new BigDecimal(numberStr);\n+\t\t} catch (Exception ignore){\n \t\t\t// 忽略解析错误\n \t\t}\n \n-\t\treturn new BigDecimal(numberStr);\n+\t\t// 支持类似于 1,234.55 格式的数字\n+\t\treturn toBigDecimal(parseNumber(numberStr));\n \t}\n \n \t/**"
"""

# 执行解析
original_code_lines, resulting_code_lines = parse_git_patch(commit_text)


# ---- 结果输出 ----

print("=" * 60)
print("             🚀 修改前 (ORIGINAL) 代码 🚀")
print("=" * 60)
print("public static BigDecimal toBigDecimal(String numberStr) {")
for line in original_code_lines:
    print(line)
print("    }")
print("\n" * 2)

print("=" * 60)
print("             ✅ 修改后 (RESULTING) 代码 ✅")
print("=" * 60)
print("public static BigDecimal toBigDecimal(String numberStr) {")
for line in resulting_code_lines:
    print(line)
print("    }")