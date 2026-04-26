import os
import json
import importlib.util
import sys
import pandas as pd
import settings 

def get_normalize_func():
    """从 settings.UTILS_FILE 动态加载 normalize_version 函数"""
    utils_path = getattr(settings, "UTILS_FILE", "./utils.py")
    module_name = "custom_utils"
    spec = importlib.util.spec_from_file_location(module_name, utils_path)
    if spec is None:
        raise ImportError(f"无法找到工具文件: {utils_path}")
    utils_module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = utils_module
    spec.loader.exec_module(utils_module)
    return utils_module.normalize_version

def load_json(path):
    if not os.path.exists(path): return None
    with open(path, 'r', encoding='utf-8') as f:
        try: return json.load(f)
        except: return None

def main():
    # 1. 初始化与工具函数加载
    try:
        normalize_version = get_normalize_func()
    except Exception as e:
        print(f"❌ 工具函数加载失败: {e}")
        return

    # 从 settings 读取路径
    excel_path = getattr(settings, "EXCEL_FILE", None)
    result_dir = getattr(settings, "RESULT_DIR", "./results")
    basic_info_dir = getattr(settings, "BASIC_INFO_DIR", "./basic_info")
    
    if not excel_path or not os.path.exists(excel_path):
        print(f"❌ 未找到 Excel 文件: {excel_path}")
        return

    # 2. 读取 Excel 并预处理（保持原始顺序）
    # 不进行任何 sort_values 操作
    df = pd.read_excel(excel_path)
    df.columns = [c.upper() for c in df.columns] # 统一列名大写
    
    # 识别版本列
    version_col = 'VERSION' if 'VERSION' in df.columns else 'TAG'
    # 预先标准化所有版本号以便比对
    df['NORM_V'] = df[version_col].apply(lambda x: normalize_version(str(x)))

    patch_results_path = os.path.join(result_dir, "patch_only_results.json")
    patch_data = load_json(patch_results_path)
    if patch_data is None:
        print(f"❌ 无法读取目标文件: {patch_results_path}")
        return

    print(f"🔍 正在处理补丁传播逻辑（基于 Excel 原始顺序）...")

    # 3. 遍历 JSON 数据
    for cve_id, analysis_list in patch_data.items():
        # A. 从 basic_info 获取种子补丁
        info_path = os.path.join(basic_info_dir, f"{cve_id}.json")
        if not os.path.exists(info_path):
            info_path = os.path.join(basic_info_dir, f"{cve_id.lower()}.json")
        
        basic_info = load_json(info_path)
        seed_patches = []
        if basic_info and "findings" in basic_info:
            seed_patches = [normalize_version(f["detected_version"]) 
                            for f in basic_info["findings"] if f.get("type") == "patch"]
        
        # B. 补丁扩张逻辑（基于当前 CVE 的 Excel 子表，保持物理顺序）
        cve_df = df[df['CVE_ID'] == cve_id].copy().reset_index() # 这里的 index 是 cve_df 内部的 0,1,2...
        
        # 用于存储最终被确认为补丁的所有版本
        all_patch_versions = set(seed_patches)

        # 针对每一个种子补丁，在 Excel 物理顺序中向上向下传播
        for seed in seed_patches:
            # 找到种子补丁在 Excel 子表中的行索引
            seed_rows = cve_df[cve_df['NORM_V'] == seed].index.tolist()
            
            for seed_idx in seed_rows:
                # 只有种子补丁本身是 SUCCESS 才能传播
                if "BUILD_SUCCESS" not in str(cve_df.loc[seed_idx, 'EXECUTION RESULT']):
                    continue

                # 向上传播（索引减小方向）
                curr_up = seed_idx - 1
                while curr_up >= 0:
                    if "BUILD_SUCCESS" in str(cve_df.loc[curr_up, 'EXECUTION RESULT']):
                        all_patch_versions.add(cve_df.loc[curr_up, 'NORM_V'])
                        curr_up -= 1
                    else:
                        break # 遇到非 SUCCESS，停止该方向传播

                # 向下传播（索引增大方向）
                curr_down = seed_idx + 1
                while curr_down < len(cve_df):
                    if "BUILD_SUCCESS" in str(cve_df.loc[curr_down, 'EXECUTION RESULT']):
                        all_patch_versions.add(cve_df.loc[curr_down, 'NORM_V'])
                        curr_down += 1
                    else:
                        break # 遇到非 SUCCESS，停止该方向传播

        # C. 更新分析结果中的 true_result
        for entry in analysis_list:
            head_tag = entry.get("head_tag", "")
            norm_head = normalize_version(head_tag)
            
            is_match = False
            if norm_head:
                # 直接匹配扩张后的集合
                if norm_head in all_patch_versions:
                    is_match = True
                else:
                    # 模糊匹配兜底
                    for p_v in all_patch_versions:
                        if p_v and (norm_head in p_v or p_v in norm_head):
                            is_match = True
                            break
            
            entry["true_result"] = "yes" if is_match else "unknown"

    # 4. 写回 JSON
    with open(patch_results_path, 'w', encoding='utf-8') as f:
        json.dump(patch_data, f, indent=4, ensure_ascii=False)
    
    print(f"✨ 传播匹配完成！已根据 Excel 原始物理顺序更新: {patch_results_path}")

if __name__ == "__main__":
    main()