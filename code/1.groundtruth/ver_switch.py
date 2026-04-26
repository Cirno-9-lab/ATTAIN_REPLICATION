import json
import os
import xml.etree.ElementTree as ET
import subprocess
import shutil
import pandas as pd
import time
from datetime import datetime

def run_cve_tests_sequential(cve_id: str, target_group_id: str, target_artifact_id: str, maven_namespace_uri: str, workspace_dir: str):
    """
    单进程顺序执行 CVE 版本测试，并将所有结果统一输出到 ver_test/CVE-{cve_id}.json。
    包含查找逻辑修正，以兼容缺少默认命名空间的 pom.xml。

    Args:
        cve_id (str): 要测试的 CVE ID。
        target_group_id (str): 要更改版本的库的 groupId。
        target_artifact_id (str): 要更改版本的库的 artifactId。
        maven_namespace_uri (str): Maven POM 的完整 XML 命名空间 URI。
        workspace_dir (str): 项目的根目录路径 (/alv_evaluate/myResearch/workspace)。
    """
    
    # 路径配置
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 项目基础路径：/.../code/1.groundtruth/testcase-trigger/testcase-trigger/CVE_ID
    base_path = os.path.join(script_dir, "testcase-trigger", "testcase-trigger", cve_id)
    pom_file_path = os.path.join(base_path, "pom.xml")

    # 1. 读取 trueresult.json
    try:
        # 假设 trueresult.json 位于脚本运行的当前目录下
        with open('trueresult.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("错误：trueresult.json 文件未找到。请确保它位于脚本的同一目录下。")
        return
    except json.JSONDecodeError:
        print("错误：trueresult.json 文件内容格式不正确，请检查 JSON 语法。")
        return

    cve_data = data.get(cve_id, {})
    affected_versions = cve_data.get("affected", [])
    unaffected_versions = cve_data.get("unaffected", [])

    if not affected_versions and not unaffected_versions:
        print(f"在 trueresult.json 中未找到 CVE ID: {cve_id} 的 affected 或 unaffected 版本信息。跳过。")
        return

    print(f"找到 CVE ID: {cve_id} 的 affected 版本：{affected_versions}")
    print(f"找到 CVE ID: {cve_id} 的 unaffected 版本：{unaffected_versions}")

    if not os.path.exists(pom_file_path):
        print(f"错误：项目 {cve_id} 的 pom.xml 文件未找到，路径为：{pom_file_path}")
        return

    try:
        with open(pom_file_path, 'r', encoding='utf-8') as f:
            original_pom_content = f.read()
    except Exception as e:
        print(f"读取原始 pom.xml 文件失败：{e}")
        return

    all_test_results = {
        "cve_id": cve_id,
        "tested_library": f"{target_group_id}:{target_artifact_id}",
        "results_by_version": []
    }

    versions_to_test = []
    for ver in affected_versions:
        versions_to_test.append({"version": ver, "type": "affected"})
    for ver in unaffected_versions:
        versions_to_test.append({"version": ver, "type": "unaffected"})

    for item in versions_to_test:
        version = item["version"]
        version_type = item["type"]
        print(f"\n--- 正在处理版本：{version} ({version_type}) ---")

        test_result_entry = {
            "version": version,
            "version_type": version_type,
            "status": "未执行",
            "return_code": None,
            "stdout": "",
            "stderr": ""
        }

        try:
            # 恢复 pom.xml
            with open(pom_file_path, 'w', encoding='utf-8') as f:
                f.write(original_pom_content)
        except Exception as e:
            print(f"恢复 {pom_file_path} 到原始内容时发生错误：{e}")
            test_result_entry["status"] = "错误"
            test_result_entry["stderr"] = f"恢复 pom.xml 原始内容失败: {e}"
            all_test_results["results_by_version"].append(test_result_entry)
            continue

        try:
            # 解析 pom.xml
            tree = ET.parse(pom_file_path)
            root = tree.getroot()
            
            target_dependency = None
            
            # --- 依赖查找逻辑：优先带命名空间，失败回退到不带命名空间 ---
            
            # 1. 尝试使用命名空间查找 <dependencies> 节点
            dependencies_nodes = root.findall(f'{{{maven_namespace_uri}}}dependencies')
            ns_mode = True # 标记是否使用命名空间模式
            
            # 2. 如果命名空间查找失败，则回退到不带命名空间的查找
            if not dependencies_nodes:
                dependencies_nodes = root.findall('dependencies')
                ns_mode = False 
                
            if not dependencies_nodes:
                 raise ValueError("在 POM 中未找到 <dependencies> 节点 (带/不带命名空间均未找到)。")
                 
            # 3. 确定内层查找路径
            if ns_mode: 
                dependency_path, group_path, artifact_path, version_path = \
                    f'{{{maven_namespace_uri}}}dependency', f'{{{maven_namespace_uri}}}groupId', f'{{{maven_namespace_uri}}}artifactId', f'{{{maven_namespace_uri}}}version'
            else:
                dependency_path, group_path, artifact_path, version_path = 'dependency', 'groupId', 'artifactId', 'version'

            # 4. 遍历查找目标依赖
            for dependencies_node in dependencies_nodes:
                for dependency in dependencies_node.findall(dependency_path):
                    
                    group_id_elem = dependency.find(group_path)
                    artifact_id_elem = dependency.find(artifact_path)
                    
                    if (group_id_elem is not None and group_id_elem.text == target_group_id and
                        artifact_id_elem is not None and artifact_id_elem.text == target_artifact_id):
                        target_dependency = dependency
                        break 
                if target_dependency is not None:
                    break
            
            # --- 依赖查找逻辑修正结束 ---

            if target_dependency is None:
                raise ValueError(f"在 {pom_file_path} 中未找到目标依赖 '{target_group_id}:{target_artifact_id}'。请检查 XML 结构或 Excel 数据。")

            # 查找并修改 <version> 标签
            version_element = target_dependency.find(version_path)
            if version_element is None:
                raise ValueError(f"已找到目标依赖 '{target_group_id}:{target_artifact_id}'，但在其中缺少 <version> 标签。")

            version_element.text = version
            
            # 序列化并清理 XML
            xml_string_with_ns0 = ET.tostring(root, encoding='utf-8', xml_declaration=True).decode('utf-8')
            cleaned_xml_string = xml_string_with_ns0.replace('ns0:', '').replace('xmlns:ns0="http://maven.apache.org/POM/4.0.0"', '')

            # 写入文件
            with open(pom_file_path, 'w', encoding='utf-8') as f:
                f.write(cleaned_xml_string)

            print(f"已更新 {pom_file_path} 中的版本为：{version}")

            if os.path.exists(base_path):
                print(f"正在 {base_path} 目录下执行 'mvn clean test'...")
                process = subprocess.run(
                    ["mvn", "clean", "test"],
                    cwd=base_path,
                    capture_output=True,
                    text=True,
                    check=False
                )
                test_result_entry["return_code"] = process.returncode
                
                # *** 修正：处理 subprocess.run 输出的 None 值 ***
                test_result_entry["stdout"] = process.stdout if process.stdout is not None else ""
                test_result_entry["stderr"] = process.stderr if process.stderr is not None else ""
                
                if process.returncode == 0:
                    test_result_entry["status"] = "成功"
                    print(f"'mvn clean test' 针对版本 {version} 成功完成。")
                else:
                    test_result_entry["status"] = "失败"
                    print(f"'mvn clean test' 针对版本 {version} 失败，退出码：{process.returncode}。")
            else:
                test_result_entry["status"] = "错误"
                print(f"错误：项目目录 {base_path} 不存在。")
                test_result_entry["stderr"] = f"项目目录 {base_path} 不存在。"

        except FileNotFoundError:
            test_result_entry["status"] = "错误"
            test_result_entry["stderr"] = "'mvn' 命令未找到。请确保 Maven 已安装并配置在 PATH 环境变量中。"
            print(f"错误：{test_result_entry['stderr']}")
        except Exception as e:
            test_result_entry["status"] = "异常"
            test_result_entry["stderr"] = str(e)
            print(f"执行 'mvn clean test' 或文件操作时发生异常：{e}")
        finally:
            all_test_results["results_by_version"].append(test_result_entry)

    # 恢复 pom.xml 到原始版本
    if original_pom_content:
        print(f"\n--- 所有测试完成，恢复 {pom_file_path} 到原始版本 ---")
        try:
            with open(pom_file_path, 'w', encoding='utf-8') as f:
                f.write(original_pom_content)
            print("pom.xml 已成功恢复到原始版本。")
        except Exception as e:
                print(f"恢复 {pom_file_path} 时发生错误：{e}")

    # **输出结果到 ver_test**
    output_dir = os.path.join(workspace_dir, "dataset", "ver_test")
    os.makedirs(output_dir, exist_ok=True)

    output_file_name = f"{cve_id}.json"
    output_file_path = os.path.join(output_dir, output_file_name)

    try:
        with open(output_file_path, 'w', encoding='utf-8') as outfile:
            json.dump(all_test_results, outfile, indent=4, ensure_ascii=False)
        print(f"\n所有测试结果已统一保存到：{output_file_path}")
    except Exception as e:
        print(f"写入最终测试结果到 JSON 文件时发生错误：{e}")

if __name__ == "__main__":
    # --- 计时开始 ---
    start_time = time.time()
    start_time_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"脚本开始执行时间: {start_time_str}")
    
    # --- 目录配置 ---
    # 脚本路径：/.../workspace/code/1.groundtruth/data_stat.py
    script_dir = os.path.dirname(os.path.abspath(__file__))
    code_dir = os.path.dirname(script_dir) 
    workspace_dir = os.path.dirname(code_dir) # /.../workspace
    
    # --- 输入文件路径 ---
    # 目标 Excel 文件路径: /.../workspace/dataset/cve_dataset.xlsx
    excel_file_path = os.path.join(workspace_dir, "dataset", "cve_dataset.xlsx")
    
    # 定义 Maven POM 的标准默认命名空间 URI
    MAVEN_POM_NAMESPACE = "http://maven.apache.org/POM/4.0.0"

    print(f"正在读取 CVE 数据文件: {excel_file_path}")

    try:
        df = pd.read_excel(excel_file_path)
    except FileNotFoundError:
        print(f"错误：找不到 Excel 文件：{excel_file_path}")
        exit(1)
    except Exception as e:
        print(f"读取 Excel 文件时发生错误: {e}")
        exit(1)
    
    required_cols = ['cve_id', 'target_group_id', 'target_artifact_id']
    if not all(col in df.columns for col in required_cols):
        print(f"错误：Excel 文件缺少必要的列。所需的列名：{required_cols}")
        exit(1)
        
    print(f"已成功读取 {len(df)} 条 CVE 记录。开始顺序执行测试...")

    # 遍历 DataFrame 的每一行，调用测试函数
    for index, row in df.iterrows():
        try:
            current_cve_id = str(row['cve_id']).strip()
            current_target_group_id = str(row['target_group_id']).strip()
            current_target_artifact_id = str(row['target_artifact_id']).strip()
            
            print(f"\n=======================================================")
            print(f"开始测试记录 {index + 1}/{len(df)}：CVE ID: {current_cve_id}")
            print(f"目标依赖: {current_target_group_id}:{current_target_artifact_id}")
            print(f"=======================================================")

            run_cve_tests_sequential(
                cve_id=current_cve_id,
                target_group_id=current_target_group_id,
                target_artifact_id=current_target_artifact_id,
                maven_namespace_uri=MAVEN_POM_NAMESPACE,
                workspace_dir=workspace_dir # 传入 workspace_dir 用于输出路径计算
            )
            
        except Exception as e:
            print(f"\n*** 警告: 处理 CVE ID {current_cve_id} 时发生错误: {e} ***")
            continue
    
    print("\n所有 CVE 记录处理完成。")

    # --- 计时结束与日志输出 ---
    end_time = time.time()
    end_time_dt = datetime.now()
    end_time_str_for_file = end_time_dt.strftime("%Y%m%d_%H%M%S")
    total_execution_time = end_time - start_time
    
    log_content = f"--- 脚本执行计时信息 ---\n"
    log_content += f"脚本开始时间: {start_time_str}\n"
    log_content += f"脚本结束时间: {end_time_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
    log_content += f"总执行时间: {total_execution_time:.2f} 秒 ({total_execution_time / 60:.2f} 分钟)\n"

    # 日志输出目录: /alv_evaluate/myResearch/workspace/dataset/log/
    log_dir = os.path.join(workspace_dir, "dataset", "log")
    os.makedirs(log_dir, exist_ok=True)
    
    log_file_name = f"ver_switch_log_{end_time_str_for_file}.txt"
    log_file_path = os.path.join(log_dir, log_file_name)

    try:
        with open(log_file_path, 'w', encoding='utf-8') as log_file:
            log_file.write(log_content)
        print(f"\n✅ 计时信息已保存到日志文件: {log_file_path}")
    except Exception as e:
        print(f"\n❌ 写入计时日志文件时发生错误: {e}")