import os
import subprocess
import requests
import xml.etree.ElementTree as ET
import settings  # 导入配置

def get_demo_directories(cve_root_dir):
    return [os.path.join(cve_root_dir, d) for d in os.listdir(cve_root_dir) 
            if os.path.isdir(os.path.join(cve_root_dir, d)) and d.startswith('demo')]

# 修改点：默认参数使用 settings 中的路径
def read_versions_from_file(artifact_id, library_root_dir=settings.LIBRARY_ROOT):
    artifact_dir = os.path.join(library_root_dir, artifact_id)
    version_file_path = os.path.join(artifact_dir, "version.txt")

    if not os.path.exists(version_file_path):
        raise FileNotFoundError(f"Version file not found: {version_file_path}")

    with open(version_file_path, 'r') as file:
        versions = [line.strip() for line in file.readlines()]
    
    return versions

# 修改点：默认参数使用 settings 中的路径
def write_summary_to_file(aggregated_results, artifact_id, cve_id, result_root_dir=settings.RESULT_ROOT):
    result_file_path = os.path.join(result_root_dir, f"{artifact_id}-{cve_id}.txt")
    
    os.makedirs(os.path.dirname(result_file_path), exist_ok=True)

    with open(result_file_path, 'w') as result_file:
        for version, version_results in aggregated_results.items():
            version_result = f"Version: {version}"
            for demo_dir, status in version_results:
                result_line = f"{version_result}, Demo directory: {demo_dir}, Status: {status}"
                print(result_line)
                result_file.write(result_line + "\n")
    
    print(f"Summary written to {result_file_path}")

def fetch_versions_from_metadata(metadata_url):
    response = requests.get(metadata_url)
    if response.status_code == 200:
        root = ET.fromstring(response.content)
        versions = root.find(".//versions")
        if versions is not None:
            return [version.text for version in versions.findall("version")]
        return []
    return []

# 修改点：默认参数使用 settings 中的路径
def save_versions_to_file(artifact_id, versions, library_root_dir=settings.LIBRARY_ROOT):
    artifact_dir = os.path.join(library_root_dir, artifact_id)
    os.makedirs(artifact_dir, exist_ok=True)
    version_file_path = os.path.join(artifact_dir, "version.txt")
    with open(version_file_path, 'w') as file:
        for version in versions:
            file.write(f"{version}\n")

def collect(group_id, artifact_id):
    base_url = "https://repo.maven.apache.org/maven2"
    metadata_url = f"{base_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    versions = fetch_versions_from_metadata(metadata_url)
    save_versions_to_file(artifact_id, versions)

def main():
    cve_id = 'CVE-2022-42004'
    
    # 修改点：使用 settings 中的 exploits 路径
    root_dir = os.path.join(settings.EXPLOITS_ROOT, cve_id)
    
    group_id = "com.fasterxml.jackson.core"
    library_name = "jackson-databind" 
    reproduce_input = "java.lang.StackOverflowError"
    
    collect(group_id, library_name)
    versions = read_versions_from_file(library_name)
    demo_dirs = get_demo_directories(root_dir)
    
    aggregated_results = {}
    
    # 修改点：使用 settings 中的 result 路径
    log_directory = os.path.join(settings.RESULT_ROOT, library_name)
    os.makedirs(log_directory, exist_ok=True) # 确保日志目录存在
    log_file = os.path.join(log_directory, f'{cve_id}-log')
    
    with open(log_file, 'w') as log:
        log.truncate(0)

    for version in versions:
        print(f"Running tests for {library_name} version {version}...")
        for demo_dir in demo_dirs:
            pom_file = os.path.join(demo_dir, "pom.xml")
        
            if os.path.exists(pom_file):
                # Maven 更新命令
                update_command = f"mvn versions:use-dep-version -Dincludes={group_id}:{library_name} -DdepVersion={version} -f {pom_file}"
                subprocess.run(update_command, shell=True, check=True)

                # 根据库名选择测试命令（保持逻辑不变）
                if library_name == 'c3p0':
                    test_command = f"mvn test -DargLine=\"-Xms4g -Xmx4g\" -f {pom_file}"
                # ... (中间省略其他 elif 逻辑以节省篇幅，实际应用中请保留原始 elif 段落)
                else:
                    test_command = f"mvn test -DargLine=\"-da -Xms2g -Xmx2g\" -f {pom_file}"
                
                test_command_clean = f"mvn clean -f {pom_file}"
                aggregated_results[version] = aggregated_results.get(version, [])
                
                try:
                    subprocess.run(test_command_clean, shell=True, check=True, capture_output=True)
                    subprocess.run(test_command, shell=True, check=True, capture_output=True)
                    
                    with open(log_file, 'a') as log:
                        log.write(f"Success for {library_name} version {version} in {demo_dir}:\n\n\n")
                    aggregated_results[version].append((demo_dir, "no vulnerability"))
                    
                except subprocess.CalledProcessError as e:
                    stdout = e.stdout.decode('utf-8') if e.stdout else ""
                    if reproduce_input in stdout:
                        # 漏洞复现成功逻辑
                        aggregated_results[version].append((demo_dir, "Vulnerability reproduced when executing Poc"))
                    else:
                        # 其他失败逻辑
                        aggregated_results[version].append((demo_dir, "Error occure when executing Poc"))
            else:
                aggregated_results.setdefault(version, []).append((demo_dir, "pom file not found"))

    write_summary_to_file(aggregated_results, library_name, cve_id)

if __name__ == "__main__":
    main()