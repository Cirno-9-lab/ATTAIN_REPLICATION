import os
import subprocess
import requests
import xml.etree.ElementTree as ET

def get_demo_directories(cve_root_dir):
    return [os.path.join(cve_root_dir, d) for d in os.listdir(cve_root_dir) 
            if os.path.isdir(os.path.join(cve_root_dir, d)) and d.startswith('demo')]
    

def fetch_versions_from_metadata(metadata_url):
    response = requests.get(metadata_url)
    if response.status_code == 200:
        root = ET.fromstring(response.content)
        versions = root.find(".//versions")
        if versions is not None:
            return [v.text for v in versions.findall("version")]
    return []


def collect_versions(group_id, artifact_id):
    base_url = "https://repo.maven.apache.org/maven2"
    metadata_url = f"{base_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    return fetch_versions_from_metadata(metadata_url)

    
def get_version(package_name, cve_id):
    file_path = '/PoCEmpirical/reproduce/all.txt'

    first_patched_version = None
    group_id, artifact_id = '', ''

    # 查找first patched version 和 artifact信息
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            parts = line.strip().split('\t')
            if len(parts) < 7:
                continue
            cve, pkg, *_ , patched_version = parts
            if cve == cve_id and pkg == package_name:
                first_patched_version = patched_version
                if ':' in pkg:
                    group_id, artifact_id = pkg.split(':', 1)
                break

    if not first_patched_version or not group_id or not artifact_id:
        return None  # 信息不足

    # 获取所有版本列表
    versions = collect_versions(group_id, artifact_id)
    if first_patched_version not in versions:
        return None  # 如果补丁版本不在版本列表中，返回None

    # 获取补丁版本的前一个版本
    idx = versions.index(first_patched_version)
    if idx == 0:
        return None  # 没有更早的版本
    return versions[idx - 1]
    
    
data = [] 
with open('G:\\hard_fork\\PoCEmpirical\\reproduce\\disclosed-version.txt', 'r', encoding='utf-8') as file:
    for line in file:
        parts = line.strip().split('\t')
        while len(parts) < 4:
            parts.append('')
        data.append(parts)  # 不再是 tuple，而是 list


import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--log_file', required=True)
parser.add_argument('--result', required=True)
args = parser.parse_args()

log_file = args.log_file
result = args.result


for entry in data:
    
    package_name = entry[0]
    group_id = package_name.split(":")[0]
    library_name = package_name.split(":")[1]
    
    cve_id = entry[1]
    version = entry[2]
    behavior = entry[3]
    
        
    root_dir = f"G:\\hard_fork\\PoCEmpirical\\reproduce\\exploits\\{cve_id}"
    
    demo_dirs = get_demo_directories(root_dir)

    for demo_dir in demo_dirs:
        pom_file = os.path.join(demo_dir, "pom.xml")  
        if os.path.exists(pom_file):
            # try:
            #     update_command = f"mvn versions:use-dep-version -Dincludes={group_id}:{library_name} -DdepVersion={version} -f {pom_file}"
            #     subprocess.run(update_command, shell=True, check=True)
            #     print(f"Updated {library_name} to version {version} in {pom_file}")
                
            #     test_command_clean = f"mvn clean -f {pom_file}"
            #     subprocess.run(test_command_clean, shell=True, check=True)
            #     print("cleaned")
                
                
            # except subprocess.CalledProcessError as e:
            #     stdout = e.stdout.decode('utf-8') if e.stdout else "No output"
            #     stderr = e.stderr.decode('utf-8') if e.stderr else "No error output"
            #     print(stdout)
            #     with open(result, 'a') as log:
            #         log.write(f"Failed Updated for {library_name} version {version} in {demo_dir}:\n")
                        
                        
            
            if library_name == 'c3p0':
                test_command = f"mvn test -DargLine=\"-Xms4g -Xmx4g\" -f {pom_file}"
            elif library_name == 'jline-parent':
                test_command = f"mvn test -f {pom_file}"
            elif library_name == 'commons-compress' and cve_id == 'CVE-2024-26308':
                test_command = f"mvn test -DargLine=\"-da -Xms1g -Xmx1g\" -f {pom_file}"
            elif library_name == 'commons-compress':
                test_command = f"mvn test -DargLine=\"-da -Xms16g -Xmx16g\" -f {pom_file}"
            elif library_name == 'snappy-java' and cve_id == 'CVE-2023-43642':
                test_command = f"mvn test -DargLine=\"-da -Xms1g -Xmx1g\" -f {pom_file}"
            elif library_name == 'snappy-java':
                test_command = f"mvn test -DargLine=\"-da -Xms16g -Xmx16g\" -f {pom_file}"
            elif library_name == 'json':
                test_command = f"mvn test -DargLine=\"-Xms128m -Xmx128m\" -f {pom_file}"
            elif library_name == 'hutool-json' and cve_id == 'CVE-2022-45690':
                test_command = f"mvn test -DargLine=\"-Xms128m -Xmx128m\" -f {pom_file}"
            elif library_name == 'jackson-dataformat-cbor':
                test_command = f"mvn test -DargLine=\"-Xms1g -Xmx1g\" -f {pom_file}"
            elif library_name == 'snakeyaml' and cve_id == 'CVE-2022-38750':
                test_command = f"mvn test -DargLine=\"-Xms256m -Xmx256m\" -f {pom_file}"
            else:
                test_command = f"mvn test -DargLine=\"-da -Xms2g -Xmx2g\" -f {pom_file}"
            
            
            try:
                subprocess.run(test_command, shell=True, check=True, capture_output=True)
                print(f"Tests completed for {library_name} version {version} in {demo_dir}")
        
                with open(result, 'a') as log:
                    log.write(f"No vulnerabiltiy for {library_name} version {version} in {demo_dir}:\n")
                    
                        
            except subprocess.CalledProcessError as e:
                stdout = e.stdout.decode('gbk', errors='ignore') if e.stdout else "No output"
                stderr = e.stderr.decode('gbk', errors='ignore') if e.stderr else "No error output"
                print(stdout)
                
                
                if behavior in stdout:
                    with open(result, 'a') as log:
                        log.write(f"Successfully Reproduced for {library_name} version {version} in {demo_dir}:\n")
                    
                    with open(log_file, 'a') as log:
                        log.write(f"Successfully Reproduced for {library_name} version {version} in {demo_dir}:\n")    
                        log.write(f"Standard Output: {stdout}\n")
                        log.write(f"\n\n\n\n\n\n\n\n\n\n\n\n\n")
                else:
                    with open(result, 'a') as log:
                        log.write(f"Failed Reproduced for {library_name} version {version} in {demo_dir}:\n")
                    
                    with open(log_file, 'a') as log:
                        log.write(f"Failed Reproduced for {library_name} version {version} in {demo_dir}:\n")
                        log.write(f"Standard Output: {stdout}\n")
                        log.write(f"\n\n\n\n\n\n\n\n\n\n\n\n\n")
                        
                        
            test_command_clean = f"mvn clean -f {pom_file}"
            subprocess.run(test_command_clean, shell=True, check=True)
            print("cleaned")
                    
          
    # if version == '-':
    #     print(CVE_id)
    #     patched_version = get_version(package_name, CVE_id)
    #     print(patched_version)
    #     if patched_version:
    #         entry[2] = patched_version  # 更新 version 字段
    

# with open('/PoCEmpirical/reproduce/completed.txt', 'w', encoding='utf-8') as out_file:
#     for entry in data:
#         out_file.write('\t'.join(entry) + '\n')
       
