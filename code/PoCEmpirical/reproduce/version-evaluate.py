import os
import subprocess
import requests
import xml.etree.ElementTree as ET

def get_demo_directories(cve_root_dir):
    return [os.path.join(cve_root_dir, d) for d in os.listdir(cve_root_dir) 
            if os.path.isdir(os.path.join(cve_root_dir, d)) and d.startswith('demo')]
    

def get_actual_version(demo_dir, group_id, artifact_id):
    try:
        result = subprocess.run(
            ["mvn", "dependency:list", f"-Dincludes={group_id}:{artifact_id}"],
            cwd=demo_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        output = result.stdout
        for line in output.splitlines():
            line = line.strip()
            # 例子：com.fasterxml.jackson.core:jackson-databind:jar:2.9.10.1:compile
            if f"{group_id}:{artifact_id}:" in line:
                parts = line.split(":")
                if len(parts) >= 4:
                    return parts[3]
    except Exception as e:
        print(f"[ERROR] Failed to get version in {demo_dir}: {e}")
    return None

    
data = [] 
with open('/PoCEmpirical/reproduce/disclosed-version.txt', 'r', encoding='utf-8') as file:
    for line in file:
        parts = line.strip().split('\t')
        while len(parts) < 4:
            parts.append('')
        data.append(parts)  # 不再是 tuple，而是 list


for entry in data:
    
    package_name = entry[0]
    group_id = package_name.split(":")[0]
    artifact_id = package_name.split(":")[1]
    
    cve_id = entry[1]
    expected_version = entry[2]
    behavior = entry[3]
    
        
    root_dir = f"/PoCEmpirical/reproduce/exploits/{cve_id}"
    
    demo_dirs = get_demo_directories(root_dir)

    for demo_dir in demo_dirs:
        pom_file = os.path.join(demo_dir, "pom.xml")  
        if os.path.exists(pom_file):
            actual_version = get_actual_version(demo_dir, group_id, artifact_id)
            if actual_version:
                if actual_version == expected_version:
                    print(f"[PASS] {demo_dir} uses expected version {actual_version}")
                else:
                    print(f"[FAIL] {demo_dir} uses {actual_version}, expected {expected_version}")
            else:
                print(f"[MISS] {demo_dir} does not list {group_id}:{artifact_id}")