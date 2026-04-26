import json
import sys
import os
import settings  # 确保 settings.py 在路径中
from llm import Client  # 调用你提供的 Client 类

class CVEOfflineAuditor:
    def __init__(self):
        try:
            self.llm = Client()
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    def get_cve_metadata(self, cve_id):
        """Read OWNER and REPO from the JSON file specified in settings.py"""
        file_path = getattr(settings, "CVE_LIST_FILE", "cve_list.json")
        
        if not os.path.exists(file_path):
            print(f"❌ Error: File not found at {file_path}")
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get(cve_id)
        except Exception as e:
            print(f"❌ Error reading JSON: {e}")
            return None

    def run_analysis(self, cve_id):
        # 1. 获取元数据
        metadata = self.get_cve_metadata(cve_id)
        if not metadata:
            print(f"⚠️ No metadata found for {cve_id} in {settings.CVE_LIST_FILE}")
            return

        owner = metadata.get("OWNER", "")
        repo = metadata.get("REPO", "")

        # 2. 构造精简英文提示词 (移除了 e.g. 等所有干扰项)
        prompt = f"""
You are a senior cybersecurity architect and code audit expert. Perform a deep technical audit of {cve_id} based on your pre-trained knowledge base.

Target Repository: {owner}/{repo}

Output the report strictly according to the following structure:

## 1. Root Cause
- Technical explanation of the affected component.

## 2. Patch Analysis
- Identify the core classes and methods where the fix was applied.
- Describe the introduced defense mechanisms. 

Requirements: The response must be precise and grounded. Strictly forbid hallucinations.
"""

        print(f"🔬 Auditing {cve_id} (Repo: {owner}/{repo})...")
        
        # 3. 调用 llm.py 的 call_llm 方法
        report = self.llm.call_llm(prompt)
        return report

if __name__ == "__main__":
    # 示例运行：以 CVE-2014-3625 为例
    target_cve = "CVE-2014-3625"
    auditor = CVEOfflineAuditor()
    
    report = auditor.run_analysis(target_cve)
    
    if report:
        if report == "STOP_SIGNAL":
            print("❌ Audit stopped: Insufficient API quota or balance.")
        else:
            print("\n" + "="*60)
            print(f" OFFICIAL AUDIT REPORT: {target_cve} ")
            print("="*60)
            print(report)