#!/usr/bin/env python3
"""
漏洞引入commit推理脚本
直接使用git仓库和补丁文件信息
"""
import os
import sys
import json
import subprocess
from pathlib import Path

# 添加settings路径
sys.path.insert(0, "/home/xinweimao/alv_evaluate/myResearch/workspace/code")
import settings
import llm

# 路径配置
CVE_LIST_FILE = settings.CVE_LIST_FILE
PATCH_RESULTS_FILE = os.path.join(settings.OUTPUT_DIR, "result/patch_only_results.json")
REPO_DIR = settings.REPO_DIR
OUTPUT_FILE = os.path.join(settings.OUTPUT_DIR, "result/intro_commits.json")

class IntroCommitFinder:
    def __init__(self):
        self.llm_client = llm.Client()
        self.cve_list = json.load(open(CVE_LIST_FILE, 'r'))
        self.patch_results = json.load(open(PATCH_RESULTS_FILE, 'r'))
        self.results = {}
    
    def get_repo_path(self, owner, repo):
        """获取仓库路径"""
        repo_path = os.path.join(REPO_DIR, repo)
        if os.path.exists(repo_path):
            return repo_path
        return None
    
    def get_patch_files(self, cve_id, base_tag, head_tag):
        """获取补丁文件列表"""
        patch_files = set()
        cve_id_upper = cve_id.upper()
        
        if cve_id_upper in self.patch_results:
            for entry in self.patch_results[cve_id_upper]:
                if entry.get("base_tag") == base_tag and entry.get("head_tag") == head_tag:
                    analysis = entry.get("analysis", {})
                    for commit_hash, files_info in analysis.items():
                        patch_files.update(files_info.keys())
        
        return list(patch_files)
    
    def get_commits_between_tags(self, repo_path, base_tag, head_tag):
        """获取两个tag之间的commits"""
        try:
            cmd = f'cd {repo_path} && git log --oneline {base_tag}..{head_tag}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return []
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(' ', 1)
                    if len(parts) == 2:
                        commits.append({
                            'hash': parts[0],
                            'message': parts[1]
                        })
            return commits
        except Exception as e:
            print(f"  ⚠️  获取commits失败: {e}")
            return []
    
    def get_commit_files(self, repo_path, commit_hash):
        """获取commit修改的文件"""
        try:
            cmd = f'cd {repo_path} && git show --name-only --pretty=format: {commit_hash}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return []
            
            files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
            return files
        except:
            return []
    
    def analyze_commit(self, cve_id, commit_hash, commit_msg, modified_files, patch_files, nvd_desc):
        """分析commit是否引入漏洞"""
        # 检查是否修改了补丁文件
        patch_files_modified = [f for f in modified_files if f in patch_files]
        
        if not patch_files_modified:
            return None
        
        # 使用LLM分析
        prompt = f"""
Analyze if this commit introduced the vulnerability.

CVE: {cve_id}
Vulnerability: {nvd_desc}
Commit: {commit_hash}
Message: {commit_msg}
Modified Files: {', '.join(patch_files_modified)}

Task: Did this commit introduce the vulnerability?
Return JSON:
{{
    "introduced": true/false,
    "confidence": 0.0-1.0,
    "reason": "brief explanation"
}}
"""
        try:
            response = self.llm_client.call_llm(prompt)
            # 简单解析
            introduced = "true" in response.lower()
            confidence = 0.7 if introduced else 0.3
            
            return {
                'hash': commit_hash,
                'message': commit_msg,
                'modified_patch_files': patch_files_modified,
                'introduced': introduced,
                'confidence': confidence,
                'llm_response': response
            }
        except Exception as e:
            print(f"  ⚠️  LLM分析失败: {e}")
            return None
    
    def process_cve(self, cve_id):
        """处理单个CVE"""
        print(f"\n处理 {cve_id}...")
        
        meta = self.cve_list.get(cve_id.upper(), {})
        if not meta:
            print(f"  ⚠️  未找到CVE信息")
            return
        
        owner = meta.get('OWNER', '')
        repo = meta.get('REPO', '')
        nvd_desc = meta.get('description', '')
        
        repo_path = self.get_repo_path(owner, repo)
        if not repo_path:
            print(f"  ⚠️  仓库不存在: {repo}")
            return
        
        print(f"  仓库: {owner}/{repo}")
        
        version_pairs = meta.get('version_pair', [])
        cve_results = []
        
        for vp in version_pairs:
            seek_patch = vp.get('seek_patch', True)
            
            # 只处理漏洞引入（seek_patch=false）
            if seek_patch:
                continue
            
            base_tag = vp.get('BASE_TAG', '')
            head_tag = vp.get('HEAD_TAG', '')
            
            print(f"  版本对: {base_tag} -> {head_tag} (漏洞引入)")
            
            # 获取补丁文件
            patch_files = self.get_patch_files(cve_id, base_tag, head_tag)
            print(f"  补丁文件数: {len(patch_files)}")
            
            if not patch_files:
                print(f"  ⚠️  无补丁文件信息")
                continue
            
            # 获取commits
            commits = self.get_commits_between_tags(repo_path, base_tag, head_tag)
            print(f"  commits数: {len(commits)}")
            
            if not commits:
                continue
            
            # 分析每个commit
            candidates = []
            for commit in commits:
                commit_hash = commit['hash']
                modified_files = self.get_commit_files(repo_path, commit_hash)
                
                analysis = self.analyze_commit(
                    cve_id, commit_hash, commit['message'],
                    modified_files, patch_files, nvd_desc
                )
                
                if analysis and analysis['introduced']:
                    candidates.append(analysis)
                    print(f"    ✓ 候选: {commit_hash[:8]} (置信度: {analysis['confidence']})")
            
            cve_results.append({
                'base_tag': base_tag,
                'head_tag': head_tag,
                'seek_patch': seek_patch,
                'patch_files': patch_files,
                'candidates': candidates
            })
        
        if cve_results:
            self.results[cve_id] = cve_results
    
    def run(self):
        """运行主流程"""
        print("🔍 漏洞引入commit推理")
        print("=" * 60)
        
        # 只处理前10个CVE作为测试
        cve_ids = list(self.cve_list.keys())[:10]
        
        for cve_id in cve_ids:
            try:
                self.process_cve(cve_id)
            except Exception as e:
                print(f"  ❌ 处理失败: {e}")
        
        # 保存结果
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ 完成！结果保存到: {OUTPUT_FILE}")
        print(f"处理CVE数: {len(cve_ids)}, 找到结果数: {len(self.results)}")

if __name__ == "__main__":
    finder = IntroCommitFinder()
    finder.run()
