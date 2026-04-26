#!/usr/bin/env python3
"""
漏洞引入commit推理脚本 - 简化版
直接使用git仓库和补丁文件信息，不依赖LLM
"""
import os
import sys
import json
import subprocess
from pathlib import Path

# 路径配置
CVE_LIST_FILE = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/list/cve_list.json"
PATCH_RESULTS_FILE = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/result/patch_only_results.json"
REPO_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/llmszz-replication-package1/result"
OUTPUT_FILE = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/result/intro_commits.json"

class IntroCommitFinder:
    def __init__(self):
        self.cve_list = json.load(open(CVE_LIST_FILE, 'r'))
        self.patch_results = json.load(open(PATCH_RESULTS_FILE, 'r'))
        self.results = {}
    
    def get_repo_path(self, owner, repo):
        """获取仓库路径"""
        repo_path = os.path.join(REPO_DIR, repo)
        return repo_path if os.path.exists(repo_path) else None
    
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
                print(f"    git命令失败: {result.stderr[:100]}")
                return []
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(' ', 1)
                    if len(parts) == 2:
                        commits.append({'hash': parts[0], 'message': parts[1]})
            return commits
        except Exception as e:
            print(f"    ⚠️  获取commits失败: {e}")
            return []
    
    def get_commit_files(self, repo_path, commit_hash):
        """获取commit修改的文件"""
        try:
            cmd = f'cd {repo_path} && git show --name-only --pretty=format: {commit_hash}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return []
            return [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
        except:
            return []
    
    def get_all_patch_files_for_cve(self, cve_id):
        """获取CVE的所有补丁文件（从所有版本对）"""
        all_patch_files = set()
        cve_id_upper = cve_id.upper()
        
        if cve_id_upper in self.patch_results:
            for entry in self.patch_results[cve_id_upper]:
                analysis = entry.get("analysis", {})
                for commit_hash, files_info in analysis.items():
                    all_patch_files.update(files_info.keys())
        
        return list(all_patch_files)
    
    def process_cve(self, cve_id):
        """处理单个CVE"""
        print(f"\n{cve_id}")
        
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
        
        # 获取所有补丁文件
        all_patch_files = self.get_all_patch_files_for_cve(cve_id)
        print(f"  总补丁文件: {len(all_patch_files)}")
        
        version_pairs = meta.get('version_pair', [])
        cve_results = []
        
        for vp in version_pairs:
            seek_patch = vp.get('seek_patch', True)
            
            # 只处理漏洞引入（seek_patch=false）
            if seek_patch:
                continue
            
            base_tag = vp.get('BASE_TAG', '')
            head_tag = vp.get('HEAD_TAG', '')
            
            # 跳过unknown版本
            if 'unknown' in base_tag.lower() or 'unknown' in head_tag.lower():
                continue
            
            print(f"  漏洞引入: {base_tag} -> {head_tag}")
            
            # 获取commits
            commits = self.get_commits_between_tags(repo_path, base_tag, head_tag)
            print(f"  Commits: {len(commits)}")
            
            if not commits:
                continue
            
            # 找修改了补丁文件的commits
            candidates = []
            for commit in commits:
                commit_hash = commit['hash']
                modified_files = self.get_commit_files(repo_path, commit_hash)
                
                # 检查是否修改了补丁文件
                patch_files_modified = [f for f in modified_files if f in all_patch_files]
                
                if patch_files_modified:
                    candidates.append({
                        'hash': commit_hash,
                        'message': commit['message'],
                        'modified_patch_files': patch_files_modified,
                        'confidence': 0.8
                    })
                    print(f"    ✓ {commit_hash[:8]}: {commit['message'][:50]}")
            
            cve_results.append({
                'base_tag': base_tag,
                'head_tag': head_tag,
                'seek_patch': seek_patch,
                'patch_files': all_patch_files,
                'total_commits': len(commits),
                'candidates': candidates
            })
        
        if cve_results:
            self.results[cve_id] = cve_results
    
    def run(self):
        """运行主流程"""
        print("🔍 漏洞引入commit推理")
        print("=" * 60)
        
        # 处理所有CVE
        cve_ids = list(self.cve_list.keys())
        
        for i, cve_id in enumerate(cve_ids, 1):
            if i % 10 == 0:
                print(f"\n进度: {i}/{len(cve_ids)}")
            try:
                self.process_cve(cve_id)
            except Exception as e:
                print(f"  ❌ 错误: {e}")
        
        # 保存结果
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n{'=' * 60}")
        print(f"✅ 完成！结果: {OUTPUT_FILE}")
        print(f"总CVE数: {len(cve_ids)}")
        print(f"找到结果: {len(self.results)}")

if __name__ == "__main__":
    finder = IntroCommitFinder()
    finder.run()
