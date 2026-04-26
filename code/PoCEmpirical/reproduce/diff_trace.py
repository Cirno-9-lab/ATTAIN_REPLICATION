import os
import json
import subprocess
import re
import sys
from concurrent.futures import ThreadPoolExecutor

# 1. 环境路径配置
CODE_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/code"
if CODE_DIR not in sys.path:
    sys.path.append(CODE_DIR)

# 2. 导入配置与工具
try:
    import settings
    from llm import Client
except ImportError as e:
    print(f"❌ 导入失败，请检查路径或文件名: {e}")
    sys.exit(1)

def fix_hardcoded_paths(demo_dir):
    """
    遍历 Java 源文件，将 Windows 硬编码路径替换为 Linux 环境下的 BASE_DIR。
    """
    target_path = settings.BASE_DIR 
    old_path = "G:/hard_fork/PoCEmpirical/reproduce"
    
    print(f"   🛠️  修复源码中的硬编码路径: {demo_dir}...")
    for root, dirs, files in os.walk(demo_dir):
        for file in files:
            if file.endswith(".java"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    if old_path in content:
                        new_content = content.replace(old_path, target_path)
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                except Exception as e:
                    print(f"     ⚠️  处理 {file} 报错: {e}")

def get_target_info(cve_id):
    """解析 GAV 信息和预期错误"""
    file_path = settings.DISCLOSED_VERSION_FILE
    if not os.path.exists(file_path):
        return None
    
    target = cve_id.strip()
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if target in line:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 4 and parts[1] == target:
                    gav = parts[0].split(':')
                    return {
                        "group_id": gav[0], 
                        "artifact_id": gav[1], 
                        "expected": parts[3]
                    }
    return None

class InstrumentedAnalyzer:
    def __init__(self):
        self.llm = Client()
        with open(settings.CVE_LIST_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            self.cve_data = json.load(f)

    def _run_test_with_agent(self, group_id, artifact_id, version, demo_dir):
        """执行带 Agent 的测试，通过 -DforkCount=0 解决 Corrupted STDOUT 问题"""
        fix_hardcoded_paths(demo_dir)
        pom_file = os.path.join(demo_dir, "pom.xml")
        
        # 1. 切换库版本
        update_cmd = f"mvn versions:use-dep-version -Dincludes={group_id}:{artifact_id} -DdepVersion={version} -f {pom_file}"
        subprocess.run(update_cmd, shell=True, capture_output=True)
        
        # 2. 准备 Agent 参数与稳定性参数
        agent_path = getattr(settings, 'AGENT_JAR', None)
        stability_args = (
            "-DforkCount=0 "              # 禁用 Fork 模式，解决流冲突
            "-DreuseForks=false "         # 不重用进程
            "-Dsurefire.useManifestOnlyJar=false" # 避免类路径过长
        )
        
        arg_line = ""
        if agent_path and os.path.exists(agent_path):
            # 将 Agent 加入 argLine
            arg_line = f'-DargLine="-javaagent:{agent_path}"'
            print(f"   💉 插桩就绪: {agent_path}")
        else:
            print("   ⚠️  未找到 Agent JAR，将进行原始测试。")

        # 3. 运行测试
        print(f"   🚀 运行插桩测试 (CVE-2023-39010 @ {version})...")
        test_cmd = f"mvn clean test -U {arg_line} {stability_args} -Dsurefire.trimStackTrace=false -f {pom_file}"
        res = subprocess.run(test_cmd, shell=True, capture_output=True, text=True, errors='replace')
        
        full_log = (res.stdout or "") + "\n" + (res.stderr or "")

        # --- 优先级提取 ---
        # A. 查找异常堆栈
        stack_pattern = r"([a-zA-Z0-9.]+(?:Exception|Error|AssertionError):.*?(?:\n\s+at .*?)+)"
        match = re.search(stack_pattern, full_log, re.DOTALL)
        if match:
            return match.group(1)

        # B. 查找 Agent 自定义输出标记（如果有）或测试结果区块
        if "T E S T S" in full_log:
            test_area = full_log.split("T E S T S")[-1]
            return f"INSTRUMENTED_OUTPUT:\n{test_area[:1500].strip()}"

        # C. 极端保底：如果是构建失败且没匹配到，返回末尾日志
        return "\n".join(full_log.splitlines()[-30:])

    def run_experiment(self, cve_id="CVE-2023-39010"):
        print(f"--- 实验开始: {cve_id} ---")
        
        info = self.cve_data.get(cve_id)
        meta = get_target_info(cve_id)
        if not info or not meta: return

        demo_base = os.path.join(settings.EXPLOITS_ROOT, cve_id)
        target_demo = next((os.path.join(demo_base, d) for d in os.listdir(demo_base) if d.startswith('demo')), None)
        if not target_demo: return

        final_results = []
        for pair in info.get("version_pair", []):
            v_ver = pair.get("appears")
            if not v_ver or v_ver == "unknown": continue
            
            trace = self._run_test_with_agent(meta['group_id'], meta['artifact_id'], v_ver, target_demo)

            # LLM 提取关键指纹
            prompt = (f"根据以下插桩日志分析漏洞 {cve_id} 的根因方法。\n"
                      f"日志内容:\n{trace[:1500]}\n"
                      f"预期错误: {meta['expected']}\n"
                      f"返回 5-8 个用于过滤 git diff 的技术关键词 (英文, 逗号隔开):")
            
            keywords_raw = self.llm.call_llm(prompt)
            keywords = [k.strip().replace('*', '').replace('`', '') for k in keywords_raw.split(',')]

            final_results.append({
                "appears": v_ver,
                "not appears": pair.get("not appears"),
                "trace_snippet": trace[:1200],
                "fingerprints": keywords
            })

        # 保存结果文件
        out_path = os.path.join(settings.MVN_RESULT_DIR, f"{cve_id}.json")
        os.makedirs(settings.MVN_RESULT_DIR, exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump({
                "cve": cve_id,
                "results": final_results,
                "meta": {"agent_enabled": True, "fork_disabled": True}
            }, f, indent=4, ensure_ascii=False)
        print(f"✅ 实验数据已存至: {out_path}")

if __name__ == "__main__":
    analyzer = InstrumentedAnalyzer()
    analyzer.run_experiment("CVE-2023-39010")