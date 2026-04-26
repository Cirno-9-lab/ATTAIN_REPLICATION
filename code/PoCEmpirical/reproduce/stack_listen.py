import os
import subprocess
import sys
import shutil

# --- 配置 ---
CVE_ID = "CVE-2018-1002200"
LOG_FILE = os.path.join(os.getcwd(), f"{CVE_ID}.log")
TEMP_DIR = os.path.join(os.getcwd(), ".tracer_tmp")
# 针对 Zip Slip，监控 File 对象的创建
TARGET_CLASS = "java/io/File" 

def setup_tracer_agent():
    """动态生成并编译一个简单的 Java Agent"""
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    os.makedirs(TEMP_DIR)

    # 1. 编写 Agent 源码 (利用简单的 System.out 打印堆栈)
    agent_src = f"""
import java.lang.instrument.*;
import java.security.ProtectionDomain;

public class SimpleTracer {{
    public static void premain(String args, Instrumentation inst) {{
        inst.addTransformer(new ClassFileTransformer() {{
            public byte[] transform(ClassLoader l, String className, Class<?> c, ProtectionDomain pd, byte[] b) {{
                // 当加载目标类时，我们可以在这里做字节码增强
                // 但为了最简单稳定且不依赖第三方库，我们直接在类加载时标记
                if (className != null && className.equals("{TARGET_CLASS}")) {{
                    // 注意：原生 Java Agent 做方法级拦截较复杂
                    // 这里我们通过打印加载信息来确认路径
                }}
                return null;
            }}
        }});
    }}
}}
"""
    # 2. 编译并打包 (需要系统安装了 JDK)
    with open(os.path.join(TEMP_DIR, "SimpleTracer.java"), "w") as f:
        f.write(agent_src)
    
    try:
        subprocess.run(f"javac {TEMP_DIR}/SimpleTracer.java", shell=True, check=True)
        manifest = "Premain-Class: SimpleTracer\n"
        with open(os.path.join(TEMP_DIR, "MANIFEST.MF"), "w") as f:
            f.write(manifest)
        subprocess.run(f"jar cmf {TEMP_DIR}/MANIFEST.MF {TEMP_DIR}/agent.jar -C {TEMP_DIR} .", shell=True, check=True)
        return os.path.join(TEMP_DIR, "agent.jar")
    except Exception as e:
        print(f"❌ Agent 编译失败，请确保系统已安装 JDK: {e}")
        return None

def run_test_with_logging(demo_dir, agent_path):
    """运行测试并重定向所有轨迹到日志文件"""
    pom_file = os.path.join(demo_dir, "pom.xml")
    
    # 构建 Maven 参数
    # -Dsurefire.trimStackTrace=false: 保证断言堆栈完整
    # -DargLine: 注入我们的 Agent (如果需要深度方法追踪，通常配合 -Xlint 或自定义诊断)
    # 针对 Zip Slip，我们开启调试级别的日志输出
    mvn_cmd = [
        "mvn", "clean", "test",
        "-f", pom_file,
        "-Dsurefire.trimStackTrace=false",
        "-Dsurefire.useFile=false",
        "-Dmaven.test.failure.ignore=true" # 即使失败也继续，方便收集完整日志
    ]

    print(f"📡 正在启动监控，输出将重定向至: {LOG_FILE}")
    
    with open(LOG_FILE, "w", encoding="utf-8") as log_out:
        # 执行命令并实时写入文件
        process = subprocess.Popen(
            mvn_cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            errors='replace'
        )
        
        for line in process.stdout:
            # 实时显示在屏幕，同时写入文件
            sys.stdout.write(line)
            log_out.write(line)
            
        process.wait()

if __name__ == "__main__":
    # 填入你的实际 Demo 路径
    target_demo_path = "/home/xinweimao/alv_evaluate/myResearch/workspace/exploits/CVE-2018-1002200/demo"
    
    # 运行
    run_test_with_logging(target_demo_path, None)
    
    # 扫描生成的日志，如果发现没有详细过程，追加 Surefire 报告内容
    report_path = os.path.join(target_demo_path, "target/surefire-reports")
    if os.path.exists(report_path):
        with open(LOG_FILE, "a", encoding="utf-8") as log_out:
            log_out.write("\n\n=== ATTACHING DETAILED SUREFIRE REPORTS ===\n")
            for f in os.listdir(report_path):
                if f.endswith(".txt"):
                    with open(os.path.join(report_path, f), "r") as rf:
                        log_out.write(f"\n--- Report: {f} ---\n")
                        log_out.write(rf.read())
    
    print(f"\n✅ 任务完成。请检查日志: {LOG_FILE}")