import os

# 基础路径
BASE_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/PoCEmpirical/reproduce"
CODE_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/code"
OUTPUT_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset"
REPO_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/code/llmszz-replication-package1/result"
PATCH_INFO_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/patch_info"
BASIC_INFO_DIR = "/home/xinweimao/alv_evaluate/myResearch/workspace/dataset/basic_info"

# 数据与结果路径
LIBRARY_ROOT = os.path.join(BASE_DIR, "library")
EXPLOITS_ROOT = os.path.join(BASE_DIR, "exploits")
CVE_LIST_FILE = os.path.join(OUTPUT_DIR, "list/cve_list.json")
EXCEL_FILE = os.path.join(OUTPUT_DIR, "execution_result.xlsx")
DISCLOSED_VERSION_FILE = os.path.join(BASE_DIR, "disclosed-version.txt")
LLM_FILE = os.path.join(CODE_DIR, "llm.py")
UTILS_FILE = os.path.join(CODE_DIR, "utils.py")
AGENT_JAR = os.path.join(BASE_DIR, "assertion-agent/agent.jar")

# 新增：MVN 结果输出目录 修改
MVN_RESULT_DIR = os.path.join(OUTPUT_DIR, "mvn_test")
INFER_RESULT_DIR = os.path.join(OUTPUT_DIR, "result_diff")
RESULT_DIR = os.path.join(OUTPUT_DIR, "result")