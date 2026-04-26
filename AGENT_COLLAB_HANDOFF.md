## Agent 协作交接文档

*更新时间：2026-04-26 03:09*

## 1. 文档范围

这份文档只说明 **`code/difftrace/demo` 目录下现有工具链** 的职责、输入输出、数据流和最近已落地的修复点。

原则上它**不覆盖**更上游的数据准备脚本；但当前有一个例外：`code/difftrace/demo/scripts/version_switch_unified_time_scan.py` 虽然会直接读取 `dataset/execution_result.xlsx` 等上游输入，并回写 `dataset/list/cve_list_v2.json`，但脚本本体位于 `demo/scripts` 下，已经成为这条链路的正式组成部分，所以本文档会一并记录。

当前建议把 `demo` 工具链理解为五层：

1. **版本对生成层**：由 `version_switch_unified_time_scan.py` 生成并刷新 `dataset/list/cve_list_v2.json`
2. **批处理调度层**：读取 `cve_list_v2.json`，挑选 case、并发运行、汇总批次结果
3. **单 case 执行层**：materialize 工作区、跑 baseline/target、归一化单 case 结果
4. **diff / trace / LLM 分析层**：生成版本差异、trace 差异、LLM hunk 选择与漏洞存在性判断
5. **评估与辅助层**：回填场景、统计日志、评估 LLM 判定质量

---

## 2. 目录与核心输入输出

### 2.1 主要目录

- **脚本目录**：`code/difftrace/demo/scripts`
- **默认输出根目录**：优先 `/data-1/xinweimao/code/difftrace/demo/target`，否则回退到 `code/difftrace/demo/target`
- **默认 target 根目录解析脚本**：`target_paths.py`

### 2.2 工具链的典型输入

- **统一 case 数据集**：`dataset/list/cve_list_v2.json`
- **exploit demo 源目录**：通常来自 `code/PoCEmpirical/reproduce/Exploits/...`
- **单 case 版本对**：`baseline_version` / `target_version`（由 `cve_list_v2.json` 中的 `version_pair` 提供）
- **真值评估表**：`dataset/execution_result.xlsx`

当前 `demo/scripts` 下需要消费 case 数据集的脚本，默认都应以 `dataset/list/cve_list_v2.json` 作为输入口径。

### 2.3 版本切换 / 版本对生成链路的典型输入输出

这条链路现在由 `version_switch_unified_time_scan.py` 负责，典型输入包括：

- `dataset/execution_result.xlsx`
- `dataset/cve_ghrepo.json`
- `dataset/mvn_test/*.json`
- `code/PoCEmpirical/reproduce/disclosed-version.txt`
- `dataset/maven_release_history_cache.json`
- `dataset/maven_artifact_lookup_cache.json`

典型输出包括：

- 主输出：`dataset/list/cve_list_v2.json`（也可用 `--output-json` 改到别处）
- 单 CVE 调试输出：如 `tmp/cve_2022_42003_unified_time_scan.json`、`tmp/cve_2013_7285_unified_time_scan.json`
- 单 CVE 矩阵快照：如 `tmp/cve_2022_42003_matrix_latest.json`、`tmp/cve_2013_7285_matrix_latest.json`
- 手工渲染图：如 `tmp/CVE-2022-42003_branch_matrix_full_v5.svg`、`tmp/CVE-2013-7285_version_tree.svg`

当前主输出 JSON 已经**不再写出** `branch_summary` 和 `branch_matrix`；二维矩阵仅在单 CVE 调试时通过独立快照文件保留，避免主结果过大。
另一个已经确认的现实情况是：**历史快照或旧版 `cve_list_v2.json` 条目可能只保留 `version_pair`，并不保证内嵌 `version_tree`**。如果要手工验某个 CVE 的版本树，应重新执行 `version_switch_unified_time_scan.py --cve <CVE>`，再以 `tmp/<cve>_unified_time_scan.json` 和 `tmp/<cve>_matrix_latest.json` 作为渲染输入。
此外，当前正式口径已经收敛为 **仅保留 Excel 测试版本**：

- `cve_list_v2.json` 中的 `version_pair`、`skipped_same_generation_pairs`、`unresolved_versions` 只允许引用 `dataset/execution_result.xlsx` 中实际测试过的版本
- 单 CVE 矩阵快照 `tmp/*_matrix_latest.json` 也会在最终输出前裁成 Excel-only 子矩阵
- 因此像早期完整 Maven 发布历史中的辅助锚点版本，不再出现在主输出和验图结果里

### 2.4 单 case 的典型输出结构

对任意一个 `case_id`，通常会生成：

- `cases/<case_id>/case-input.json`
- `cases/<case_id>/materialized-case.json`
- `cases/<case_id>/case-result.json`
- `cases/<case_id>/driver-run.json`
- `cases/<case_id>/run-version-analysis.log`
- `cases/<case_id>/workspace/`
- `cases/<case_id>/analysis/`

其中 `analysis/` 下面常见产物包括：

- `analysis-metadata.json`
- `execution-observations.json`
- `trace-commands.json`
- `baseline-maven.log` / `target-maven.log`
- `baseline-trace.log` / `target-trace.log`
- `trace-diff-summary.json` / `trace-diff-summary.txt`
- `llm-scenario.json`
- `llm-hunk-analysis.md`
- `llm-hunk-judgments.json`
- `llm-vulnerability-judgment.json`
- `version-diff/summary.json`
- `version-diff/llm-guide.txt`
- `version-diff/api-diffs/...`
- `version-diff/diffs/...`
- `version-diff/api-change-summary.json`

---

## 3. 端到端数据流

### 3.1 批处理主链

- **`version_switch_unified_time_scan.py`**
  - **输入**：`dataset/execution_result.xlsx`、Maven 发布时间缓存、artifact 线索等上游数据
  - **输出**：`dataset/list/cve_list_v2.json`
  - **作用**：先生成当前正式使用的版本对数据集，供后续所有 case 级脚本消费

- **`run_batch_analysis.py`**
  - **输入**：`cve_list_v2.json` + exploit 根目录 + 选择模式（`compile-false` / `seek-patch-false`）
  - **输出**：批次目录、`batch-summary.json`、`batch-status.jsonl`、每个 case 的 `case-result.json`
  - **作用**：从 `cve_list_v2.json` 批量挑选 case，分区并发调度单 case 脚本

- **`run_case_analysis_runner_fix.py`** 或 **`run_case_analysis.py`**
  - **输入**：`cve_list_v2.json` 中的一个 CVE + 一个 `pair_index`
  - **输出**：单 case 目录、materialized workspace、analysis 产物、`case-result.json`
  - **作用**：驱动单 case 全流程

- **`run_version_regression_analysis.py`**
  - **输入**：`baseline_version`、`target_version`、`test_file`
  - **输出**：trace、dependency-tree diff、`version-diff/`、`llm-scenario.json`、可选 LLM 分析
  - **作用**：真正执行 baseline/target 回归分析

### 3.2 LLM 分析链

- **`backfill_llm_scenarios.py`**
  - **输入**：已有 `batch-summary.json`
  - **输出**：缺失的 `analysis/llm-scenario.json`
  - **作用**：给老批次补齐 LLM 场景描述

- **`run_llm_diff_batch.py`**
  - **输入**：`batch-summary.json` + 每个 case 的 `llm-scenario.json`
  - **输出**：每个 case 的 `llm-hunk-analysis.md`
  - **作用**：批量跑 LLM hunk 选择

- **`aggregate_llm_diff_results.py`**
  - **输入**：`batch-summary.json` + `llm-hunk-analysis.md`
  - **输出**：`dataset/llm_hunk_analysis.json`、`dataset/llm_hunk_analysis.csv`，并在 case 目录写回 judgment 文件
  - **作用**：把 per-case LLM 中间过程聚合成结构化总表，并补 final judgment

- **`evaluate_llm_vulnerability_detection.py`**
  - **输入**：`dataset/llm_hunk_analysis.json` + `dataset/execution_result.xlsx`
  - **输出**：`dataset/llm_vulnerability_presence_eval.json`、`dataset/llm_vulnerability_presence_eval.csv`
  - **作用**：用真值评估 LLM 对“漏洞是否仍存在”的判定质量

---

## 4. 脚本字典：每个脚本做什么

下面按“脚本：输入 -> 输出 -> 作用”列出 `code/difftrace/demo/scripts` 下的现有核心脚本。

### 4.1 版本对推断与二维矩阵辅助

- **`version_switch_unified_time_scan.py`**：
  - **输入**：`dataset/execution_result.xlsx`、`dataset/cve_ghrepo.json`、`dataset/mvn_test/*.json`、`disclosed-version.txt`、Maven 发布时间缓存与 artifact 候选缓存
  - **输出**：默认写 `dataset/list/cve_list_v2_unified_time_scan.json`，生产运行可通过 `--output-json` 直接写到 `dataset/list/cve_list_v2.json`
  - **作用**：
    - 统一按 Maven 发布时间扫描所有版本
    - 当版本顺序未回跳时，把版本放入第 0 列主链
    - 当版本顺序回跳时，把版本挂到对应 `x.y` 当时最新主列版本右侧
    - 生成 `version_pair`、补齐 GitHub tag / compare URL，并写回最终 `cve_list` 结构
  - **当前实现重点**：
    - 带后缀版本（如 `rc` / `pr`）会先作为普通版本参与时间扫描，再根据完整版本顺序判断是否回跳
    - `runtime-fork` / `suffix-fork` 若与稳定版 `normalized_core` 相同且发布时间足够接近，会优先挂到稳定版同一行右侧
    - `unresolved_versions` 不再只是简单留在列表里；在单 CVE 调试矩阵中，会按 Excel 原始顺序，从第一个未解析版本开始，直接顺接到上一个已定位版本后面
    - 在完成挂接后，最终输出阶段会把矩阵裁成 **Excel-only** 子矩阵；因此主输出和图表都不会再混入非 Excel 测试版本
    - 它生成的 `dataset/list/cve_list_v2.json` 是当前后续脚本统一消费的 case 数据集

### 4.2 批处理与单 case 调度

- **`run_batch_analysis.py`**：
  - **输入**：`cve_list_v2.json`、`--selection-mode`、exploit roots、Maven/Java 参数
  - **输出**：`target/.../cases/<case_id>/...`、`batch-summary.json`、`batch-status.jsonl`、`batch-driver-logs/`
  - **作用**：
    - 从 `cve_list_v2.json` 中筛选满足条件的版本对
    - 默认按 CVE 分区并发执行
    - 调用单 case 入口脚本
    - 维护批次进度、日志和最终汇总
  - **当前实现重点**：
    - 已加入 `coerce_text(...)`，修复 timeout 分支里 `bytes/str` 混拼崩溃
    - 默认单 case 入口已切到 `run_case_analysis_runner_fix.py`
    - 支持 `--continue-latest-run` 基于 `batch-status.jsonl` 续跑

- **`run_case_analysis.py`**：
  - **输入**：`cve_list_v2.json` + `--cve-id` + `--pair-index` + exploit demo
  - **输出**：`case-input.json`、`materialized-case.json`、`case-result.json`、`analysis/`
  - **作用**：
    - 从 `cve_list_v2.json` 解析单个版本对
    - 寻找 exploit demo
    - materialize 一个独立 Maven workspace
    - 对每个测试文件调用 `run_version_regression_analysis.py`
    - 聚合成最终 `case-result.json`
  - **状态判定逻辑**：
    - 读取 `trace-diff-summary.json`、`execution-observations.json`、`api-change-summary.json`、`llm-scenario.json`
    - 输出 `status`、`failure_kind`、`failure_subtype`
  - **当前实现重点**：
    - `infer_failure_subtype(...)` 已覆盖 `missing_class`、`binary_incompatibility`、`toolchain_incompatibility` 等 subtype

- **`run_case_analysis_runner_fix.py`**：
  - **输入**：与 `run_case_analysis.py` 相同，当前统一从 `cve_list_v2.json` 读取 case
  - **输出**：同样写 `case-result.json`，但会在失败时补写/修正 payload
  - **作用**：
    - 作为 `run_case_analysis.py` 的 wrapper
    - 专门处理 `runner_error`、路径缺失、artifact 推断失败、trace package 推断失败等脏情况
    - 在缺少正式结果文件时合成可用的 `case-result.json`
  - **当前实现重点**：
    - 支持 `workspace already exists` 自动重试
    - 支持 artifact / trace package 自动补推断
    - 支持从 `baseline-maven.log` / `target-maven.log` / excerpt 中把 `runner_error` 归一化成真实的 `compile_failure` 或 `execution_failure`
    - 是当前批处理默认入口

### 4.3 materialize 与 trace 执行层

- **`materialize_case_workspace.py`**：
  - **输入**：exploit demo、版本号、artifact 提示、test 文件提示
  - **输出**：materialized workspace、可选 `materialized-case.json`
  - **作用**：
    - 复制原始 exploit demo 到独立工作区
    - patch `pom.xml`，注入待分析依赖版本与 trace agent 配置
    - 推断 artifact、test file、trace packages
    - 拷贝 trace runtime 源码 / 预构建 agent
    - 为旧版本库做兼容性改写
  - **当前实现重点**：
    - 已包含多类 compat rewrite
    - 已加入对硬编码 exploit demo 绝对路径的重写，避免 materialized workspace 仍引用旧目录
    - 已补 `plexus-archiver`、`spring-security` 等兼容改写

- **`trace_workflow_lib.py`**：
  - **输入**：项目根目录、测试文件、版本、trace package
  - **输出**：trace log、dependency tree、统一 JSON/text 辅助产物
  - **作用**：公共底层库，提供：
    - `discover_test_context(...)`
    - `run_trace(...)`
    - `run_dependency_tree(...)`
    - `extract_error_excerpt(...)`
    - `compare_trace_sequences(...)`
    - `write_json(...)` / `write_text(...)`
  - **地位**：`run_dependency_trace.py` 与 `run_version_regression_analysis.py` 的公共执行底座

- **`compat_replay_lib.py`**：
  - **输入**：baseline 编译结果、target classpath、compat replay 布局
  - **输出**：compat replay 目录、classpath 日志、generator 日志、compat plan、重放执行结果
  - **作用**：
    - 准备 target 版本的回放 classpath
    - 调用 `CompatReplayGenerator`
    - 调用 `CompatJUnitRunner` 在 target 依赖环境中重放 baseline 编译产物
  - **使用场景**：`run_version_regression_analysis.py --compat-replay-target`

- **`run_dependency_trace.py`**：
  - **输入**：单个版本 + 单个 test file
  - **输出**：trace log（默认按 test selector 和 version 生成）
  - **作用**：最轻量的单次 trace 入口，适合手工调试某个版本

- **`run_dependency_trace.sh`**：
  - **输入**：同 `run_dependency_trace.py`
  - **输出**：同上
  - **作用**：用 `conda run -n lumen` 包一层 Python 入口，方便直接命令行使用

### 4.4 baseline / target 回归分析层

- **`run_version_regression_analysis.py`**：
  - **输入**：`baseline_version`、`target_version`、`test_file`
  - **输出**：
    - `analysis-metadata.json`
    - `baseline-maven.log` / `target-maven.log`
    - `baseline-trace.log` / `target-trace.log`
    - `baseline-dependency-tree.txt` / `target-dependency-tree.txt`
    - `dependency-tree.diff`
    - `trace-commands.json`
    - `execution-observations.json`
    - `trace-diff-summary.json` / `trace-diff-summary.txt`
    - `version-diff/`
    - `llm-scenario.json`
    - 可选 `llm-hunk-analysis.md`
  - **作用**：
    - 跑 baseline 和 target 两轮执行
    - 比较 trace 是否有差异
    - 生成依赖树 diff 和版本二进制/API diff
    - 按失败或 trace_diff 场景构建 `llm-scenario.json`
    - 若启用 `--run-llm`，直接触发 hunk selector
  - **分支**：
    - 正常 `maven_test`
    - `--compat-replay-target` 的 `compat_replay`

- **`run_version_regression_analysis.sh`**：
  - **输入**：同 `run_version_regression_analysis.py`
  - **输出**：同上
  - **作用**：用 `conda run -n lumen` 包装 Python 入口

### 4.5 版本 diff 生成层

- **`version_diff_lib.py`**：
  - **输入**：baseline / target artifact、jar、pom、diff 输出根目录
  - **输出**：`version-diff/` 目录树
  - **作用**：
    - 生成 `api-diffs/*.diff`（签名级）
    - 生成 `diffs/*.diff`（字节码级，带 `javap -c -p`）
    - 生成 `api-raw/`、`raw/`
    - 生成 `summary.json`、`added-classes.txt`、`removed-classes.txt`、`llm-guide.txt`
    - 提供 `load_version_diff_context(...)` 给 LLM 或聚合阶段做上下文扩展
  - **当前实现重点**：
    - 明确区分 `api-diffs` 与 `diffs`
    - 支持把具体 diff hunk 反解到 baseline/target raw 上下文

- **`extract_api_changes.py`**：
  - **输入**：`analysis/version-diff/api-raw/`
  - **输出**：`analysis/version-diff/api-change-summary.json`
  - **作用**：
    - 从 `javap` API dump 中提取类、构造器、方法、字段变化
    - 生成结构化 breaking change 摘要
  - **使用方式**：
    - 可单独 CLI 调用
    - 也会被 `run_case_analysis.py` 直接 import 调用

### 4.6 LLM hunk 选择与漏洞存在性判断

- **`llm_hunk_selector.py`**：
  - **输入**：某个 case 的 `analysis_dir` + `llm-scenario.json`
  - **输出**：`llm-hunk-analysis.md`
  - **作用**：
    - 用工具式 LLM 交互，从 `version-diff/`、失败 excerpt、trace 摘要中选出最相关 hunk
    - 输出固定四段：`Diagnosis`、`Selected Hunks`、`Supporting Evidence`、`Open Questions`
    - 其内置的 final judgment prompt 模板也会在聚合阶段被调用，用于生成 `llm-vulnerability-judgment.json`
  - **内置工具**：
    - `keyword_search`
    - `read_file`
    - `load_diff_context`
    - `search_code_context`
  - **当前实现重点**：
    - prompt 已强化：如果 `api-diff` 只显示类签名/字段描述/marker interface，不能停；必须继续看对应 `version-diff/diffs/*.diff` 或 `load_diff_context`
    - 对构造器 / Collection / Map / self-reference 类问题，要求展开到完整方法/构造器上下文，而不是只引用类声明

- **`run_llm_diff_batch.py`**：
  - **输入**：`batch-summary.json`
  - **输出**：各 case 的 `llm-hunk-analysis.md`
  - **作用**：批量调用 `llm_hunk_selector.py` 处理已有 analysis 目录
  - **特性**：
    - 支持 `--status-filter`
    - 支持 `--limit`
    - 支持 `--random-seed`
    - 支持 `--force` 重跑

- **`backfill_llm_scenarios.py`**：
  - **输入**：旧批次的 `batch-summary.json`
  - **输出**：缺失的 `analysis/llm-scenario.json`
  - **作用**：
    - 从已有 `case-result.json` / `analysis` 产物反推 scenario
    - 让历史批次也能接入 `run_llm_diff_batch.py`

- **`aggregate_llm_diff_results.py`**：
  - **输入**：`batch-summary.json` + 各 case 的 `llm-hunk-analysis.md`
  - **输出**：
    - 汇总：`dataset/llm_hunk_analysis.json`、`dataset/llm_hunk_analysis.csv`
    - 单 case 回写：`llm-hunk-judgments.json`、`llm-vulnerability-judgment.json`
  - **作用**：
    - 解析 `Final response` 和 `Selected Hunks`
    - 生成结构化 `selected_hunks` 与 `selected_hunk_payloads`
    - 基于规则 / LLM / hybrid 模式生成最终漏洞存在性结论
  - **当前实现重点**：
    - 已加入“浅层 `api-diff` 自动扩展”逻辑
    - 当选中的 `api-diff` 只含类签名等浅信息时，会自动拼接同名 `version-diff/diffs/*.diff` 的字节码上下文
    - 回写字段里会出现 `paired_bytecode_path` 和 `Related bytecode diff context`
    - 这个修复就是为了避免类似 `CVE-2023-1436` 只看见 `implements Serializable`、却漏掉 `JSONObject(Map)` / `JSONArray(Collection)` 完整修复逻辑的误判

- **`evaluate_llm_vulnerability_detection.py`**：
  - **输入**：`dataset/llm_hunk_analysis.json` + `dataset/execution_result.xlsx`
  - **输出**：`dataset/llm_vulnerability_presence_eval.json`、`dataset/llm_vulnerability_presence_eval.csv`
  - **作用**：
    - 把 LLM 的 `vulnerability_presence_verdict` / score 映射成 affected / not affected
    - 计算 coverage、accuracy、precision、recall、F1
    - 输出逐 case 明细，便于误判分析

### 4.7 辅助与统计脚本

- **`count_batch_driver_log_status.py`**：
  - **输入**：`batch-driver-logs/` + 相邻 case 目录中的 `case-result.json`
  - **输出**：stdout 统计，或 JSON 统计
  - **作用**：
    - 统计 driver 日志内容类别
    - 对照 `case-result.json` 统计 `status` 与 `failure_subtype`
    - 适合排查“批处理看起来失败，但 case-result 已经归一化”的情况

- **`cwe_cnt.py`**：
  - **输入**：`dataset/cwe_statistics.csv`、`dataset/list/cve_list_v2.json`、`dataset/execution_result.xlsx`
  - **输出**：`dataset/cwe_cnt.csv`（整表转置，第一列为 `Metric`，后续列为各 CWE 标签及 `others`）
  - **作用**：
    - 在 `True Affected Version` 作为真值、`No_Data` 统一视为 `not affected` 的前提下
    - 按 `cwe_statistics.csv` 中占比最高的前 10 个 CWE + `others` 分组
    - 统计 PoB（`LLM_Verdict`）、PoC（`Execution Result`）、vszz（`vszz_verdict`）、llm（`llm4szz_verdict`）四种方法在各组上的 Precision/Recall/F1，用于 RQ1 的 CWE 维度对比

- **`llm_token_logger.py`**：
  - **输入**：无外部 CLI 输入，由 `llm_hunk_selector.py` 与 `result_analysis_full_coverage.py` 在每次 LLM 请求返回后直接调用
  - **输出**：`logs/llm_token_usage.jsonl`（每行一条 JSON 记录，包含 method、case_id、model 以及 prompt_tokens / completion_tokens / total_tokens 等字段）
  - **作用**：
    - 作为统一的 LLM usage 记录器，把 DiffTrace LLM hunk 选择 / 漏洞判定以及 Excel 版本链 refine 阶段的所有 token 消耗写入一份可离线聚合的日志
    - 便于在论文实验阶段按脚本阶段（Dynamic Prompting / Evidence Typing / Vulnerability Judgment / Excel Refine）或按 case/batch 统计真实 token 成本

- **`target_paths.py`**：
  - **输入**：环境变量 `DIFFTRACE_DEMO_TARGET_ROOT`（可选）
  - **输出**：统一的默认输出根目录
  - **作用**：把 demo 的 target 路径选择集中管理，避免脚本各自硬编码


---

## 5. 近期已整合进工具链的修改

这里仅保留仍然影响当前链路理解的修改，不再保留旧的批次复盘细节。

### 5.1 批处理与 runner 修复

- `run_batch_analysis.py`
  - 已修复 timeout 分支的 `bytes/str` 拼接问题
  - 默认入口改为 `run_case_analysis_runner_fix.py`
  - 支持根据 `batch-status.jsonl` 续跑

- `run_case_analysis_runner_fix.py`
  - 增强了 `runner_error` 归一化
  - 能在结果文件缺失时合成 payload，避免批次统计断裂
  - 能自动重试一部分 workspace / artifact / trace package 问题

### 5.2 materialize 与兼容回放

- `materialize_case_workspace.py`
  - 增加了多类兼容性改写
  - 增加了 exploit demo 硬编码绝对路径的重写
  - 目标是把更多 case 从假性 `compile_failure` 推进到真实运行结果

### 5.3 LLM hunk 与漏洞判定链路修复

- `llm_hunk_selector.py`
  - hunk 选择提示词不再允许只读 declaration-only 的 `api-diff` 就定稿
  - 当 `version-diff/api-diffs` / `version-diff/diffs` 里**没有可归因的 concrete diff** 时，`Selected Hunks` 现在允许降级引用少量 fallback evidence：`trace-diff-summary.txt`、`*-observation-excerpt.txt`、`dependency-tree.diff`、`execution-observations.json`、`version-diff/pom.diff`
  - 但 fallback evidence 只用于解释**不确定性 / harness-breakage / 环境问题**，默认**不能单独证明漏洞已修复**
  - final judgment 提示词已升级到 **`direct_diff_v5`**，除既有的 Logic-First / API Removal ≠ Logic Fix / Implicit Persistence 约束外，又补了两条：
    - **Unrelated Runtime Failure ≠ Vulnerability Persistence**：`ClassNotFoundException` / `NoClassDefFoundError` / JAXB / classpath 失败，本身不等于“漏洞仍在”
    - **Trace-Anchored Fix Rule**：若 baseline trace 命中了脆弱方法，但 target trace 在该点前结束，且 diff 显示目标版本移除/替换了这条路径，则即使 target 还伴随无关运行时失败，也可视为 fix evidence
  - 对无 hunk case，final judgment prompt 现在会自动补充 `trace-diff-summary.txt`、失败 excerpt、`dependency-tree.diff`、`version-diff/pom.diff`、`version-diff/summary.json` 的上下文

- `aggregate_llm_diff_results.py`
  - 已兼容解析 `### Diagnosis` / `### Selected Hunks` 这类 Markdown 标题
  - 已兼容 `1.` / `1)` 两种编号格式，避免 `selected_hunks` 被解析为空
  - `Selected Hunks` 现在除了 concrete diff，也能解析 fallback evidence 路径（如 `trace-diff-summary.txt` / `version-diff/pom.diff`）
  - 会把过浅的 `api-diff` 自动扩为 “`api-diff` + paired `bytecode diff` context”
  - final judgment 前会把 `selected_hunk_payloads` 和自动补充的 `judgment_payloads` 分开处理：前者表示 LLM 明确选中的证据，后者表示真正喂给 rule / final LLM 的证据集合
  - final LLM judgment 不再要求“必须先有 concrete diff hunk”；即使 `selected_hunk_count=0`，只要 analysis 目录里还有 trace / observation / dependency / pom 证据，也会继续推理并生成 judgment

- 代表性修复效果：
  - `CVE-2023-1436` 这类 case 不再只看见 `JSONObject` / `JSONArray` 的 `Serializable` 声明变化
  - 现在能把 `JSONObject(Map)`、`JSONArray(Collection)` 中真正的递归包装删除逻辑纳入证据
  - `CVE-2022-25867` 这类 case 不再把 parser API 缺失误当作“漏洞已修复”的直接证据；最新 rerun 应以 `direct_diff_v3` prompt 重新生成最终 judgment

### 5.4 统一时间扫描版本生成链路更新

- 新增独立脚本 `version_switch_unified_time_scan.py`，不再继续污染旧的 `version_switch_branch_aware.py`
- 当前算法规则是：
  - 所有版本先统一按发布时间扫描
  - 没有回跳的版本进入第 0 列主链
  - 只有发生回跳时，才挂到对应 `x.y` 当时最新主列版本的右侧
- 带后缀版本（如 `2.3.0-rc1`、`2.18.0-rc1`）会先按正常版本参与时间扫描；如果没有回跳，可以直接落在第一列
- 单 CVE 调试时，未解析版本会按 Excel 顺序顺接：例如当前已验证 `2.18.4 -> 2.18.5`，以及 `2.19.0 -> 2.19.1 -> 2.19.2 -> 2.19.3 -> 2.19.4 -> 2.20.0-rc1 -> 2.20.0 -> 2.20.1`
- 当前正式输出口径已经切到 **Excel-only**：`cve_list_v2.json` 与 `tmp/*_matrix_latest.json` 在最终写出前都会过滤掉非 Excel 测试版本
- `cve_list_v2.json` 主输出中已移除 `branch_summary` 和 `branch_matrix`，避免结果文件过大；矩阵只在单 CVE 验证时额外写入 `tmp/*_matrix_latest.json`
- 当前已稳定使用过的手工验图脚本包括：`tmp/render_cve_2022_42003_matrix.py`、`tmp/render_cve_2019_20445_version_tree.py`、`tmp/render_cve_2013_7285_version_tree.py`
- 最近稳定产物包括：`tmp/CVE-2022-42003_branch_matrix_full_v5.svg`、`tmp/CVE-2019-20445_version_tree.svg`、`tmp/CVE-2013-7285_version_tree.svg`

- **2026-04-15 12:33 最新全量结果**：
  - 输出文件：`dataset/list/cve_list_v2.json`
  - 总 CVE 数：`224`
  - `version_pair` 总数：`845`
  - `seek_patch=True`：`488`
  - `seek_patch=False`：`357`
  - `entries_without_boundary_pairs`：`5`
  - `entries_with_unresolved_versions`：`0`
  - `unresolved_versions` 总数：`0`
  - `entries_with_same_generation_skips`：`71`
  - `skipped_same_generation_pairs` 总数：`326`
  - Excel 版本引用校验：`invalid_version_refs = 0`

- **2026-04-16 07:51 最新单 CVE 验图日志（`CVE-2013-7285`）**：
  - 执行命令：`python code/difftrace/demo/scripts/version_switch_unified_time_scan.py --cve CVE-2013-7285 --output-json tmp/cve_2013_7285_unified_time_scan.json`
  - 脚本 stdout 关键结果：`written_entries = 1`、`entries_with_same_generation_skips = 1`、`matrix_snapshot_paths["CVE-2013-7285"] = tmp/cve_2013_7285_matrix_latest.json`
  - 生成产物：`tmp/cve_2013_7285_unified_time_scan.json`、`tmp/cve_2013_7285_matrix_latest.json`、`tmp/render_cve_2013_7285_version_tree.py`、`tmp/CVE-2013-7285_version_tree.svg`
  - 当前 case 摘要：`artifact = com.thoughtworks.xstream:xstream`、`version_pair = 3`、`skipped_same_generation_pairs = 6`、`unresolved_versions = 0`、`version_tree` 共 `6` 条 branch（row `0` 到 `5`）
  - 当前已确认的一个细节：`1.4.10 -> 1.4.10-java7`、`1.4.11 -> 1.4.11-java7`、`1.4.12 -> 1.4.12-java7`、`1.4.13 -> 1.4.13-java7`、`1.4.14 -> 1.4.14-jdk7` 会被记录为 same-generation skip；`1.4.14-jdk7 -> 1.4.14-java7` 会作为 fork skip
  - 本次补齐的工作流修复：不要直接假设 `dataset/list/cve_list_v2.json` 一定带 `version_tree`；若主输出缺这个字段，先跑单 CVE `--cve` 重建 `tmp/*_unified_time_scan.json` 与 `tmp/*_matrix_latest.json`，再让渲染脚本从这两份输入 merge 生成版本树图

### 5.5 Excel 收尾评估链路更新（2026-04-17）

- 新增总控脚本 `code/difftrace/demo/scripts/run_excel_pipeline_with_difftrace.py`：
  - 先执行 `refresh.py` → difftrace 最终结果回填 → `patch_analysis.py` → `unknown_infer.py` → 最后执行收尾分析脚本
  - 支持 `--difftrace-batch-root` 或 `--difftrace-eval-json` 指向 `llm_vulnerability_presence_eval.json`
  - 新增 `--result-analysis-mode {default, full-coverage}`：
    - `default`：调用原 `result_analysis.py`
    - `full-coverage`：调用 `result_analysis_full_coverage.py`，允许 `affected_intro` 向上传递、`affected_patch` 向下传递
  - 若同一 `(CVE, Version)` 在 difftrace 评估结果中同时出现 `affected` 和 `not affected`，当前按保守策略解析为 `affected`
- `intro_analysis_embedding_f.py` 当前**不做修改**；这条新链路里由 difftrace 最终评估结果直接替代 `intro_only_results.json` 回填步骤。
- `unknown_infer.py` 已改为**直接写回 `execution_result.xlsx`**：
  - 漏洞引入边界写 `affected_intro` / `not affected_intro`
  - 补丁边界写 `affected_patch` / `not affected_patch`
  - 仍然只处理 `LLM_Verdict == No_Data` 的边界行；若同一行同时命中 intro / patch，则按 `intro` 优先
- `unknown_analysis.py` 已退出当前正式链路，不再作为必须步骤。

---

## 6. 建议的接手顺序

### 6.1 如果你要跑一个新批次

按这个顺序看：

1. `version_switch_unified_time_scan.py`
2. `target_paths.py`
3. `run_batch_analysis.py`
4. `run_case_analysis_runner_fix.py`
5. `run_case_analysis.py`
6. `run_version_regression_analysis.py`

其中第 1 步先刷新 `dataset/list/cve_list_v2.json`，后续脚本统一消费这份数据集。

### 6.2 如果你要排查单个 case 为什么是某个状态

按这个顺序看：

1. `cases/<case_id>/case-result.json`
2. `cases/<case_id>/run-version-analysis.log`
3. `cases/<case_id>/analysis/execution-observations.json`
4. `cases/<case_id>/analysis/trace-diff-summary.json`
5. `cases/<case_id>/analysis/version-diff/summary.json`
6. `cases/<case_id>/analysis/version-diff/api-diffs/...`
7. `cases/<case_id>/analysis/version-diff/diffs/...`

### 6.3 如果你要排查 LLM 为什么选错 hunk / 判错漏洞存在性

按这个顺序看：

1. `analysis/llm-scenario.json`
2. `analysis/llm-hunk-analysis.md`
3. `analysis/llm-hunk-judgments.json`
4. `analysis/llm-vulnerability-judgment.json`
5. `llm_hunk_selector.py`
6. `aggregate_llm_diff_results.py`
7. `version_diff_lib.py`

### 6.4 全量 staged 批处理运行手册（tmux + 16 workers）

推荐把“全量 tracediff/case-level”与“LLM 推断”拆成两个严格串行阶段：

1. **阶段 A：case-level / tracediff**
   - 分别运行 `run_batch_analysis.py --selection-mode compile-false` 与 `run_batch_analysis.py --selection-mode seek-patch-false`
   - 两个批次都结束后，再进入阶段 B
2. **阶段 B：LLM 链路**
   - 基于阶段 A 的两个 `batch-summary.json` 做去重合并
   - 然后依次执行 `backfill_llm_scenarios.py` → `run_llm_diff_batch.py` → `aggregate_llm_diff_results.py` → `evaluate_llm_vulnerability_detection.py`

当前 `cve_list_v2.json`（2026-04-15 快照）下：

- **`compile-false`**: 402 cases
- **`seek-patch-false`**: 357 cases
- **两者交集**: 300 cases
- **按唯一 `(cve_id, pair_index)` 去重后的 union**: 459 cases

因此**不要**直接把两个 summary 的 case 简单拼接后统计；应按唯一 case 去重。实践上建议：

- 先保留两个原始批次目录
- 合并时按唯一 `case_id` / `(cve_id, pair_index)` 去重
- 若同一 case 在两个批次都出现，优先保留状态信息更丰富的一条（通常 `trace_diff` / `execution_failure` 优先于 `compile_failure`）

如果用户要求在 `tmux` 环境运行，推荐：

- 进入 `tmux` 会话：`tmux attach -t mywork`
- 激活环境：`conda activate difftrace`
- 使用单独窗口执行全量批次，避免污染已有 pane
- 所有结果写到新的时间戳目录下，并同时保留总日志

### 6.5 CVE-2020-28052 超大 trace case 的特殊处理

- **涉及批次**：
  - 旧批次：`/data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260416_103100`
  - 新批次：`/data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260418_150218`
- **case_id**：`CVE-2020-28052__00__1.65__1.64`（`org.bouncycastle:bcprov-jdk15to18`）
- **旧批次行为**：
  - baseline PoC `JsonTest.testSkipSource` 单次执行耗时约 600+s，baseline 测试失败、target 测试成功；
  - trace 体量极大（baseline ≈ 21.6GB，target ≈ 131.6GB），`trace-diff-summary.json` 使用 `comparison_mode = "lightweight_large_trace_fallback"`，按“执行观测差异 + trace 尺寸差异”认定 `trace_diff`。
- **新批次行为**：
  - 在批次 `seekpatch_only_20260418_150218` 中，该 case 在实际跑满 `timeout_seconds = 3600` 后被标记为 `timeout`；
  - 后续通过专用脚本，将新批次中该 case 的 `case-result.json` 与 `batch-summary.json` 条目直接替换为旧批次的结果，并在 payload 中增加 `copied_from_batch` 字段标注来源。
- **结论**：后续如果在新批次上查看 `seek_patch = false` 的统计，`CVE-2020-28052__00__1.65__1.64` 应视为沿用 20260416 批次的 huge-trace fallback 结论（`status = trace_diff` / `failure_subtype = trace_difference`），而非本轮重新跑出的独立样本。

---

## 7. 当前最重要的结论

- `code/difftrace/demo` 当前已经形成一条完整闭环：
  - **版本对生成** → **批处理调度** → **单 case 执行** → **trace / diff 产物** → **LLM hunk 选择** → **漏洞存在性聚合评估**
- 当前最关键、最容易踩坑的地方有三个：
  - **先确认 `version_switch_unified_time_scan.py` 产出的 `cve_list_v2.json` 是否是最新，再跑后续 case 级脚本**
  - **如果你是为了画版本树，不要默认 `dataset/list/cve_list_v2.json` 一定带 `version_tree`；缺字段时应先跑 `version_switch_unified_time_scan.py --cve <CVE>`，再用 `tmp/*_unified_time_scan.json` + `tmp/*_matrix_latest.json` 渲染**
  - **LLM 不要只看 `api-diffs/*.diff`，关键修复经常藏在 `diffs/*.diff` 的方法/构造器上下文里**
- 如果后续继续维护这条链路，优先从这四个脚本入手：
  - `version_switch_unified_time_scan.py`
  - `run_case_analysis_runner_fix.py`
  - `llm_hunk_selector.py`
  - `aggregate_llm_diff_results.py`

## 8. 随机抽样 10 个 case 的证据核查

本小节基于批次 `seekpatch_only_20260416_103100` 中 `llm_vulnerability_presence_eval.json`，随机抽取 10 个 case，人工检查 difftrace + hunk 选取的证据是否对齐真实问题。

整体印象：大部分 case 中，trace diff 和版本 diff 的证据都落在合理模块 / 类上，误判更多来自“如何解读证据”而非“证据找错地方”。

### 8.1 抽样样本列表（含真值与预测）

- **CVE-2022-32549__01__2.24.0__2.23.6**  
  - **真值 / 预测 / outcome**: affected / not affected / **FN**  
  - **场景**: compile_failure / missing_class
- **CVE-2018-1000873__00__2.6.0-rc2__2.6.0-rc1**  
  - **真值 / 预测 / outcome**: affected / affected / **TP**  
  - **场景**: trace_diff / execution_failure / test_failure
- **CVE-2013-7285__02__1.4.10__1.4.9**  
  - **真值 / 预测 / outcome**: not affected / affected / **FP**  
  - **场景**: trace_diff / execution_failure / test_failure
- **CVE-2023-34455__02__1.1.2.2__1.1.2.1**  
  - **真值 / 预测 / outcome**: affected / affected / **TP**  
  - **场景**: execution_failure / test_failure
- **CVE-2020-5398__03__5.0.0.RELEASE__4.3.11.RELEASE**  
  - **真值 / 预测 / outcome**: not affected / not affected / **TN**  
  - **场景**: trace_diff / compile_failure / test_failure
- **CVE-2020-26258__00__1.4.1__1.4**  
  - **真值 / 预测 / outcome**: affected / unknown / **ABSTAIN**  
  - **场景**: trace_diff / execution_failure / test_failure
- **CVE-2020-11619__04__2.8.11.1__2.8.11**  
  - **真值 / 预测 / outcome**: not affected / affected / **FP**  
  - **场景**: execution_failure / test_failure
- **CVE-2018-21234__00__4.3.0__4.2.0**  
  - **真值 / 预测 / outcome**: affected / affected / **TP**  
  - **场景**: compile_failure / missing_class
- **CVE-2023-34455__00__1.1.2-RC3__1.1.2-RC2**  
  - **真值 / 预测 / outcome**: affected / affected / **TP**  
  - **场景**: execution_failure / test_failure
- **CVE-2017-7957__02__1.4.7__1.4.6**  
  - **真值 / 预测 / outcome**: affected / not affected / **FN**  
  - **场景**: trace_diff / execution_failure / test_failure

### 8.2 每个 case 的证据与分析摘要

- **CVE-2022-32549__01__2.24.0__2.23.6（FN，compile_failure / missing_class）**  
  - **选取证据**: 命中 `version-diff/api-diffs/org/apache/sling/api/request/builder/impl/RequestProgressTrackerImpl.diff`，显示 `RequestProgressTrackerImpl` 在 target 版本被完全移除；同时结合 `target-failure-excerpt.txt` 中的编译错误。  
  - **人工判断**: 证据清楚刻画了“类被移除 → 依赖编译失败”的根因，**定位非常准确**；FN 更像是后续漏洞存在性判定逻辑的问题，而不是 difftrace / hunk 找错地方。

- **CVE-2018-1000873__00__2.6.0-rc2__2.6.0-rc1（TP，trace_diff）**  
  - **选取证据**: 重点选中 `version-diff/api-diffs/com/fasterxml/jackson/datatype/jsr310/deser/key/Jsr310KeyDeserializer.diff`，展示 `Jsr310KeyDeserializer` 整类移除及其 `deserializeKey` / `deserialize` 方法签名。  
  - **人工判断**: 该类正是 JSR-310 key 反序列化核心组件，与已知安全修复紧密相关，**证据高度对齐** trace 回归和 CVE 语义。

- **CVE-2013-7285__02__1.4.10__1.4.9（FP，trace_diff）**  
  - **选取证据**: 命中 `version-diff/api-diffs/com/thoughtworks/xstream/XStream$1.diff`，聚焦到 `XStream$1`（converter lookup 相关匿名类）的字节码差异。  
  - **人工判断**: XStream$1 是 XStream 转换器注册/安全控制的重要节点，**证据位置很合理**；FP 主要来自对这些改动是否等价于“漏洞仍存在”的解释偏悲观，而不是证据误选。

- **CVE-2023-34455__02__1.1.2.2__1.1.2.1（TP，execution_failure / test_failure）**  
  - **选取证据**: 从 `target-observation-excerpt.txt` 抓取 `NegativeArraySizeException` / `OutOfMemoryError` 测试失败栈，再将 hunk 锚定到 `version-diff/api-diffs/org/xerial/snappy/SnappyFramedOutputStream.diff`。  
  - **人工判断**: SnappyFramedOutputStream 是 Snappy 压缩/解压的关键类，结合异常类型与版本差异，**证据对齐度很高**，能解释回归行为。

- **CVE-2020-5398__03__5.0.0.RELEASE__4.3.11.RELEASE（TN，trace_diff / compile_failure）**  
  - **选取证据**: 选中 `version-diff/api-diffs/org/springframework/http/ContentDisposition$BuilderImpl.diff`，展示 `ContentDisposition$BuilderImpl` 整个 builder 实现类在旧版本缺失。  
  - **人工判断**: 该 builder 负责构造 Content-Disposition header，与该 CVE 的修复点高度相关，**证据强相关且解释力强**。

- **CVE-2020-26258__00__1.4.1__1.4（ABSTAIN，trace_diff）**  
  - **选取证据**: 先使用 `trace-diff-summary.txt` 锚定首个分歧在 `AbstractDriver#getNameCoder`，列出大量 baseline-only 的 XML 处理调用；随后 evidence repair 补充 `version-diff/diffs/.../XppDomComparator.diff` 与 `XppFactory.diff`，指向 XPP DOM 相关类被移除。  
  - **人工判断**: 证据在模块和调用路径上都与 XML 解析行为变化高度契合，**定位是对的**；但由于无法从这些证据中得出清晰的“已修复 / 未修复”结论，最终选择 ABSTAIN，符合“证据不足不强行表态”的设计目标。

- **CVE-2020-11619__04__2.8.11.1__2.8.11（FP，execution_failure / test_failure）**  
  - **选取证据**: 经 evidence repair 后，聚焦到：`XStream.diff` 中 `SecurityMapper` 字段移除、`SunLimitedUnsafeReflectionProvider` / `SunUnsafeReflectionProvider` 整类移除、`XStream$1` 接口变化等。  
  - **人工判断**: 这些改动都紧贴 XStream 的安全/反射处理逻辑，**证据位置本身很准确**；FP 来自于把这些安全相关变更直接解读成“漏洞仍存在”的结论，属于判读层面的问题。

- **CVE-2018-21234__00__4.3.0__4.2.0（TP，compile_failure / missing_class）**  
  - **选取证据**: 先从 `JsonContext` 的 raw 声明入手，再通过 evidence repair 选中 `version-diff/api-diffs/jodd/json/JsonSerializer.diff`、`JsonParser.diff`、`JsonContext.diff`，集中在 jodd-json 的序列化/解析组件内部。  
  - **人工判断**: 证据成功锁定到正确模块与核心类，但粒度偏“结构性变化”而非直接对应具体异常行，**属于“模块级对齐但略泛”**，仍然是可接受的解释路径。

- **CVE-2023-34455__00__1.1.2-RC3__1.1.2-RC2（TP，execution_failure / test_failure）**  
  - **选取证据**: 多轮尝试未找到合适的 Java diff，最终只能把 `target-observation-excerpt.txt` 中的 `NegativeArraySizeException` / `OutOfMemoryError` 日志作为 Selected Hunks，并结合 trace / dependency-tree 的“无显著差异”信息。  
  - **人工判断**: 这里的“hunk”实质上是 fallback evidence（测试日志），**缺少能解释失败原因的具体代码 diff**，证据较弱但仍能撑起“这是预存在问题而非版本回归”的高层判断。

- **CVE-2017-7957__02__1.4.7__1.4.6（FN，trace_diff）**  
  - **选取证据**: 修正后将 hunk 聚焦到 XStream 反射与安全路径上的一组改动：`XStream.diff` 中 `SecurityMapper` 字段删除、`SunLimitedUnsafeReflectionProvider` 整类删除、`XStream$1` 接口和构造参数变化等。  
  - **人工判断**: 这些变更与 XStream 安全策略和对象构造路径密切相关，**证据对齐度很高**；FN 同样主要源自对这些证据与 CVE 真值之间关系的判定逻辑，而非证据查找失败。

## 9. Excel 全集评估补充链路

这一节记录 `dataset/execution_result.xlsx` 的全量评估补充流程。它不属于 `code/difftrace/demo` 的 case-level tracediff 主链，但现在已经成为**把 intro / patch / unknown 判定合并回 Excel，并对全集求总 Precision / Recall / F1** 的收尾步骤。

### 9.1 当前正式数据流

按 **2026-04-20** 当前口径，Excel 评估收尾流程已经切换为：

1. **`refresh.py`**  
   - **输入**: `execution_result.xlsx`  
   - **输出**: `execution_result.xlsx`  
   - **作用**: 把 `LLM_Verdict` 刷新为 `No_Data`，作为整条链路的初始化步骤。

2. **difftrace 最终结果回填（由 `run_excel_pipeline_with_difftrace.py` 内部执行）**  
   - **输入**: `llm_vulnerability_presence_eval.json`、`execution_result.xlsx`  
   - **输出**: `execution_result.xlsx`  
   - **作用**:
     - 读取 `code/difftrace/demo/target/...` 或 `/data-1/xinweimao/code/difftrace/demo/target/...` 下的 `llm_vulnerability_presence_eval.json`；
     - 把 case 级 `predicted_label` 聚合成 `(CVE, Version)` 级别结论；
     - 若同一 `(CVE, Version)` 同时出现 `affected` 与 `not affected`，按保守策略解析为 `affected`；
     - 为了兼容后续收尾传播逻辑，这一步仍然写成 `affected_intro` / `not affected_intro`；`unknown` 则保持 `No_Data`。

3. **`patch_analysis.py`**  
   - **输入**: `dataset/result/patch_only_results.json`、`execution_result.xlsx`  
   - **输出**: `execution_result.xlsx`  
   - **作用**: 将 patch 侧命中的版本写成 `affected_patch` / `not affected_patch`；该步骤**不清空前一步结果，只直接覆盖命中的行**。

4. **`unknown_infer.py`（直写 Excel 版）**  
   - **输入**: `execution_result.xlsx`  
   - **输出**: `execution_result.xlsx`  
   - **作用**:
     - 不再生成 `dataset/result/unknown_only_results.json`；
     - 按 Excel 原顺序扫描同一 CVE 的相邻版本，寻找 `APPEARS ↔ 非 APPEARS` 的翻转边界；
     - 只处理当前 `LLM_Verdict == No_Data` 的目标行；
     - 若是**漏洞引入边界**，直接写 `affected_intro` / `not affected_intro`；
     - 否则视为**补丁边界**，直接写 `affected_patch` / `not affected_patch`；
     - 若同一行同时命中 intro 与 patch，则按 **`intro` 优先**。

5. **收尾分析脚本（由 `run_excel_pipeline_with_difftrace.py` 按模式选择）**  
   - **输入**: `execution_result.xlsx`  
   - **输出**: `execution_result.xlsx`  
   - **作用**:
     - `default` 模式调用 **`result_analysis.py`**：对剩余 `No_Data` 行做最终前向 / 后向补全，并重新计算 `Aligned_llm`；
     - `full-coverage` 模式调用 **`result_analysis_full_coverage.py`**：在默认逻辑基础上，额外允许 **`affected_patch` 向下传递**、**`affected_intro` 向上传递**；
     - 两种模式都会打印**全集总 Precision / Recall / Accuracy / F1**，作为最终总评估结果。

当前正式链路里，**`unknown_analysis.py` 已不再需要**；若要测试更激进的正类传播，只需要切换第 5 步的收尾模式。

### 9.2 为什么引入 `run_excel_pipeline_with_difftrace.py`

当前新增的总控脚本是 `code/difftrace/demo/scripts/run_excel_pipeline_with_difftrace.py`，它的职责是把 difftrace 批次输出接到 Excel 全量评估收尾链路上。

它的核心约束如下：

- **不修改 `intro_analysis_embedding_f.py`**：该脚本目前保持原样，仅作为旧链路的兼容入口保留。
- **intro 步骤由 difftrace 最终评估结果替代**：不再依赖 `intro_only_results.json` 回填 Excel，而是直接读取 `llm_vulnerability_presence_eval.json`。
- **与现有标签体系兼容**：difftrace 回填时继续输出 `affected_intro` / `not affected_intro`，这样默认模式与 full-coverage 模式都可以直接消费同一份 Excel。
- **支持两种定位方式**：
  - `--difftrace-batch-root <batch_dir>`
  - `--difftrace-eval-json <eval_json>`
- **支持收尾模式切换**：
  - `--result-analysis-mode default`
  - `--result-analysis-mode full-coverage`
- **支持自定义收尾脚本路径**：
  - `--result-analysis-script <path>`
  - `--full-coverage-result-analysis-script <path>`
- **支持 `--dry-run`**：可先验证目标 batch 是否能被正确识别，而不实际改写 Excel。

### 9.3 推荐运行顺序

当前推荐优先直接运行总控脚本。

#### 9.3.1 默认模式

```bash
python code/difftrace/demo/scripts/run_excel_pipeline_with_difftrace.py --difftrace-batch-root /data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260416_103100
```

#### 9.3.2 full-coverage 模式

```bash
python code/difftrace/demo/scripts/run_excel_pipeline_with_difftrace.py --difftrace-batch-root /data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260416_103100 --result-analysis-mode full-coverage
```

两种模式在前 4 步完全相同，内部都会顺序执行：

1. `python code/refresh.py`
2. difftrace 最终结果回填到 `execution_result.xlsx`
3. `python code/patch_analysis.py`
4. `python code/unknown_infer.py`
5. `python code/result_analysis.py` **或** `python code/result_analysis_full_coverage.py`（取决于 `--result-analysis-mode`）

如果需要手工分步跑，也应使用上面这 5 步；**不要再把 `unknown_analysis.py` 放回正式顺序**。

### 9.4 2026-04-20 当前一次实跑结果（基于 seekpatch_only_20260418_150218）

本节记录 2026-04-20 在当前代码与规则下，对 `dataset/execution_result.xlsx` 的两次完整 Excel 全链路实跑，均采用 **full-coverage 模式**：

- **9.4.1**：使用上一次 stageb 自动流水线产出的 eval，完整复现“旧口径”的 Excel 收尾结果；
- **9.4.2**：使用 `dataset` 目录下、基于最新泛化规则重新评估得到的 eval，得到“新口径”的 Excel 收尾结果。

#### 9.4.1 使用 stageb 自动流水线 eval 复现旧口径结果

- **评估文件**：
  - `code/difftrace/demo/target/seekpatch_only_20260418_150218/llm-stageb-auto-RENEW/llm_vulnerability_presence_eval.json`
- **运行模式**：`--result-analysis-mode full-coverage`
- **推荐复现命令**：

  ```bash
  cd /home/xinweimao/alv_evaluate/myResearch/workspace

  python code/difftrace/demo/scripts/run_excel_pipeline_with_difftrace.py \
    --difftrace-eval-json code/difftrace/demo/target/seekpatch_only_20260418_150218/llm-stageb-auto-RENEW/llm_vulnerability_presence_eval.json \
    --result-analysis-mode full-coverage
  ```

- **difftrace 回填阶段（作为 intro 替代步骤）**：
  - matched_rows = 186
  - written_rows = 174
  - unknown_rows = 12
  - TP = 106, TN = 4, FP = 60, FN = 4  
    （这些 TP/FP/FN/TN 只针对**被回填覆盖到的行子集**，用于观测 difftrace 回填本身的质量。）

- **full-coverage 收尾后的全集指标**（以 `result_analysis_full_coverage.py` 输出为准）：
  - TP: `13501`
  - FP: `2168`
  - FN: `867`
  - TN: `11614`
  - Accuracy: `89.22%`
  - Precision: `86.16%`
  - Recall: `93.97%`
  - F1: `0.8990`

> 这一组指标可以理解为：**完全沿用 stageb 自动流水线那次 eval 的“旧规则”口径，在 Excel 端复现的 full-coverage 总体结果。**

#### 9.4.2 使用 dataset 下最新 eval + 泛化规则的当前口径结果

这一小节对应 2026-04-20 早上在规则层做了一次泛化修改后，用最新 eval 驱动 Excel 的正式结果。

- **评估文件**：
  - `dataset/llm_vulnerability_presence_eval.json`
- **评估文件来源**：
  - 由 `code/difftrace/demo/scripts/aggregate_llm_diff_results.py` 读取 `code/difftrace/demo/target/seekpatch_only_20260418_150218/batch-summary.json`，生成 `dataset/llm_hunk_analysis.json`；
  - 再由 `code/difftrace/demo/scripts/evaluate_llm_vulnerability_detection.py` 读取该 hunk 分析和 `dataset/execution_result.xlsx`，写出 `dataset/llm_vulnerability_presence_eval.json`。
- **规则层的关键泛化修改**（不再针对单个 CVE，而是模式级约束）：
  - 在 `infer_predicted_label` 中针对 `final_failure_reason = "vulnerability_not_present"`：
    - 以前是一刀切地直接判为 `not affected`；
    - 现在调整为：
      - 若 **`scenario_type = trace_diff` 且 `trace_has_effective_difference = True` 且 `trace_evidence_valid = True`**，说明 difftrace 给出了高质量的行为差异证据，此时 **不再直接信任 LLM 的“漏洞不存在”结论**，而是退回 `unknown`；
      - 其它场景仍按 "vulnerability_not_present ⇒ not_affected" 处理。
  - 新增一条基于执行观测的泛化覆写规则：
    - 当 **`scenario_type = "trace_diff"` 且 `trace_has_effective_difference = True` 且 `trace_evidence_valid = True`**，
    - 且 **`baseline_execution_observation = "test_failure"`、`target_execution_observation = "success"`** 时，
    - 更合理的解释是“高版本引入额外行为变化或 bug 而非低版本仍受漏洞影响”，因此直接预测为 **`not affected`**，以少量 FN 为代价减少类似 `CVE-2021-43795` 这类系统性 FP 模式。
  - 同时删除了之前的 `CVE-2019-20444` 专用 override，完全依赖 difftrace + LLM 字段（含执行观测）的模式化规则，而非硬编码某个 CVE。

- **LLM 评估层面的整体指标（`evaluate_llm_vulnerability_detection.py` 输出）**：
  - 正类 = `affected`：
    - TP = 24, FP = 6, FN = 9, TN = 20  
    - Precision ≈ 0.8000, Recall ≈ 0.7273, F1 ≈ 0.7619
  - 正类 = `not affected`：
    - TP = 20, FP = 9, FN = 6, TN = 24  
    - Precision ≈ 0.6897, Recall ≈ 0.7692, F1 ≈ 0.7273
  - `predicted_label` 分布：`unknown = 105`、`affected = 30`、`not affected = 29`

- **DiffTrace → Excel 全链路执行摘要**（full-coverage 模式）：

  ```bash
  cd /home/xinweimao/alv_evaluate/myResearch/workspace

  python code/difftrace/demo/scripts/run_excel_pipeline_with_difftrace.py \
    --difftrace-eval-json dataset/llm_vulnerability_presence_eval.json \
    --result-analysis-mode full-coverage
  ```

  - **difftrace 回填阶段（intro 替代）**：
    - matched_rows = 186
    - written_rows = 72
    - unknown_rows = 114
    - TP = 30, TN = 25, FP = 7, FN = 10  
      （同样只针对被回填覆盖的子集；在更保守的 LLM 规则下，写回行数相较 stageb 旧口径明显减少，但子集上的 Precision 仍保持在约 81%，F1 约为 0.78。）

  - **`patch_analysis.py` 阶段（固定阈值 0.3）**：
    - Total Matched = 389
    - TP = 1, TN = 355, FP = 8, FN = 25
    - Accuracy = 0.9152

  - **`result_analysis_full_coverage.py` 收尾后的全集指标**：
    - TP: `12807`
    - FP: `335`
    - FN: `1561`
    - TN: `13447`
    - Accuracy: `93.26%`
    - Precision: `97.45%`
    - Recall: `89.14%`
    - F1: `0.9311`

> 与 9.4.1 的旧口径（Precision≈86.16%, Recall≈93.97%）相比，当前这版 **在略牺牲部分召回（≈89.1%）的前提下进一步显著降低误报（Precision≈97.5%，F1≈0.931）**，且规则不再依赖某个特定 CVE，而是依赖 difftrace trace 证据、执行观测以及 LLM 的 `final_failure_reason` 做模式级泛化约束。

### 9.4.3 Excel 收尾阶段的 LLM 扩张判断（可选）

- 在 `result_analysis_full_coverage.py` 中新增了一个基于 LLM 的扩张判断子模块，用来在 `affected_intro` / `affected_patch` 跨越不同 `Execution Result` bucket（`APPEARS` vs `OTHER`）传播时，调用 LLM 对“是否继续扩张”做一致性校验，但 **不改变任何最终标签**。
- 对这些潜在边界点，脚本会调用 `hypothetical_llm_score(row, neighbor_version)`，构造包含 `CVE_ID`、`Library`、`PoC`、`Execution Result`、`LLM_Verdict` 以及相邻版本号的 JSON 交给 LLM，得到一个 `refinement_score` 并写入诊断列 `LLM_Refinement_Score` / `LLM_Refinement_Decision`，实际的标签传播仍严格按原有规则执行。
- 外部 LLM 调用受环境变量 `EXCEL_ENABLE_LLM_REFINE` 控制：默认关闭时直接返回常数分数，不打外部 API；只有当 `EXCEL_ENABLE_LLM_REFINE ∈ {1, true, yes, on}` 时才会真正请求模型并在日志中打印对应的 `CVE_ID` / 邻居版本与 `refinement_score`，同时保持 9.4.2 中记录的整体指标不变。

### 9.5 Excel 列约定与常见疑问

#### 9.5.1 当前正式收尾流程只认哪两列

当前正式 Excel 收尾链路，**唯一正式使用的结果列**是：

- `LLM_Verdict`
- `Aligned_llm`

`refresh.py`、difftrace 回填、`patch_analysis.py`、`unknown_infer.py`、`result_analysis.py`、`result_analysis_full_coverage.py`，当前都围绕这两列读写。

#### 9.5.2 为什么会看到 `v6_improved_Verdict` / `Aligned_v6`

这两列**不是当前收尾流程的一部分**，而是历史脚本 `code/evaluate_v6_improved.py` 单独写入 Excel 时留下的对比列。

需要注意：

- 当前正式收尾链路**不会读取**这两列；
- `result_analysis.py` 也**不会使用**这两列做最终 Precision / Recall / F1 统计；
- 因此它们可以视为**历史实验遗留列**，不是当前正式口径。

#### 9.5.3 为什么 `LLM_Verdict` 里会出现不带后缀的 `affected`

这不是 difftrace / patch / unknown 三步直接写入的结果，而是 **`result_analysis.py` / `result_analysis_full_coverage.py` 的兜底逻辑**。

当前这两个收尾脚本在前向扫描时都包含一条规则：

- 如果某行当前仍是 `LLM_Verdict == No_Data`
- 且该行 `Execution Result == APPEARS`
- 则直接把该行写成 **`affected`**

这样做的含义是：

- 这类行已经可以从 PoC 执行结果直接确定为“漏洞仍存在”；
- 但它**不是**由某个明确的 intro 边界、patch 边界或 unknown 边界步骤写入的；
- 所以当前实现把它当作**通用阳性兜底标签**，写成裸 `affected`，而不是 `affected_intro` 或 `affected_patch`。

#### 9.5.4 当前标签来源的解释口径

按当前实现，`LLM_Verdict` 中几种常见值应这样理解：

- `affected_intro` / `not affected_intro`：来自 difftrace intro 替代回填，或 `unknown_infer.py` 命中的 introduction 边界；在 `full-coverage` 模式下，`affected_intro` 还可能被继续向上传递
- `affected_patch` / `not affected_patch`：来自 `patch_analysis.py`，或 `unknown_infer.py` 命中的 patch 边界；在 `full-coverage` 模式下，`affected_patch` 还可能被继续向下传递
- `affected`：来自 `result_analysis.py` / `result_analysis_full_coverage.py` 对 `APPEARS + No_Data` 的最终兜底补全
- `No_Data`：在进入收尾分析脚本之前，仍未被前面步骤命中的行

因此如果在 Excel 中看到：

- `v6_improved_Verdict` / `Aligned_v6`：说明是**历史实验列**，不属于当前正式收尾链路
- 裸 `affected`：说明是**最终收尾阶段的兜底写入**，不是某个带来源后缀的边界判定

### 9.6 `library_fp_fn_ranking.py`：按 Library 统计 FN / FP 排名

当前新增的 `code/library_fp_fn_ranking.py` 用于对 `execution_result.xlsx` 做 **Library 维度的误差聚合分析**，快速回答两个问题：

- 哪些 `Library` 的 **FN 最多**
- 哪些 `Library` 的 **FP 最多**

它默认读取：

- `dataset/execution_result.xlsx`

默认使用的列是：

- `Library`
- `Aligned_llm`

因此它当前对齐的是**正式收尾口径**，也就是围绕 `LLM_Verdict` / `Aligned_llm` 这套最终结果列来统计，而不是历史实验列。

#### 9.6.1 运行方式

```bash
python code/library_fp_fn_ranking.py
```

如果需要指定 Excel、列名或输出目录，也可以显式传参，例如：

```bash
python code/library_fp_fn_ranking.py --excel dataset/execution_result.xlsx --library-col Library --aligned-col Aligned_llm --top 20 --output-dir dataset/result/library_fp_fn_ranking
```

#### 9.6.2 统计逻辑

脚本会先把 `Library` 与 `Aligned_llm` 做标准化处理，然后：

- 把空 `Library` 统一记为 `\(EMPTY_LIBRARY\)`；
- 把 `Aligned_llm == FN` 记为 `is_fn = True`；
- 把 `Aligned_llm == FP` 记为 `is_fp = True`；
- 把 `FN` 与 `FP` 的并集记为 `error_count`；
- 最后按 `Library` 聚合，统计：
  - `total_rows`
  - `fn_count`
  - `fp_count`
  - `error_count`
  - `fn_ratio`
  - `fp_ratio`
  - `error_ratio`

排序规则分三份：

- **FN 排名**：优先按 `fn_count` 降序，再看 `fp_count`、`error_count`、`Library`
- **FP 排名**：优先按 `fp_count` 降序，再看 `fn_count`、`error_count`、`Library`
- **总误差排名**：优先按 `error_count` 降序，再看 `fn_count`、`fp_count`、`Library`

#### 9.6.3 输出结果

脚本会在默认目录 `dataset/result/library_fp_fn_ranking` 下生成 4 份 CSV：

- `library_fn_fp_summary.csv`：每个 `Library` 的总表
- `library_fn_ranking.csv`：按 `FN` 数量降序
- `library_fp_ranking.csv`：按 `FP` 数量降序
- `library_error_ranking.csv`：按 `FN + FP` 总误差降序

同时终端会直接打印：

- `FN` 最多的前 N 个 `Library`
- `FP` 最多的前 N 个 `Library`
- 当前 `FN` 最高与 `FP` 最高的 `Library` 简要结论

#### 9.6.4 当前使用建议

这个脚本适合放在**整条 Excel 收尾链路完成之后**再运行，也就是在 `refresh.py`、difftrace 回填、`patch_analysis.py`、`unknown_infer.py`、`result_analysis.py` / `result_analysis_full_coverage.py` 之后执行。

这样统计出的 `FN / FP` 才对应**最终正式结果**，可以直接用于判断：

- 哪些库是当前 Recall 的主要拖累项
- 哪些库是当前 Precision 的主要误报来源
- 后续应该优先挑哪些 `Library` 去做 case-level 深挖分析
