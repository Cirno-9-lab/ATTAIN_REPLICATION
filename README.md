# ATTAIN

自动化漏洞回归测试工具链（基于 Maven 依赖 trace + 版本 diff + LLM 分析）。

## 工具链五层架构

```
版本对生成层 (version_switch_unified_time_scan.py)
    ↓
批处理调度层 (run_batch_analysis.py)
    ↓
单 case 执行层 (run_case_analysis_runner_fix.py / run_case_analysis.py)
    ↓
diff / trace / LLM 分析层
    ↓
评估与辅助层
```

## 端到端主流程

### 阶段 A：Case-level trace diff

```
① version_switch_unified_time_scan.py
   输入: execution_result.xlsx, Maven 发布时间缓存, ...
   输出: dataset/list/cve_list_v2.json (统一 case 数据集)

② run_batch_analysis.py
   输入: cve_list_v2.json + exploit 根目录
   输出: batch-summary.json, 各 case 的 case-result.json
   调度模式: --selection-mode compile-false / seek-patch-false

③ run_case_analysis_runner_fix.py (默认入口)
   输入: cve_list_v2.json + --cve-id + --pair-index
   输出: case-result.json, analysis/ 产物
   核心子流程: materialize_case_workspace.py → run_version_regression_analysis.py
```

### 阶段 B：LLM 分析链路

```
④ backfill_llm_scenarios.py (补齐缺失的 llm-scenario.json)
    ↓
⑤ run_llm_diff_batch.py (批量调用 llm_hunk_selector.py)
   输出: llm-hunk-analysis.md
    ↓
⑥ aggregate_llm_diff_results.py
   输入: batch-summary.json + hunk analysis
   输出: dataset/llm_hunk_analysis.json / .csv
    ↓
⑦ evaluate_llm_vulnerability_detection.py
   输入: hunk analysis + execution_result.xlsx
   输出: llm_vulnerability_presence_eval.json / .csv
```

### 阶段 C：Excel 全量评估收尾

```
⑧ refresh.py → (difftrace 结果回填) → patch_analysis.py → unknown_infer.py → result_analysis.py
   或一键脚本: run_excel_pipeline_with_difftrace.py
   支持 --result-analysis-mode default / full-coverage
```

## 核心脚本速查

| 脚本 | 职责 |
|------|------|
| `version_switch_unified_time_scan.py` | 按 Maven 发布时间扫描版本，生成 version_pair |
| `run_batch_analysis.py` | 批量挑 case、并发调度、汇总批次结果 |
| `run_case_analysis_runner_fix.py` | 单 case 执行入口，含错误归一化与自动重试 |
| `materialize_case_workspace.py` | 复制 exploit demo、patch pom.xml、注入依赖 |
| `run_version_regression_analysis.py` | 跑 baseline/target 两轮、trace 比较、版本 diff |
| `version_diff_lib.py` | 生成 api-diffs / diffs / summary.json |
| `llm_hunk_selector.py` | LLM 工具式交互，选取最相关 diff hunk |
| `aggregate_llm_diff_results.py` | 汇总 LLM 中间结果，生成结构化 judgment |
| `evaluate_llm_vulnerability_detection.py` | 用真值评估 LLM 判定质量 |
| `run_excel_pipeline_with_difftrace.py` | Excel 全量评估收尾总控 |

## 重要提醒

1. 跑 case 前务必确认 `cve_list_v2.json` 是最新版本
2. LLM hunk 分析不能只看 `api-diffs/*.diff`，关键修复常藏在 `diffs/*.diff` 的方法/构造器上下文
3. `cve_list_v2.json` 不保证内嵌 `version_tree`，画版本树需用 `--cve` 单 CVE 模式重建
4. 阶段 A 和阶段 B 严格串行，两个 `batch-summary.json` 按唯一 `(cve_id, pair_index)` 去重合并（建议 459 cases）

## 目录结构

```
code/difftrace/demo/scripts/   ← 脚本目录
target/.../cases/<case_id>/    ← 单 case 产物
  analysis/
    baseline-trace.log / target-trace.log
    trace-diff-summary.json / trace-diff-summary.txt
    version-diff/ (api-diffs/, diffs/, summary.json)
    llm-scenario.json / llm-hunk-analysis.md
    llm-hunk-judgments.json / llm-vulnerability-judgment.json
dataset/
  list/cve_list_v2.json        ← 统一 case 数据集
  execution_result.xlsx         ← 真值评估表
  llm_vulnerability_presence_eval.json / .csv
```
