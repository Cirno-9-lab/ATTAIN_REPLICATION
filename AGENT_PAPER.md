## 基于 DiffTrace 的漏洞利用跨版本分析：论文三模块视角

*最后更新：2026-04-26*

本文档从"论文三模块"的视角，对当前 `code/difftrace/demo` 工具链中的主要脚本与函数进行重新编排。目标是：

- **模块一**：从 PoC 在 baseline/target 上的执行出发，得到执行轨迹链与跨版本 diff，并通过 LLM + 工具调用自动探索这些 diff；
- **模块二**：基于模块一筛选出的"利用相关 diff / 证据"，判定漏洞是否仍存在，并给出"利用为何失效"的原因；
- **模块三**：对关键 diff 进行回溯与 alignment，将证据稳定对齐到关键文件 / 关键 hunk，支撑后续统计、Excel 收尾和论文案例分析。

下面每个模块都按照 **对应函数/脚本 → 输入 → 输出 → 实现功能** 的格式说明。

---

## 实验划分：实验一 / 实验二 / 实验三

- **实验一（DiffTrace 主流水线）**：以当前三个模块（执行轨迹 + diff 探索 / 漏洞存在性判定 / Excel 版本链传播）组成的 baseline 工具链为主体，在 `dataset/execution_result.xlsx` 上评估 difftrace+LLM 的整体检测能力。
- **实验二（消融实验）**：围绕三个模块内部的关键子组件做对照实验，包括：模块一的 failure-only 消融（ab1 pipeline）、模块二的 evidence / rule 子模块消融（ab2 设计）、模块三的 full-coverage 传播消融（ab3 设计），用于量化各子模块对整体性能的边际贡献。
- **实验三（CWE 维度方法对比）**：在 `True Affected Version` 作为真值、`No_Data` 视为 `not affected` 的前提下，通过脚本 `code/difftrace/demo/scripts/cwe_cnt.py` 读取 `dataset/list/cve_list_v2.json` 与 `dataset/execution_result.xlsx`，按前 10 个 CWE + `others` 分组，统计 PoB（`LLM_Verdict`）、PoC（`Execution Result`）、vszz（`vszz_verdict`）、llm（`llm4szz_verdict`）四种方法在各组上的 Precision/Recall/F1，并以转置形式输出到 `dataset/cwe_cnt.csv`，用于 RQ1 的 CWE 维度对比。

---

## 模块一：执行轨迹差分 + LLM 工具增强 diff 探索

### 1. 模块目标

- 给定同一 PoC 在旧版本（baseline）与新版本（target）上的执行情况：
  - 获得一对 **执行轨迹链**（trace + 执行观测）；
  - 生成对应的 **版本 diff 目录 `version-diff/`**；
- 在此基础上，通过 **LLM 驱动的工具调用（Tool-augmented dynamic prompting）**：
  - 以"执行轨迹差异"为线索，从大量 diff 中自动筛出少量 **与漏洞利用相关的高信号 hunk**；
  - 为模块二的判定阶段提供结构化证据。

### 2. 核心脚本与函数

#### 2.1 执行轨迹链与回归分析

- **脚本 `run_version_regression_analysis.py`**
  - **主要调用的底层函数**：`trace_workflow_lib.py` 中的：
    - `discover_test_context(...)`
    - `run_trace(...)`
    - `run_dependency_tree(...)`
    - `compare_trace_sequences(...)`
  - **输入**：
    - `baseline_version` / `target_version`
    - `test_file`（来自 `run_case_analysis*.py`）
    - materialized workspace 路径、trace 配置等
  - **输出（写入单个 case 的 `analysis/` 目录）**：
    - 执行相关：
      - `analysis-metadata.json`
      - `baseline-maven.log` / `target-maven.log`
      - `baseline-trace.log` / `target-trace.log`
      - `trace-commands.json`
      - `execution-observations.json`
      - `trace-diff-summary.json` / `trace-diff-summary.txt`
    - 版本 diff 相关：
      - `version-diff/api-diffs/*.diff`
      - `version-diff/diffs/*.diff`
      - `version-diff/api-raw/`（baseline/target 原始 API 文本）
      - `version-diff/raw/`（baseline/target `javap -c -p` 文本）
      - `version-diff/summary.json`（changed/added/removed 类统计与预览）
    - LLM 场景：
      - `llm-scenario.json`（封装 `scenario_type`、trace 差异标志、失败 excerpt 路径、关键词等）
  - **实现功能**：
    - 对单个 `(baseline_version, target_version, test_file)`，构建完整的 **执行轨迹链 + 跨版本 diff 视图**；
    - 将 trace、依赖树 diff、版本 diff、执行观测统一汇入 `analysis/` 目录，作为后续 LLM 模块的输入。

- **库 `trace_workflow_lib.py`**
  - **关键函数**：
    - `discover_test_context(project_root, test_file, ...)`：推断测试上下文（test selector、trace packages 等）；
    - `run_trace(project_root, test_selector, version, ...)`：在指定版本上执行带 trace 的测试，生成 trace log；
    - `compare_trace_sequences(baseline_trace, target_trace, ...)`：比较 baseline/target trace 序列，输出 `trace-diff-summary.json` / `.txt`；
  - **输入**：项目根目录、测试文件、版本信息、trace 配置；
  - **输出**：trace log、dependency tree、统一 JSON/text 辅助产物；
  - **实现功能**：实现论文中"执行轨迹链"与"轨迹差异"的底层执行逻辑。

#### 2.2 版本 diff 生成与上下文查询

- **库 `version_diff_lib.py`**
  - `load_version_diff_context(diff_root, diff_relative_path, hunk_hint=..., diff_start_line=..., diff_end_line=..., context_lines=...)`
    - **输入**：
      - `diff_root`：通常为 `analysis/version-diff`；
      - `diff_relative_path`：某个 `api-diffs/*.diff` 或 `diffs/*.diff` 的相对路径；
      - 可选：`hunk_hint`（用于抽取 anchor 关键字）、diff 行号窗口与上下文行数；
    - **输出**：包含以下字段的字典：
      - `diff_path`：完整 diff 文件路径；
      - `baseline_raw_path` / `target_raw_path`：对应 baseline/target 原始文本路径；
      - `matched_anchor_terms`：从 diff 中抽取出的关键 token；
      - `diff_excerpt` + 起止行号；
      - `baseline_context` / `target_context`：各自的行号范围与 preview 文本；
    - **实现功能**：
      - 将"diff 文件中的修改 hunk"反解到 baseline/target 的原始代码上下文中；
      - 为后续 LLM 工具调用提供"带行号窗口的代码片段"。
  - `search_version_diff_context(diff_root, query, limit=10, scope="all"|"api-raw"|"raw")`
    - **输入**：`diff_root`、自然语言 query、检索范围；
    - **输出**：若干条匹配结果，每条包含：`path`、`line`、`text`、`scope`、`variant`（baseline/target）等；
    - **实现功能**：
      - 支持基于类名/方法名/关键词在 `api-raw` 与 `raw` 中做符号级检索；
      - 用于从"轨迹差异 / 错误信息"反向定位潜在相关的类/方法。

#### 2.3 LLM 工具增强 diff 探索（Tool-augmented dynamic prompting）

- **库/脚本 `llm_hunk_selector.py`**

  1. **Prompt 构造层**
     - `build_analysis_prompt(scenario: dict) -> str`
       - **输入**：`llm-scenario.json` 解析出的 `scenario` 字典；
       - **输出**：一段多行 prompt，包含：
         - 回归场景类型（`scenario_type`）；
         - artifact 与版本对；
         - baseline/target 的执行观测摘要；
         - 失败/trace 关键词；
         - 与 trace/失败相关的文件路径（`trace-diff-summary.txt`、`*observation-excerpt.txt`、`dependency-tree.diff`、`version-diff/summary.json` 等）；
       - **实现功能**：
         - 把"执行轨迹差异 + 版本 diff 概览"压缩为 LLM 可消费的场景描述；
         - 约束 LLM：先读 summary 与 trace，再使用工具，避免盲目搜索。

  2. **工具封装层（提供给 LLM 的函数工具）**
     - `search_workspace(root, keywords, limit, path_glob)` / `keyword_search(...)`
       - 在单个 `analysis/` 工作区内搜索关键词，返回 `file:line: text` 列表；
     - `read_workspace_file(root, path, start_line, end_line)` / `read_file(...)`
       - 在工作区内按行号窗口读取文件内容；
     - `load_diff_context(...)`（tool 版本）
       - 底层调用 `version_diff_lib.load_version_diff_context(...)`；
     - `search_code_context(...)`（tool 版本）
       - 底层调用 `version_diff_lib.search_version_diff_context(...)`；
     - **实现功能**：
       - 这些函数通过 AutoGen 的 `FunctionTool` 暴露给 LLM，使 LLM 能在"版本 diff + trace + failure excerpt"的空间里主动发起精确的检索和局部读取。

  3. **多轮工具交互与输出层**
     - `run_llm_hunk_selection(analysis_root, scenario, output_path, config)`
     - `run_llm_hunk_selection_sync(...)`
       - **输入**：
         - `analysis_root`：单 case 的 `analysis/` 目录；
         - `scenario`：由 `llm-scenario.json` 解析而来；
         - `config`：`LLMAnalysisConfig(model, base_url, api_key, max_rounds, ...)`；
       - **输出**：
         - 输出文件 `llm-hunk-analysis.md`：
           - 包含工具交互 transcript；
           - 以及最终的 `Final response`，按固定结构划分为四段：
             - `Diagnosis`
             - `Selected Hunks`
             - `Supporting Evidence`
             - `Open Questions`
       - **实现功能**：
         - 在有限 round 的工具调用预算内，引导 LLM：
           - 从 summary / trace 开始；
           - 利用搜索与上下文读取定位相关 diff；
           - 优先选择真正与漏洞路径相关的少量 hunk（而不是所有改动）；
           - 以 markdown 形式给出结构化诊断与证据列表。

### 3. 模块一的总体输入 / 输出接口

- **输入（从上游角度）**：
  - PoC + 版本对（`case-input.json` / `materialized-case.json` 内的 `baseline_version` / `target_version`、测试文件、artifact）；
  - 上游批处理生成的单 case 目录；

- **输出（供下游模块直接使用的主要文件）**：
  - 执行轨迹链与差异：`execution-observations.json`、`trace-diff-summary.json` / `.txt`；
  - 版本 diff 全量上下文：`version-diff/` 目录树；
  - LLM 选出的利用相关 diff：`llm-hunk-analysis.md`（内含 `Selected Hunks` 及其路径和简短 excerpt）。

---

## 模块二：由利用相关 diff 判定漏洞存在性与利用失效原因

### 1. 模块目标

- 在模块一输出的 `llm-hunk-analysis.md` 和 `version-diff/`、trace、failure excerpt 等证据基础上：
  - 判定目标版本**漏洞是否仍存在**（或"仍可能存在"）；
  - 给出"漏洞利用为何失效"的**语义原因标签**；
  - 结果以结构化 JSON 形式落地，便于后续 Excel 收尾与统计分析。

### 2. 核心脚本与函数

#### 2.1 单 hunk 层面的证据类型判断

- **库 `llm_hunk_selector.py`**

  - `build_hunk_judgment_prompt(case_payload, scenario, hunk_payload)`
    - **输入**：
      - `case_payload`：来自 `batch-summary.json` 的单 case 元信息（`case_id`、`cve_id`、`artifact`、`baseline_version`、`target_version`、`status`、`failure_subtype` 等）；
      - `scenario`：来自 `llm-scenario.json` 的场景信息；
      - `hunk_payload`：从 `Selected Hunks` 解析出的单个证据项（包含 `path`、`diff_excerpt`、`evidence_kind` 等）；
    - **输出**：一段中文 prompt，引导 LLM 按以下标签判断：
      - `judgment ∈ {fix_evidence, exploit_breakage_evidence, neutral}`；
      - `confidence ∈ {high, medium, low}`；
      - `key_evidence`、`reasoning`；
    - **实现功能**：
      - 在"单个 diff / fallback 证据"的层面，区分：
        - 这是目标版本的**修复证据**（fix）；
        - 还是主要说明 PoC 因 API/运行时/环境变化而**失效**（exploit breakage）；
        - 还是信息不足（neutral）。

  - `run_llm_hunk_judgment(...)` / `run_llm_hunk_judgment_sync(...)`
    - **输入**：同上 + `LLMAnalysisConfig`；
    - **输出**：规范化的 JSON（经 `_normalize_hunk_judgment_payload(...)`）：
      - `hunk_path`、`judgment`、`confidence`、`key_evidence`、`reasoning`；
    - **实现功能**：
      - 对 `Selected Hunks` 中的每个证据项做细粒度类型判定，为后续全局判断提供子证据标签。

#### 2.2 Case 级漏洞存在性与失效原因判定

- **库 `llm_hunk_selector.py`**

  - `build_vulnerability_judgment_prompt(case_payload, scenario, hunk_payloads)`
    - **输入**：同上，但 `hunk_payloads` 是一组证据项；
    - **输出**：
      - 一段更高层的 prompt，要求 LLM 输出：
        - `vulnerability_presence_score ∈ [0, 100]`；
        - `final_failure_reason ∈ {vulnerability_not_present, exploit_invalid_due_to_version_change, undetermined}`；
        - `vulnerability_presence_verdict ∈ {no, possibly_yes, unknown}`；
        - `judgment_confidence`；
        - `fix_evidence_strength` / `exploit_breakage_evidence_strength`；
        - `key_evidence`、`judgment_rationale`；
      - 同时对"逻辑优先 / 环境失败 / trace 证据质量"等做明确约束。
  - `run_llm_vulnerability_judgment(...)` / `run_llm_vulnerability_judgment_sync(...)`
    - **输入**：`case_payload`、`scenario`、若干 `hunk_payloads`、LLM 配置；
    - **输出**：规范化 JSON（经 `_normalize_judgment_payload(...)`），写入：
      - `analysis/llm-vulnerability-judgment.json`；
    - **实现功能**：
      - 在多条证据的基础上，给出**单个 case 的整体判定**：
        - 漏洞是否仍存在（或仍可能存在）；
        - 利用是因为修复失败、环境/兼容性问题，还是证据不足。

- **脚本 `aggregate_llm_diff_results.py`**

  - **主要职责**：
    1. 解析 `llm-hunk-analysis.md`：
       - 提取 `Final response`；
       - 用 `parse_sections(...)` 拆出 `Diagnosis` / `Selected Hunks` / `Supporting Evidence` / `Open Questions`；
       - 把 `Selected Hunks` 解析成结构化 `selected_hunks` / `selected_hunk_payloads`；
       - 如有需要，对浅层 api diff 做 evidence repair，补充 `paired_bytecode_path`。
    2. 生成聚合表：
       - 写出 `dataset/llm_hunk_analysis.json` / `.csv`；
    3. 生成最终漏洞判定：
       - 调用 `run_llm_vulnerability_judgment_sync(...)`，生成/更新 `analysis/llm-vulnerability-judgment.json`；
       - 将结果汇总进聚合 JSON。

#### 2.3 全集评估与标签压缩

- **脚本 `evaluate_llm_vulnerability_detection.py`**

  - `infer_predicted_label(entry, score_no_threshold, score_yes_threshold) -> str`
    - **输入**：来自 `llm_hunk_analysis.json` / `llm_vulnerability_presence_eval.json` 的单条 `entry`，包括：
      - `scenario_type`、`status`、`failure_subtype`；
      - `final_failure_reason`、`vulnerability_presence_verdict`；
      - `vulnerability_presence_score`；
      - trace 质量信号：`trace_has_effective_difference`、`trace_evidence_valid`、`first_divergence_is_noise` 等；
    - **输出**：三元标签 `predicted_label ∈ {affected, not affected, unknown}`；
    - **实现功能**：
      - 以规则方式把 LLM 的细粒度判断压缩成 `affected/not affected/unknown`；
      - 同时用 trace_diff 语义和 score 桶做泛化修正（比如在高质量 trace_diff 场景下，对 `vulnerability_not_present` 谨慎退回 `unknown`）。
  - 顶层脚本功能：
    - 与 `dataset/execution_result.xlsx` 的真值对比；
    - 计算 Precision/Recall/F1 等指标；
    - 写出 `dataset/llm_vulnerability_presence_eval.json` / `.csv`。

### 3. 模块二的总体输入 / 输出接口

- **输入**：
  - 模块一产物：`llm-hunk-analysis.md`、`version-diff/`、`trace-diff-summary.txt`、`execution-observations.json` 等；
  - 批次级元数据：`batch-summary.json`、每个 case 的 `case-result.json`、`llm-scenario.json`；
  - 真值 Excel：`dataset/execution_result.xlsx`（仅用于评估）。

- **输出**：
  - Case 层：`analysis/llm-hunk-judgments.json`、`analysis/llm-vulnerability-judgment.json`；
  - 数据集层：`dataset/llm_hunk_analysis.json` / `.csv`、`dataset/llm_vulnerability_presence_eval.json` / `.csv`；
  - 核心字段：
    - `final_failure_reason`：`vulnerability_not_present` / `exploit_invalid_due_to_version_change` / `undetermined`；
    - `vulnerability_presence_verdict`、`vulnerability_presence_score`；
    - `fix_evidence_strength`、`exploit_breakage_evidence_strength`。

---

## 模块三：Excel 版本链回溯与 full-coverage 推理

### 1. 模块目标

- 前两步已经在 Excel 中为部分 `(CVE, Version)` 写入了 `LLM_Verdict`：
  - difftrace + LLM 回填：`affected_intro` / `not affected_intro`；
  - patch 分析：`affected_patch` / `not affected_patch`；
  - unknown 边界推理：补充部分 intro/patch 标签；
- **模块三的目标**是：在这些"种子标签"基础上，只利用每个 CVE 自身的版本序列信息，
  - 在 Excel 中对同一 CVE 的其他版本进行前向/后向推理；
  - 尽可能填满剩余的 `No_Data`，给出一致的 `affected` / `not affected` 判定；
  - 这是论文意义上的"版本链回溯 / 回溯填充"步骤。

> 注意：在当前实现里，这一模块对应的脚本**有且只有** `result_analysis_full_coverage.py` 中的填充与传播逻辑。

### 2. 核心脚本与函数

- **脚本 `result_analysis_full_coverage.py`**

  - **输入**：
    - `dataset/execution_result.xlsx`：
      - 已经由前置步骤写入：
        - difftrace 最终评估结果（intro 回填）；
        - `patch_analysis.py` 产生的 patch 边界标签；
        - `unknown_infer.py` 对未覆盖行的 intro/patch 边界推理；
      - 其中 `LLM_Verdict` 列包含：`affected_intro`、`not affected_intro`、`affected_patch`、`not affected_patch`、`
        affected`（兜底）以及剩余 `No_Data`。

  - **区域划分（版本链上的"最小回溯单元"）**：
    - 脚本显式定义了一个 `region_key(idx)`：
      - `region_key = (CVE_ID, Library, Execution bucket, PoC)`；
      - 其中 Execution bucket 只区分两类：
        - `APPEARS`（PoC 执行结果为 APPEARS）；
        - `OTHER`（所有非 APPEARS 的情况）；
    - **任何标签的前向/后向传播都被限制在同一个 `region_key` 内**，防止不同 PoC / 不同执行行为之间的交叉污染。

  - **步骤 0：APPEARS + No_Data → 直接视为 affected**
    - 对所有行：
      - 如果 `LLM_Verdict == "No_Data"` 且 `Execution Result == "APPEARS"`，
      - 直接将该行为 `LLM_Verdict = "affected"`；
    - 直观含义：
      - PoC 在该版本上已经观察到 APPEARS（复现成功），即便 difftrace/patch/unknown 尚未给出 intro/patch 边界，
      - 也可以直接认为该版本"仍受影响"，视为阳性兜底标签。

  - **步骤 1：not affected_* 的单向传播（填充更多阴性结论）**
    - **1.1 `not affected_patch` 向下扩张**：
      - 自上而下遍历 Excel 行：
        - 若当前行为 `LLM_Verdict == "No_Data"`，
        - 且上一行在**同一 region** 且 `LLM_Verdict == "not affected_patch"`，
        - 则当前行被填充为 `"not affected_patch"`；
    - **1.2 `not affected_intro` 向上扩张**：
      - 自下而上遍历：
        - 若当前行为 `LLM_Verdict == "No_Data"`，
        - 且下一行在同一 region 且 `LLM_Verdict == "not affected_intro"`，
        - 则当前行被填充为 `"not affected_intro"`；
    - 直观理解：
      - 一旦发现某个版本在"引入前"或"补丁后"明确是 `not affected_*`，
      - 就可以在相邻版本的局部链段内向前/向后扩张"安全区间"。

  - **步骤 2：affected_* 的双向传播（full-coverage 正类回溯）**
    - **2.1 `affected_patch` 在同一区域内向下、向上扩张**：
      - 先从上到下，再从下到上各做一遍：
        - 当前行为 `No_Data`，且相邻行在同一 region 且为 `affected_patch`，
        - 则当前行填充为 `affected_patch`；
    - **2.2 `affected_intro` 在同一区域内向上、向下扩张**：
      - 同样采用自下而上 + 自上而下两遍：
        - 对 `No_Data` 且相邻行为 `affected_intro` 的行进行填充；
    - 直观理解：
      - 一旦确认某个版本是在"漏洞引入段（intro）"或"补丁段（patch）"处为 `affected_*`，
      - 在同一 `region_key` 的相邻版本上，可以向两侧扩展其影响区间，
      - 从而尽可能消灭 `No_Data`，达到 full-coverage。

  - **步骤 3：对齐真值，计算 `Aligned_llm` 与整体指标**
    - 在完成传播后，脚本：
      - 重新计算 `Aligned_llm`：
        - `T`（预测与 `True Affected Version` 同号）、`FN`、`FP`、`TN` 四类；
      - 统计：
        - `TP`、`FP`、`FN`、`TN`；
        - Precision、Recall、Accuracy、F1；
      - 将更新后的整表写回 `execution_result.xlsx`。
    - 在论文语境中，这一步给出的是：
      - 在 **"先有部分高质量 intro/patch 种子标签，再做版本链回溯填充"** 的设定下，
      - 整体检测器在全集上的最终表现（full-coverage 口径）。
  - **LLM 扩张判断层（可选、诊断用）**
    - 实现上，`result_analysis_full_coverage.py` 额外叠加了一个基于 LLM 的扩张判断子模块：当 `affected_intro` / `affected_patch` 的传播跨越不同 `Execution Result` bucket（`APPEARS` vs `OTHER`）时，对这些潜在边界点调用 `hypothetical_llm_score(row, neighbor_version)`，让模型结合单行 Excel 上下文与相邻版本信息给出一个 `refinement_score`，并将结果写入诊断列 `LLM_Refinement_Score` / `LLM_Refinement_Decision`。
    - 当前实验配置中，这一层仅用于辅助分析与可视化，不参与标签传播决策本身；通过环境变量 `EXCEL_ENABLE_LLM_REFINE` 控制是否实际调用外部 LLM，默认关闭时退化为常数分数的 stub，开启时可以在日志与 Excel 中观察到逐样本的 LLM 扩张判断，同时保持 full-coverage 指标与主结果一致。

### 3. 模块三的总体输入 / 输出接口

- **输入**：
  - `dataset/execution_result.xlsx`（已由前两模块和 Excel 前置步骤写入种子标签）；

- **输出**：
  - 同一 Excel 文件中更新后的：
    - `LLM_Verdict`（所有 `No_Data` 尽量被 `affected_*` / `not affected_*` / `affected` 覆盖）；
    - `Aligned_llm`（与真值对齐的评估标签）；
  - 从而得到一套 **基于版本链回溯与传播的 full-coverage 判定结果**，可直接用于论文中的整体性能与误差分析。

---

## 消融实验：模块一 failure-only 模式（ab1 pipeline）

这一小节描述已经落地的 **模块一 failure-only 消融流水线**，它在不改动任何原生脚本的前提下，只通过新增 `_ab1` 脚本复用同一批 `analysis/` 目录和真值 Excel，用于度量"仅依赖 failure excerpt 的模块一"对整体性能的影响。

- **总体思路（与 baseline 的差异）**：
  - 上游 trace 采集和 `version-diff/` 生成完全沿用 baseline：继续使用 `run_case_analysis*.py`、`run_version_regression_analysis.py` 等脚本产出 `analysis/` 目录，不做任何修改；
  - 从"LLM 选 hunk"这一步开始，切换到 ab1 流水线：初始 prompt 里只保留 PoC 在 target 版本上的 failure excerpt 和少量元信息，不再内联 trace-diff summary 或 version-diff 概览；
  - 其它能力（工作区检索、diff 上下文加载等工具）保持与 baseline 相同，由 LLM 按需调用；所有 ab1 结果写入带 `_ab1` 后缀的文件，避免覆盖 baseline。

- **LLM hunk 选择：`llm_hunk_selector_ab1.py` + `run_llm_diff_batch_ab1.py`**
  - `llm_hunk_selector_ab1.py`：
    - 复用原始 `llm_hunk_selector.py` 中的工具封装与 AutoGen glue，仅在 prompt 构造上做"failure-only" 约束：
      - `build_analysis_prompt_ab1(...)` 读取 `llm-scenario.json` 与 failure excerpt 文件（优先 `failure_excerpt_file`，否则回退到 `target-observation-excerpt.txt` / `baseline-observation-excerpt.txt`），构造只包含：
        - `scenario_type`、artifact、`baseline_version → target_version`；
        - baseline/target 执行观测摘要；
        - 以及一段截断后的 failure excerpt；
      - 明确告知模型：**没有预拼接 trace diff 或 version diff 概览**，若需要代码/patch 细节，必须主动调用 `keyword_search` / `read_file` / `load_diff_context` / `search_code_context` 工具自行检索；
      - 要求输出的 markdown 仍按 baseline 约定提供 `Diagnosis` / `Selected Hunks` / `Supporting Evidence` / `Open Questions` 四段，其中 `Selected Hunks` 优先引用 `version-diff/api-diffs` 或 `version-diff/diffs` 下的具体 diff 文件路径和原始 excerpt。
    - `run_llm_hunk_selection_ab1(...)` / `run_llm_hunk_selection_sync(...)`：
      - 和 baseline 保持相同的工具集与 round budget 逻辑（`_effective_tool_round_budget`），只是系统提示中强调这是 ab1 failure-only 设置，鼓励模型在有限轮数内尽量依赖 failure excerpt 做推理；
      - 最终在单个 case 的 `analysis/` 目录下写出 `llm-hunk-analysis_ab1.md`，并记录工具调用 transcript。
  - `run_llm_diff_batch_ab1.py`：
    - 作为 ab1 的 batch 驱动脚本，读取某次 seek-patch batch 的 `batch-summary.json`，按 `status ∈ {trace_diff, execution_failure}` 过滤出 failure-only 子集（`--status-filter` 可配置，默认 `trace_diff,execution_failure`）；
    - 支持 `--limit` + `--random-seed` 对 case 列表打乱并采样子集，以便做小规模抽样实验；
    - 对每个满足条件的 case，加载其 `analysis_root` 和 `llm-scenario.json`，调用 `run_llm_hunk_selection_sync(...)` 生成 `llm-hunk-analysis_ab1.md`（如已有且未加 `--force` 则跳过），失败时写入配套的 `llm-hunk-analysis_ab1.error.txt`。

- **聚合与标签压缩：`aggregate_llm_diff_results_ab1.py` + `evaluate_llm_vulnerability_detection_ab1.py`**
  - `aggregate_llm_diff_results_ab1.py`：
    - 复用 baseline `aggregate_llm_diff_results.py` 的解析与聚合逻辑，只是改读 ab1 的 markdown 文件名和输出路径：
      - 从每个 case 的 `llm-hunk-analysis_ab1.md` 中解析 `Final response`，提取 `Selected Hunks` 并构造结构化 `selected_hunks` / `hunk_payloads`；
      - 调用同一套 case-level LLM 判定逻辑，生成 `llm-vulnerability-judgment.json` 并汇总到 ab1 版本的 `dataset/llm_hunk_analysis_ab1.json` / `.csv`；
      - 保持 hunk 层与 case 层字段完全对齐 baseline，便于后续直接复用评估脚本。
  - `evaluate_llm_vulnerability_detection_ab1.py`：
    - 调用 baseline `evaluate_llm_vulnerability_detection.py` 中的工具函数（如 `load_llm_entries`、`infer_predicted_label`），但固定输入为 `llm_hunk_analysis_ab1.json` / `execution_result.xlsx`，输出为带 `_ab1` 后缀的评估文件：
      - `dataset/llm_vulnerability_presence_eval_ab1.json` / `.csv`；
    - 使用与 baseline 相同的两阈值 `score_no_threshold` / `score_yes_threshold` 和规则层逻辑，只是作用在 ab1 的 entries 上，从而实现"仅模块一不同、模块二完全相同"的 fair 对比。

- **Excel 全集评估补充链路：`run_excel_pipeline_with_difftrace_ab1.py`**
  - `run_excel_pipeline_with_difftrace_ab1.py` 复用 baseline Excel 管道中的关键函数：
    - 从 `llm_vulnerability_presence_eval_ab1.json` 反推出一个 case-level `details` 列表，并通过 `aggregate_difftrace_predictions(...)` 聚合到 `(CVE_ID, Version)` 级别；
    - 先将 baseline 的 `dataset/execution_result.xlsx` 复制为 `dataset/execution_result_ab1.xlsx`，然后在 ab1 副本上调用 `apply_difftrace_predictions_to_excel(...)` 作为 intro 回填替代步骤；
    - 通过设置 `os.environ["EXCEL_FILE"] = execution_result_ab1.xlsx` 并在运行时覆盖 `settings.EXCEL_FILE`，在**不修改任何原生脚本源码**的前提下，依次调用：
      - `refresh.update_excel_verdict()`（重置 ab1 Excel 中的 `LLM_Verdict` 为 `No_Data`）；
      - `patch_analysis.main()`（固定阈值 0.3 的 patch-only 判定回填到 ab1 Excel）；
      - `result_analysis_full_coverage.main()`（在 ab1 Excel 上执行 full-coverage 版本链传播与指标计算）。
  - 整条 ab1 Excel 链路的最终结果仅写回 `execution_result_ab1.xlsx`，包括：
    - difftrace_ab1 + patch + full-coverage 传播后的 `LLM_Verdict` / `Aligned_llm`；
    - 一套完整的 TP/FP/FN/TN + Accuracy/Precision/Recall/F1 指标；
    - 原始 `execution_result.xlsx` 和原生 `run_excel_pipeline_with_difftrace.py` / `result_analysis_full_coverage.py` 脚本不会被修改。

- **整体调用链对比（模块一 baseline vs ab1）**：
  - **Baseline（模块一正常）**：
    - `python code/difftrace/demo/scripts/run_llm_diff_batch.py --batch-summary <...>`
    - → `aggregate_llm_diff_results.py` → `evaluate_llm_vulnerability_detection.py`
    - → `run_excel_pipeline_with_difftrace.py --result-analysis-mode full-coverage`
  - **模块一 failure-only 消融（ab1）**：
    - `python code/difftrace/demo/scripts/ab1/run_llm_diff_batch_ab1.py --batch-summary <...>`
    - → `aggregate_llm_diff_results_ab1.py` → `evaluate_llm_vulnerability_detection_ab1.py`
    - → `run_excel_pipeline_with_difftrace_ab1.py`（仅写 `execution_result_ab1.xlsx`）
  - 两条链路共享相同的 `analysis/` 目录、真值 Excel 与评估规则，只在模块一的"输入信息量"和 case 选择上做最小化差异，从而将 ab1 的性能差异更直接地归因到"failure-only 的模块一"。

## 消融实验：模块二 evidence / rule 模块（ab2 设计）

这一小节先从"模块结构"的角度讨论 ab2 要消融哪些组件，并约定参数化开关，**暂不要求代码已经完全实现**。目标是把模块二拆成两个可独立关掉的子模块：
- 上游的 **Diff 自检索/证据选择模块**；
- 下游的 **规则聚合模块**（把 LLM 输出压缩成 `affected / not affected / unknown`）。

### 1. 消融点 A：移除 Diff 自检索模块（随机 diff 样本）

- **baseline 行为回顾**：
  - 模块一中，`llm_hunk_selector.py` 提供了 `search_code_context(...)` / `search_version_diff_context(...)` 等工具，LLM 会基于 trace / failure 关键词主动检索 `version-diff/` 下的类/方法，然后在 `Final response` 的 `Selected Hunks` 段落里给出少量它认为"最相关"的 diff。
  - 模块二中，`aggregate_llm_diff_results.py` 把这些 `Selected Hunks` 解析成 `selected_hunks` / `hunk_payloads`，再交给下游的单 hunk 判定与整体漏洞判定逻辑。
- **ab2-A 目标**：
  - **关掉"基于搜索+推理的 diff 自检索能力"**，改为在同一 `version-diff/` 空间里**随机选取若干 diff 样本**作为证据；
  - 这样可以从反方向度量"精确检索 + LLM 选 hunk"本身贡献了多少性能提升。
- **实现思路（设计层面）**：
  - 在模块二聚合脚本（比如 `aggregate_llm_diff_results.py`）上增加一个参数：
    - `--evidence-mode={baseline,random}`，默认 `baseline`：
      - `baseline`：按现有逻辑，优先使用 `Selected Hunks` 中的路径；
      - `random`：忽略 `Selected Hunks`，从 `analysis/version-diff/api-diffs/` 与 `analysis/version-diff/diffs/` 中枚举所有 diff 文件，并从中**随机抽样 3 个**（固定样本数便于与其它设置对比）。
  - 抽样细节：
    - 抽样单位可以是"类级 diff 文件"（每个 `*.diff` 视为一个 evidence）；
    - 用固定随机种子（例如 `--random-seed` 参数）保证实验可复现；
    - 对于没有任何 diff 的 case，直接跳过或打标 `no_diff_evidence`，不纳入 ab2-A 的统计。
- **实验输出约定**：
  - 在 JSON 层标记本次 run 的 evidence 模式：`"evidence_mode": "random" | "baseline"`；
  - 为便于论文引用，也可以约定文件名后缀，例如：
    - `dataset/llm_hunk_analysis_ab2_evidence-random.json`；
    - `dataset/llm_hunk_analysis_ab2_evidence-random.csv`。

### 2. 消融点 B：取消规则模块（LLM-only 判定）

- **baseline 行为回顾**：
  - 模块二的规则层主要集中在两个位置：
    - `aggregate_llm_diff_results.py` 中的 `infer_final_judgment(...)`：结合 hunk-level judgment、trace 质量信号、场景类型，对 LLM 的原始判断做加权与修正；
    - `evaluate_llm_vulnerability_detection.py` 中的 `infer_predicted_label(...)`：结合 `vulnerability_presence_score`、`vulnerability_presence_verdict`、trace 信号与 `failure_subtype`，把细粒度判断压缩成 `affected/not affected/unknown`。
  - 这使得最终标签并不是"裸 LLM"，而是"LLM + 一层较厚的规则修正"的结果。
- **ab2-B 目标**：
  - 在模块二层面**完全取消规则修正**，让最终评估尽量接近"纯 LLM 输出"的表现，用于度量规则层的增益。
- **实现思路（设计层面）**：
  - 在聚合脚本中保留一个判定后端参数，例如：
    - `--judgment-mode={hybrid,rule_only,llm_only}`（命名可讨论），默认 `hybrid`：
      - `hybrid`：沿用当前逻辑——优先使用 case-level LLM judgment，缺失时 fallback 到 rule；
      - `rule_only`：完全忽略 case-level LLM judgment，只依赖 `infer_final_judgment(...)` 的规则打分；
      - `llm_only`：完全忽略 `infer_final_judgment(...)` 的输出，直接把 case-level LLM judgment 作为最终 judgment，并在评估阶段用简单统一的阈值映射到 `affected/not affected/unknown`：
        - 例如：`score >= score_yes_threshold → affected`；
        - `score <= score_no_threshold → not affected`；
        - 中间区域 → `unknown`，不再额外考虑 trace 质量或场景类型。
  - 在评估脚本 `evaluate_llm_vulnerability_detection.py` 中：
    - 增加一个 `--prediction-backend={baseline,llm_only}` 开关：
      - `baseline`：调用现有 `infer_predicted_label(...)`；
      - `llm_only`：直接用上面简单阈值法对 `vulnerability_presence_score` 做三元分类，不再读取 trace 信号。
- **实验输出约定**：
  - 在 JSON 层增加字段 `"judgment_mode"` / `"prediction_backend"`，准确记录本次 run 是否为 LLM-only；
  - 或者按约定输出到不同文件名，例如：
    - `dataset/llm_vulnerability_presence_eval_ab2_llm-only.json` / `.csv`。

### 3. 组合实验与 ab2 的整体定义

在论文层面，可以把 ab2 理解为"围绕模块二的 evidence 与 rule 两个子模块的消融实验集合"，典型组合包括：

- **Baseline**：
  - `evidence_mode = baseline`；
  - `judgment_mode = hybrid` / `prediction_backend = baseline`；
  - 对应当前实现（精确 diff 检索 + LLM + 规则修正）。
- **ab2-A：随机 diff evidence（去掉 Diff 自检索）**：
  - `evidence_mode = random`；
  - `judgment_mode = hybrid` / `prediction_backend = baseline`；
  - 用于度量"只看随机 diff 样本 + 完整规则层"时的性能。
- **ab2-B：LLM-only 判定（去掉规则模块）**：
  - `evidence_mode = baseline`；
  - `judgment_mode = llm_only` / `prediction_backend = llm_only`；
  - 用于度量"保留精确 diff 选择，但完全依赖 LLM 输出"的性能。
- **（可选）ab2-A+B：随机 diff + LLM-only 极端基线**：
  - `evidence_mode = random`；
  - `judgment_mode = llm_only` / `prediction_backend = llm_only`；
  - 作为一个"几乎不利用结构化先验"的极端对照组。

上述四种设置都可以复用同一套脚本，通过参数组合和结果文件命名区分不同实验，不需要复制代码逻辑。等后续真正落地实现时，只需按这里的参数约定在 `aggregate_llm_diff_results.py` / `evaluate_llm_vulnerability_detection.py` 中加上对应的开关与字段。

## 消融实验：模块三版本链传播（ab3 设计）

- **目标**：在不改动 difftrace + Excel 前 4 步（`refresh.py` / difftrace 回填 / `patch_analysis.py` / `unknown_infer.py`）的前提下，**只关掉模块三中"full-coverage 版本链传播"这一步**，度量 `result_analysis_full_coverage.py` 的前向/后向扩张规则本身带来的增益。
- **Baseline（full-coverage 配置）**：
  - 在 `run_excel_pipeline_with_difftrace.py` 中使用：
    - `--result-analysis-mode full-coverage`；
  - 内部最后一步会调用 `code/result_analysis_full_coverage.py`：在 Excel 里允许 `affected_intro` 向上传递、`affected_patch` 向下传递，并对 `No_Data` 进行更激进的版本链填充。
- **ab3（无 full-coverage 传播的"普通版本"）**：
  - 使用完全相同的 difftrace 批次输出 + `execution_result.xlsx`，运行：
    - `python code/difftrace/demo/scripts/run_excel_pipeline_with_difftrace.py --difftrace-eval-json <eval_json 或 --difftrace-batch-root <batch_dir>> --result-analysis-mode default`
  - 该模式下总控脚本会在前 4 步保持不变的情况下，**将最后一步切换为调用 `code/result_analysis.py`**：
    - 只保留基础的规则：`APPEARS + No_Data → affected`，以及少量在同一 CVE / Library 内的单向 intro/patch 继承；
    - 不再启用 `result_analysis_full_coverage.py` 中按 `(CVE_ID, Library, Execution bucket, PoC)` 划分区域的双向扩张逻辑，也不再做任何跨版本 full-coverage 传播。
- **实验读法**：
  - ab3 与 baseline 使用同一份 `llm_vulnerability_presence_eval.json`（或同一批 difftrace 结果），只通过 `--result-analysis-mode {default, full-coverage}` 切换模块三的传播策略；
  - 两种模式输出的 `execution_result.xlsx` 只在模块三传播策略不同，其余步骤完全一致，便于在论文中把"版本链回溯/传播"的贡献单独拆出来。

## 实验三：CWE 维度方法对比

在实验一的整体评估基础上，实验三从 CWE（Common Weakness Enumeration）维度进一步对比四种方法在不同漏洞类型上的检测能力。

### 1. 实验目标

- 验证 DiffTrace（PoB）相较于 PoC 执行、VSZZ、LLM4SZZ 三种基线方法，是否在各类 CWE 上均保持优势，还是仅对特定漏洞类型有效；
- 通过按 CWE 分组的 Precision/Recall/F1 指标，揭示不同方法在不同漏洞类型上的偏置与局限。

### 2. 数据与分组

- **数据源**：`dataset/list/cve_list_v2.json`（提供每个 CVE 的 CWE 标签）+ `dataset/execution_result.xlsx`（提供真值与四种方法的预测标签）；
- **真值设定**：以 `True Affected Version` 列为真值，`affected` 为正类，`not affected` 为负类；
- **No_Data 处理**：各方法预测中的 `No_Data` 统一视为 `not affected`（阴性预测）；
- **CWE 分组**：统计所有 CVE 的主 CWE（取 `cwe` 列表的首项），按出现频次取前 10 个 CWE，其余归入 `others` 组。

### 3. 四种方法的预测映射

| 方法简称 | Excel 列名 | 正类映射规则 | 负类映射规则 |
|---------|-----------|------------|------------|
| PoB | `LLM_Verdict` | 包含 `affected`（含 `affected_intro` / `affected_patch`） | 包含 `not affected` 或 `No_Data` |
| PoC | `Execution Result` | `APPEARS` | 非 `APPEARS` |
| vszz | `vszz_verdict` | `affected` | `not affected` 或空值 |
| llm | `llm4szz_verdict` | `affected` | `not affected` 或空值 |

### 4. 评估指标

- 对每个 CWE 组，以 `affected` 为正类，计算 Precision / Recall / F1；
- 输出为转置形式的 CSV（`dataset/cwe_cnt.csv`）：行名为 `方法_指标`（如 `PoB_Precision`），列名为各 CWE 标签及 `others`。

### 5. 实现脚本

- **脚本**：`code/difftrace/demo/scripts/cwe_cnt.py`
- **输入**：`dataset/list/cve_list_v2.json`、`dataset/execution_result.xlsx`
- **输出**：`dataset/cwe_cnt.csv`（转置形式，第一列为 `Metric`，后续列为各 CWE 标签及 `others`）

## Discussion：LLM 成本与可扩展性

- **Excel 全集评估补充链路的 LLM 成本**：在 `EXCEL_ENABLE_LLM_REFINE=1`、使用 `deepseek-v3` 作为精修模型的配置下，我们对 `run_excel_pipeline_with_difftrace.py --result-analysis-mode full-coverage` 的一次完整运行记录了 `result_analysis_full_coverage.py` 中 `hypothetical_llm_score(...)` 所有调用的 usage 日志。统计结果显示，Excel 高阈值精修阶段一共触发了 **96 次 LLM 调用**，累计消耗 **14649 个 prompt tokens、1464 个 completion tokens、合计 16113 个 tokens**，平均每次调用约 168 个 tokens。这一成本量级相较于模块一/模块二在 difftrace 主链路中的 token 使用仍然可控，且当前精修阶段仅作为诊断与可视化用途，不参与标签传播决策本身，因此在论文叙述中可以将其视为对主检测器性能的一个**低额附加成本**，而非新的主要开销来源。
- **模块一+二 LLM 分析链在样本上的成本估算**：在 `code/difftrace/demo/target/seekpatch_only_20260418_150218/batch-summary.json` 中，以 `status ∈ {trace_diff, execution_failure}` 的 163 个 case 为母体，随机抽样 23 个 case（固定随机种子）并在 difftrace baseline 配置下重跑模块一 dynamic prompting 与模块二的 per-hunk / case-level judgment，对所有非 `excel_refine` 的 LLM 调用记录 usage。统计显示，这 23 个 case 共触发 **75 次 hunk_selection_* 调用、66 次 hunk_judgment 调用和 23 次 vulnerability_judgment 调用**，累计消耗 **模块一 256342 个 tokens、模块二 260096 个 tokens、合计 516438 个 tokens**，折算为平均每个 case 约 \(2.25\times 10^4\) 个 tokens。在论文层面，我们据此将 difftrace 主分析链在真实数据集上的 LLM 成本量级刻画为“每个问题约 2 万级 token”，并与仅用于诊断的 Excel 精修成本（约 1.6 万 token / 全集）区分开来。

## 总结

- **模块一**：将 PoC 的跨版本执行行为、trace 差异与版本 diff 汇聚起来，并通过 LLM + 工具调用，从中选出少量利用相关 diff hunk；
- **模块二**：在这些 diff / 证据的基础上，给出"漏洞是否仍存在"和"利用为何失效"的结构化判定，并与 Excel 真值对齐评估；
- **模块三**：在 Excel 中以 `result_analysis_full_coverage.py` 为核心（baseline 配置），基于已有的 intro/patch/兜底标签，对同一 CVE 的版本链进行前向/后向传播与回溯填充，得到 full-coverage 的 `affected` / `not affected` 判定；消融 3 通过切换到 `result_analysis.py`（`--result-analysis-mode default`）关掉这一步的 full-coverage 传播，用作对照。
