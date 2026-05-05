# ATTAIN

Automated vulnerability regression testing toolchain (based on Maven dependency tracing + version diff + LLM analysis).

## Five-Layer Toolchain Architecture

```
Version Pair Generation Layer (version_switch_unified_time_scan.py)
    ↓
Batch Scheduling Layer (run_batch_analysis.py)
    ↓
Single-Case Execution Layer (run_case_analysis_runner_fix.py / run_case_analysis.py)
    ↓
Diff / Trace / LLM Analysis Layer
    ↓
Evaluation & Auxiliary Layer
```

## End-to-End Main Workflow

### Phase A: Case-level Trace Diff

```
① version_switch_unified_time_scan.py
   Input: execution_result.xlsx, Maven release date cache, ...
   Output: dataset/list/cve_list_v2.json (unified case dataset)

② run_batch_analysis.py
   Input: cve_list_v2.json + exploit root directory
   Output: batch-summary.json, case-result.json for each case
   Dispatch mode: --selection-mode compile-false / seek-patch-false

③ run_case_analysis_runner_fix.py (default entry)
   Input: cve_list_v2.json + --cve-id + --pair-index
   Output: case-result.json, analysis/ artifacts
   Core sub-flow: materialize_case_workspace.py → run_version_regression_analysis.py
```

### Phase B: LLM Analysis Pipeline

```
④ backfill_llm_scenarios.py (fill in missing llm-scenario.json)
    ↓
⑤ run_llm_diff_batch.py (batch invocation of llm_hunk_selector.py)
   Output: llm-hunk-analysis.md
    ↓
⑥ aggregate_llm_diff_results.py
   Input: batch-summary.json + hunk analysis
   Output: dataset/llm_hunk_analysis.json / .csv
    ↓
⑦ evaluate_llm_vulnerability_detection.py
   Input: hunk analysis + execution_result.xlsx
   Output: llm_vulnerability_presence_eval.json / .csv
```

### Phase C: Excel Full Evaluation Wrap-up

```
⑧ refresh.py → (difftrace result backfill) → patch_analysis.py → unknown_infer.py → result_analysis.py
   Or one-click script: run_excel_pipeline_with_difftrace.py
   Supports --result-analysis-mode default / full-coverage
```

## Core Script Quick Reference

| Script | Responsibility |
|--------|----------------|
| `version_switch_unified_time_scan.py` | Scan versions by Maven release date, generate version_pairs |
| `run_batch_analysis.py` | Batch case selection, concurrent dispatch, aggregate batch results |
| `run_case_analysis_runner_fix.py` | Single-case execution entry, with error normalization and auto-retry |
| `materialize_case_workspace.py` | Copy exploit demo, patch pom.xml, inject dependencies |
| `run_version_regression_analysis.py` | Run baseline/target rounds, trace comparison, version diff |
| `version_diff_lib.py` | Generate api-diffs / diffs / summary.json |
| `llm_hunk_selector.py` | LLM tool-driven interaction, select most relevant diff hunk |
| `aggregate_llm_diff_results.py` | Aggregate LLM intermediate results, produce structured judgments |
| `evaluate_llm_vulnerability_detection.py` | Evaluate LLM judgment quality against ground truth |
| `run_excel_pipeline_with_difftrace.py` | Excel full evaluation wrap-up orchestration |

## Important Notes

1. Ensure `cve_list_v2.json` is up-to-date before running any case
2. LLM hunk analysis should not rely solely on `api-diffs/*.diff`; key fixes are often hidden in method/constructor context within `diffs/*.diff`
3. `cve_list_v2.json` does not guarantee an embedded `version_tree`; use `--cve` single-CVE mode to rebuild the version tree
4. Phase A and Phase B are strictly serial; merge the two `batch-summary.json` files by unique `(cve_id, pair_index)` with deduplication (recommended for 459 cases)

## Directory Structure

```
code/difftrace/demo/scripts/   ← Scripts directory
target/.../cases/<case_id>/    ← Single-case output artifacts
  analysis/
    baseline-trace.log / target-trace.log
    trace-diff-summary.json / trace-diff-summary.txt
    version-diff/ (api-diffs/, diffs/, summary.json)
    llm-scenario.json / llm-hunk-analysis.md
    llm-hunk-judgments.json / llm-vulnerability-judgment.json
dataset/
  list/cve_list_v2.json        ← Unified case dataset
  execution_result.xlsx        ← Ground truth evaluation table
  llm_vulnerability_presence_eval.json / .csv
```
