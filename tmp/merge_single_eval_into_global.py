#!/usr/bin/env python3
import json
from pathlib import Path
from collections import Counter
from math import isfinite

GLOBAL_PATH = Path('dataset/llm_vulnerability_presence_eval.json').resolve()
SINGLE_PATH = Path('/data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260416_103100/llm-stageb-single-CVE-2021-43797-20260418-060525/llm_vulnerability_presence_eval.json').resolve()

payload_global = json.loads(GLOBAL_PATH.read_text(encoding='utf-8'))
payload_single = json.loads(SINGLE_PATH.read_text(encoding='utf-8'))

g_details = list(payload_global.get('details') or [])
s_details = list(payload_single.get('details') or [])

# 用 (case_id, target_version) 做去重/替換鍵
index = {(item.get('case_id'), item.get('target_version')): i for i, item in enumerate(g_details)}
for item in s_details:
    key = (item.get('case_id'), item.get('target_version'))
    if key in index:
        g_details[index[key]] = item
    else:
        index[key] = len(g_details)
        g_details.append(item)

payload_global['details'] = g_details

# 重新計算統計字段
total_entries = len(g_details)
gt_counts = Counter()
pred_counts = Counter()
verdict_counts = Counter()
conf_counts = Counter()

total_with_truth = 0
evaluated_predictions = 0

for item in g_details:
    actual = (item.get('actual_label') or '').strip()
    if actual:
        total_with_truth += 1
        gt_counts[actual] += 1
    pred = (item.get('predicted_label') or '').strip()
    if pred:
        evaluated_predictions += 1
        pred_counts[pred] += 1
    verdict = (item.get('vulnerability_presence_verdict') or '').strip() or 'unknown'
    verdict_counts[verdict] += 1
    conf = (item.get('judgment_confidence') or '').strip().lower()
    if conf:
        conf_counts[conf] += 1

coverage = float(evaluated_predictions) / total_with_truth if total_with_truth else 0.0
if not isfinite(coverage):
    coverage = 0.0

payload_global['total_entries'] = total_entries
payload_global['total_with_truth'] = total_with_truth
payload_global['evaluated_predictions'] = evaluated_predictions
payload_global['abstained_predictions'] = max(0, total_with_truth - evaluated_predictions)
payload_global['coverage'] = coverage
payload_global['ground_truth_counts'] = dict(gt_counts)
payload_global['predicted_label_counts'] = dict(pred_counts)
payload_global['verdict_counts'] = dict(verdict_counts)
payload_global['confidence_counts'] = dict(conf_counts)

GLOBAL_PATH.write_text(json.dumps(payload_global, indent=2, ensure_ascii=False), encoding='utf-8')
print(f"merged {len(s_details)} detail(s) into {GLOBAL_PATH}")
