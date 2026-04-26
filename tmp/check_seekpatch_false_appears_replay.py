#!/usr/bin/env python3
import json
from pathlib import Path
from collections import Counter, defaultdict

REPO_ROOT = Path('/home/xinweimao/alv_evaluate/myResearch/workspace').resolve()
CVE_LIST_PATH = REPO_ROOT / 'dataset' / 'list' / 'cve_list_v2.json'
BATCH_SUMMARY_PATH = Path('/data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260416_103100/batch-summary.json').resolve()


def load_cve_pairs():
    payload = json.loads(CVE_LIST_PATH.read_text(encoding='utf-8'))
    mapping = {}
    for cve_id, cve_payload in payload.items():
        pairs = cve_payload.get('version_pair') or []
        for idx, pair in enumerate(pairs):
            if not pair.get('seek_patch'):
                key = (cve_id, pair.get('appears'), pair.get('not appears'))
                mapping[key] = {
                    'cve_id': cve_id,
                    'appears': pair.get('appears'),
                    'not_appears': pair.get('not appears'),
                    'seek_patch': pair.get('seek_patch'),
                    'compile': pair.get('compile'),
                    'pair_meta': pair,
                    'pair_index': idx,
                }
    return mapping


def load_batch_cases():
    payload = json.loads(BATCH_SUMMARY_PATH.read_text(encoding='utf-8'))
    return payload.get('cases') or []


def normalize_obs(obs: str) -> str:
    obs = (obs or '').strip().lower()
    if obs == 'test_failure':
        return 'fail'
    if obs == 'success':
        return 'success'
    return f'other:{obs or "none"}'


def main():
    cve_pairs = load_cve_pairs()
    cases = load_batch_cases()

    stats = Counter()
    buckets = defaultdict(list)  # category -> list of case summaries
    unmatched_cases = []

    for case in cases:
        if case.get('seek_patch') is not False:
            continue
        cve_id = case.get('cve_id')
        baseline = case.get('baseline_version')
        target = case.get('target_version')
        key_bt = (cve_id, baseline, target)
        key_tb = (cve_id, target, baseline)

        pair = cve_pairs.get(key_bt) or cve_pairs.get(key_tb)
        if not pair:
            unmatched_cases.append({
                'case_id': case.get('case_id'),
                'cve_id': cve_id,
                'baseline_version': baseline,
                'target_version': target,
                'note': 'no seek_patch=false pair in cve_list_v2 for this (CVE, baseline, target)',
            })
            stats['unmatched'] += 1
            continue

        appears_version = pair['appears']
        not_appears_version = pair['not_appears']

        # 決定 appears / not_appears 各自在 baseline 還是 target
        if baseline == appears_version:
            appears_side = 'baseline'
            appears_obs_raw = case.get('baseline_execution_observation')
        elif target == appears_version:
            appears_side = 'target'
            appears_obs_raw = case.get('target_execution_observation')
        else:
            unmatched_cases.append({
                'case_id': case.get('case_id'),
                'cve_id': cve_id,
                'baseline_version': baseline,
                'target_version': target,
                'appears_version': appears_version,
                'note': 'appears version does not match baseline/target',
            })
            stats['appears_not_in_pair'] += 1
            continue

        if baseline == not_appears_version:
            not_appears_side = 'baseline'
            not_appears_obs_raw = case.get('baseline_execution_observation')
        elif target == not_appears_version:
            not_appears_side = 'target'
            not_appears_obs_raw = case.get('target_execution_observation')
        else:
            unmatched_cases.append({
                'case_id': case.get('case_id'),
                'cve_id': cve_id,
                'baseline_version': baseline,
                'target_version': target,
                'not_appears_version': not_appears_version,
                'note': 'not_appears version does not match baseline/target',
            })
            stats['not_appears_not_in_pair'] += 1
            continue

        status = case.get('status')
        failure_subtype = case.get('failure_subtype')

        # 僅在 execution_failure + test_failure 這類語義明確場景下做嚴格判定
        if not (status == 'execution_failure' and failure_subtype == 'test_failure'):
            stats['non_test_failure_case'] += 1
            continue

        appears_state = normalize_obs(appears_obs_raw)
        not_appears_state = normalize_obs(not_appears_obs_raw)

        summary = {
            'case_id': case.get('case_id'),
            'cve_id': cve_id,
            'appears_version': appears_version,
            'appears_side': appears_side,
            'appears_observation': appears_state,
            'not_appears_version': not_appears_version,
            'not_appears_side': not_appears_side,
            'not_appears_observation': not_appears_state,
        }

        stats['evaluated'] += 1

        # 分類
        if appears_state == 'fail' and not_appears_state == 'success':
            category = 'expected_opposite_correct'
        elif appears_state == 'success' and not_appears_state == 'fail':
            category = 'direction_reversed'
        elif appears_state == 'fail' and not_appears_state == 'fail':
            category = 'both_fail'
        elif appears_state == 'success' and not_appears_state == 'success':
            category = 'both_success'
        else:
            category = 'mixed_or_other'

        stats[category] += 1
        buckets[category].append(summary)

    print('==== 校驗結果 (seek_patch=false, appears/not appears 是否呈現相反行為) ====')
    for key in sorted(stats.keys()):
        print(f'{key}: {stats[key]}')

    def dump_bucket(name: str):
        items = buckets.get(name) or []
        if not items:
            return
        print(f"\n---- {name} ({len(items)}) ----")
        for item in items:
            print(json.dumps(item, ensure_ascii=False))

    dump_bucket('direction_reversed')
    dump_bucket('both_fail')
    dump_bucket('both_success')
    dump_bucket('mixed_or_other')

    if unmatched_cases:
        print('\n---- 無法在 cve_list_v2 中對齊 version_pair 的 case 列表 (或 appears/not_appears 不在 pair 內) ----')
        for item in unmatched_cases:
            print(json.dumps(item, ensure_ascii=False))


if __name__ == '__main__':
    main()
