#!/usr/bin/env python3
import json
from pathlib import Path
from collections import defaultdict

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

    both_fail_by_cve = defaultdict(list)

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
            continue

        appears_version = pair['appears']
        not_appears_version = pair['not_appears']

        if baseline == appears_version:
            appears_side = 'baseline'
            appears_obs_raw = case.get('baseline_execution_observation')
        elif target == appears_version:
            appears_side = 'target'
            appears_obs_raw = case.get('target_execution_observation')
        else:
            continue

        if baseline == not_appears_version:
            not_appears_side = 'baseline'
            not_appears_obs_raw = case.get('baseline_execution_observation')
        elif target == not_appears_version:
            not_appears_side = 'target'
            not_appears_obs_raw = case.get('target_execution_observation')
        else:
            continue

        status = case.get('status')
        failure_subtype = case.get('failure_subtype')
        if not (status == 'execution_failure' and failure_subtype == 'test_failure'):
            continue

        appears_state = normalize_obs(appears_obs_raw)
        not_appears_state = normalize_obs(not_appears_obs_raw)
        if appears_state == 'fail' and not_appears_state == 'fail':
            both_fail_by_cve[cve_id].append({
                'case_id': case.get('case_id'),
                'appears_version': appears_version,
                'appears_side': appears_side,
                'appears_observation': appears_state,
                'not_appears_version': not_appears_version,
                'not_appears_side': not_appears_side,
                'not_appears_observation': not_appears_state,
            })

    selected = []
    for cve_id in sorted(both_fail_by_cve.keys()):
        if len(selected) >= 5:
            break
        cases_for_cve = both_fail_by_cve[cve_id]
        if not cases_for_cve:
            continue
        selected.append({'cve_id': cve_id, 'sample_case': cases_for_cve[0]})

    print(json.dumps({'selected_both_fail_samples': selected}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
