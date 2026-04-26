import json
from pathlib import Path
from collections import Counter, defaultdict

BASE = Path('/home/xinweimao/alv_evaluate/myResearch/workspace')
CVE_LIST_PATH = BASE / 'dataset/list/cve_list_v2.json'
BATCH_SUMMARY_PATH = Path('/data-1/xinweimao/code/difftrace/demo/target/seekpatch_only_20260416_103100/batch-summary.json')
STAGEB_EVAL_PATH = BASE / 'code/difftrace/demo/target/seekpatch_only_20260416_103100/llm-stageb-full-20260417-160346/llm_vulnerability_presence_eval_llminfer_new2.json'


def load_json(path: Path):
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)


def build_cve_pair_index(cve_payload: dict):
    """索引 cve_list_v2.json，方便按 (cve_id, baseline, target) 查找 version_pair.

    返回:
      pair_index[(cve_id, baseline, target)] = {
          'meta': version_pair_obj,
          'appears_side': 'baseline' or 'target',
      }
    只收錄 seek_patch == False 的 pair，因為本批 selection_mode 就是 seek-patch-false。
    """
    index = {}
    for cve_id, meta in cve_payload.items():
        for vp in meta.get('version_pair', []):
            if not vp.get('seek_patch'):
                appears = vp.get('appears')
                not_appears = vp.get('not appears')
                # baseline=appears, target=not_appears
                index[(cve_id, appears, not_appears)] = {
                    'meta': vp,
                    'appears_side': 'baseline',
                }
                # baseline=not_appears, target=appears
                index[(cve_id, not_appears, appears)] = {
                    'meta': vp,
                    'appears_side': 'target',
                }
    return index


def map_observation(obs: str):
    """把 execution_observation 映射為簡單語義: fail / success / other."""
    if not obs:
        return 'other'
    obs = obs.strip().lower()
    if obs == 'test_failure':
        return 'fail'
    if obs == 'success':
        return 'success'
    return 'other'


def main():
    print(f'Loading cve list from: {CVE_LIST_PATH}')
    cve_payload = load_json(CVE_LIST_PATH)

    print(f'Loading batch summary from: {BATCH_SUMMARY_PATH}')
    batch = load_json(BATCH_SUMMARY_PATH)
    cases = batch.get('cases', [])
    by_case_id = {c['case_id']: c for c in cases}

    print(f'Loading StageB eval from: {STAGEB_EVAL_PATH}')
    stageb = load_json(STAGEB_EVAL_PATH)
    details = stageb.get('details', [])

    # 構建 (cve_id, baseline, target) -> seek_patch=false pair 的索引
    pair_index = build_cve_pair_index(cve_payload)

    # 統計
    total_unknown = 0
    total_unknown_with_pair = 0
    total_unknown_with_batch = 0

    category_counts = Counter()
    # 收集少量示例
    examples = defaultdict(list)

    missing_cve_pair = []
    missing_batch_case = []

    for d in details:
        verdict = (d.get('vulnerability_presence_verdict') or '').strip().lower()
        pred_label = (d.get('predicted_label') or '').strip().lower()
        if verdict != 'unknown' and pred_label != 'unknown':
            continue
        total_unknown += 1

        case_id = d.get('case_id')
        cve_id = d.get('cve_id')
        baseline_version = d.get('baseline_version')
        target_version = d.get('target_version')

        batch_case = by_case_id.get(case_id)
        if not batch_case:
            missing_batch_case.append(case_id)
            continue
        total_unknown_with_batch += 1

        key = (cve_id, baseline_version, target_version)
        pair_meta = pair_index.get(key)
        if not pair_meta:
            missing_cve_pair.append({'case_id': case_id, 'cve_id': cve_id,
                                     'baseline_version': baseline_version,
                                     'target_version': target_version})
            continue
        total_unknown_with_pair += 1

        appears_side = pair_meta['appears_side']
        baseline_obs = batch_case.get('baseline_execution_observation')
        target_obs = batch_case.get('target_execution_observation')

        if appears_side == 'baseline':
            appears_obs = baseline_obs
            not_appears_obs = target_obs
        else:
            appears_obs = target_obs
            not_appears_obs = baseline_obs

        appears_label = map_observation(appears_obs)
        not_appears_label = map_observation(not_appears_obs)

        # 類別劃分
        if appears_label == 'fail' and not_appears_label == 'success':
            cat = 'expected_opposite_correct'
        elif appears_label == 'success' and not_appears_label == 'fail':
            cat = 'direction_reversed'
        elif appears_label == 'fail' and not_appears_label == 'fail':
            cat = 'both_fail'
        elif appears_label == 'success' and not_appears_label == 'success':
            cat = 'both_success'
        else:
            cat = 'mixed_or_other'

        category_counts[cat] += 1
        if len(examples[cat]) < 10:
            examples[cat].append({
                'case_id': case_id,
                'cve_id': cve_id,
                'appears_side': appears_side,
                'appears_version': appears_obs,
                'not_appears_version': not_appears_obs,
                'baseline_version': baseline_version,
                'target_version': target_version,
                'baseline_observation': baseline_obs,
                'target_observation': target_obs,
                'scenario_type': d.get('scenario_type'),
                'status': d.get('status'),
                'failure_subtype': d.get('failure_subtype'),
            })

    print('\n=== Summary (StageB unknown verdicts, seek_patch=false pairs) ===')
    print(f'total_unknown_entries           : {total_unknown}')
    print(f'unknown_with_batch_case         : {total_unknown_with_batch}')
    print(f'unknown_with_seek_patch_false_pair: {total_unknown_with_pair}')

    print('\nCategory counts (based on appears/not_appears observations):')
    for cat, cnt in category_counts.most_common():
        print(f'  {cat:26s}: {cnt}')

    if missing_cve_pair:
        print(f"\nmissing_cve_pair entries: {len(missing_cve_pair)} (first 10)")
        for item in missing_cve_pair[:10]:
            print(' ', item)

    if missing_batch_case:
        print(f"\nmissing_batch_case entries: {len(missing_batch_case)} (first 10)")
        for cid in missing_batch_case[:10]:
            print(' ', cid)

    print('\n=== Examples by category (up to 10 each) ===')
    for cat, items in examples.items():
        print(f"\n[{cat}] ({len(items)} samples)")
        for it in items:
            print(' ', json.dumps(it, ensure_ascii=False))


if __name__ == '__main__':
    main()
