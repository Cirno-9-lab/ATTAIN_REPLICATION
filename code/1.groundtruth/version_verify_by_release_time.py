#!/usr/bin/env python3

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.dirname(SCRIPT_DIR)
WORKSPACE_DIR = os.path.dirname(CODE_DIR)
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from utils import get_release_history, normalize_version  # noqa: E402


DEFAULT_EXCEL_PATH = os.path.join(WORKSPACE_DIR, "dataset", "execution_result.xlsx")
DEFAULT_GHREPO_PATH = os.path.join(WORKSPACE_DIR, "dataset", "cve_ghrepo.json")
DEFAULT_MVN_TEST_DIR = os.path.join(WORKSPACE_DIR, "dataset", "mvn_test")
DEFAULT_OUTPUT_PATH = os.path.join(WORKSPACE_DIR, "dataset", "cve_critical_version_by_release_time.json")
DEFAULT_CACHE_PATH = os.path.join(WORKSPACE_DIR, "dataset", "maven_release_history_cache.json")


REPAIR_LABELS = {"not affected", "fixed", "patched", "unaffected"}
AFFECTED_LABELS = {"affected", "vulnerable"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="按 Maven 发布时间重排 execution_result.xlsx 中的版本，并重新生成真正需要分析的相邻版本对。"
    )
    parser.add_argument("--excel", default=DEFAULT_EXCEL_PATH, help=f"输入 Excel，默认 {DEFAULT_EXCEL_PATH}")
    parser.add_argument("--ghrepo-json", default=DEFAULT_GHREPO_PATH, help=f"CVE 元信息 JSON，默认 {DEFAULT_GHREPO_PATH}")
    parser.add_argument("--mvn-test-dir", default=DEFAULT_MVN_TEST_DIR, help=f"包含每个 CVE 的 Maven 坐标 JSON 目录，默认 {DEFAULT_MVN_TEST_DIR}")
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_PATH, help=f"输出 JSON，默认 {DEFAULT_OUTPUT_PATH}")
    parser.add_argument("--cache-json", default=DEFAULT_CACHE_PATH, help=f"Maven 发布时间缓存 JSON，默认 {DEFAULT_CACHE_PATH}")
    parser.add_argument("--cve", action="append", help="仅处理指定 CVE，可多次传入")
    parser.add_argument("--refresh-cache", action="store_true", help="忽略本地缓存，重新拉取 Maven 发布时间")
    return parser.parse_args()


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, payload) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def load_repo_mapping(json_path: str) -> Dict[str, Dict[str, str]]:
    raw = load_json(json_path, {})
    mapping: Dict[str, Dict[str, str]] = {}
    if not isinstance(raw, dict):
        return mapping
    for cve_id, info in raw.items():
        if not isinstance(info, dict):
            continue
        mapping[cve_id] = {
            "owner": info.get("owner", "unknown"),
            "repo_name": info.get("repo", "unknown"),
            "description": info.get("description", ""),
        }
    return mapping


def load_gav_mapping(mvn_test_dir: str, cve_filter: Optional[set[str]] = None) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not os.path.isdir(mvn_test_dir):
        return mapping
    for name in sorted(os.listdir(mvn_test_dir)):
        if not name.endswith(".json"):
            continue
        cve_id = name[:-5]
        if cve_filter and cve_id not in cve_filter:
            continue
        payload = load_json(os.path.join(mvn_test_dir, name), {})
        gav = str(payload.get("gav") or "").strip()
        if gav:
            mapping[cve_id] = gav
    return mapping


def parse_gav_from_description(description: str) -> Optional[str]:
    if not description:
        return None
    marker = "package "
    lower = description.lower()
    idx = lower.find(marker)
    if idx == -1:
        return None
    tail = description[idx + len(marker):].split()[0].strip().rstrip(",.;")
    if ":" in tail:
        return tail
    return None


def resolve_gav(cve_id: str, repo_map: Dict[str, Dict[str, str]], gav_map: Dict[str, str]) -> Optional[str]:
    gav = gav_map.get(cve_id)
    if gav:
        return gav
    description = repo_map.get(cve_id, {}).get("description", "")
    return parse_gav_from_description(description)


def load_history_cache(path: str) -> Dict[str, List[Dict[str, str]]]:
    raw = load_json(path, {})
    if not isinstance(raw, dict):
        return {}
    cache: Dict[str, List[Dict[str, str]]] = {}
    for gav, entries in raw.items():
        if not isinstance(entries, list):
            continue
        normalized_entries = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            version = str(entry.get("version") or "").strip()
            release_date = str(entry.get("release_date") or "").strip()
            if version and release_date:
                normalized_entries.append({"version": version, "release_date": release_date})
        if normalized_entries:
            cache[gav] = normalized_entries
    return cache


def save_history_cache(path: str, cache: Dict[str, List[Dict[str, str]]]) -> None:
    save_json(path, cache)


def history_from_cache_entries(entries: List[Dict[str, str]]) -> List[Dict[str, object]]:
    restored = []
    for entry in entries:
        version = str(entry.get("version") or "").strip()
        release_date = str(entry.get("release_date") or "").strip()
        if not version or not release_date:
            continue
        try:
            restored.append({"version": version, "release_date": datetime.fromisoformat(release_date)})
        except ValueError:
            continue
    return restored


def history_to_cache_entries(entries: List[Dict[str, object]]) -> List[Dict[str, str]]:
    return [
        {
            "version": str(entry["version"]),
            "release_date": entry["release_date"].isoformat(timespec="seconds"),
        }
        for entry in entries
    ]


def fetch_full_release_history(group_id: str, artifact_id: str) -> List[Dict[str, object]]:
    url = "https://search.maven.org/solrsearch/select"
    rows = 200
    start = 0
    collected = []
    seen_versions = set()
    while True:
        response = requests.get(
            url,
            params={
                "q": f"g:{group_id} AND a:{artifact_id}",
                "core": "gav",
                "rows": rows,
                "start": start,
                "wt": "json",
            },
            timeout=20,
        )
        response.raise_for_status()
        docs = response.json().get("response", {}).get("docs", [])
        if not docs:
            break
        for doc in docs:
            version = str(doc.get("v") or "").strip()
            timestamp = doc.get("timestamp")
            if not version or version in seen_versions or timestamp is None:
                continue
            seen_versions.add(version)
            collected.append(
                {
                    "version": version,
                    "release_date": datetime.fromtimestamp(timestamp / 1000.0),
                }
            )
        if len(docs) < rows:
            break
        start += rows
    return sorted(collected, key=lambda item: item["release_date"])



def get_release_history_cached(
    gav: str,
    cache: Dict[str, List[Dict[str, str]]],
    refresh_cache: bool = False,
) -> List[Dict[str, object]]:
    if not refresh_cache and gav in cache:
        restored = history_from_cache_entries(cache[gav])
        if restored:
            return restored
    group_id, artifact_id = gav.split(":", 1)
    history: List[Dict[str, object]] = []
    try:
        history = fetch_full_release_history(group_id, artifact_id)
    except Exception:
        history = get_release_history(group_id, artifact_id)
    if history:
        cache[gav] = history_to_cache_entries(history)
    return history


def is_poc_success(status) -> bool:
    return str(status).strip().upper() == "APPEARS"


def is_poc_fail(status) -> bool:
    return str(status).strip().upper() in {"BUILD_SUCCESS", "BUILD_FAILURE_OTHER"}


def get_compile_status(status) -> bool:
    normalized = str(status).strip().upper()
    if normalized == "BUILD_FAILURE_OTHER":
        return False
    return normalized in {"BUILD_SUCCESS", "APPEARS"}


def normalize_truth_label(value) -> str:
    normalized = str(value).strip().lower()
    if normalized in REPAIR_LABELS:
        return "not affected"
    if normalized in AFFECTED_LABELS:
        return "affected"
    return normalized or "unknown"


def build_release_index(history: List[Dict[str, object]]) -> Tuple[Dict[str, Dict[str, object]], Dict[str, List[Dict[str, object]]]]:
    exact = {}
    normalized = {}
    for item in history:
        version = str(item["version"]).strip()
        exact[version] = item
        normalized.setdefault(normalize_version(version), []).append(item)
    return exact, normalized


def resolve_release_entry(version: str, history: List[Dict[str, object]]) -> Optional[Dict[str, object]]:
    exact_map, normalized_map = build_release_index(history)
    candidate = exact_map.get(version)
    if candidate:
        return candidate
    normalized_version = normalize_version(version)
    matches = normalized_map.get(normalized_version, [])
    if len(matches) == 1:
        return matches[0]
    return None


def sort_rows_by_release_date(rows: List[dict], history: List[Dict[str, object]]) -> Tuple[List[dict], List[str]]:
    enriched = []
    unresolved = []
    for idx, row in enumerate(rows):
        version = str(row["version"]).strip()
        release_entry = resolve_release_entry(version, history)
        if release_entry is None:
            unresolved.append(version)
        enriched.append(
            {
                **row,
                "_original_index": idx,
                "_release_entry": release_entry,
                "_release_date": release_entry["release_date"] if release_entry else None,
                "_resolved_version": release_entry["version"] if release_entry else None,
            }
        )
    enriched.sort(
        key=lambda item: (
            item["_release_date"] is None,
            item["_release_date"] or datetime.max,
            item["_original_index"],
        )
    )
    return enriched, unresolved


def summarize_ordered_rows(rows: List[dict]) -> List[Dict[str, object]]:
    summary = []
    for row in rows:
        summary.append(
            {
                "version": row["version"],
                "release_date": row["_release_date"].isoformat(timespec="seconds") if row["_release_date"] else None,
                "true_affected_version": normalize_truth_label(row.get("true_affected_version")),
                "execution_result": row.get("execution_result"),
                "original_index": row["_original_index"],
                "resolved_maven_version": row.get("_resolved_version"),
            }
        )
    return summary


def collect_version_pairs(rows: List[dict]) -> List[Dict[str, object]]:
    version_pairs = []
    for i in range(len(rows) - 1):
        curr_row = rows[i]
        next_row = rows[i + 1]

        base_ver = str(curr_row["version"])
        head_ver = str(next_row["version"])
        res_base = curr_row["execution_result"]
        res_head = next_row["execution_result"]
        cause_base = str(curr_row.get("cause") or "")
        cause_head = str(next_row.get("cause") or "")

        pair_entry = None
        if is_poc_success(res_base) and is_poc_fail(res_head):
            is_compile = get_compile_status(res_head)
            pair_entry = {
                "appears": base_ver,
                "not appears": head_ver,
                "BASE_TAG": base_ver,
                "HEAD_TAG": head_ver,
                "seek_patch": True,
                "compile": is_compile,
                "ordering_basis": "maven_release_date",
                "baseline_release_date": curr_row["_release_date"].isoformat(timespec="seconds") if curr_row["_release_date"] else None,
                "target_release_date": next_row["_release_date"].isoformat(timespec="seconds") if next_row["_release_date"] else None,
                "baseline_truth": normalize_truth_label(curr_row.get("true_affected_version")),
                "target_truth": normalize_truth_label(next_row.get("true_affected_version")),
            }
            if not is_compile:
                pair_entry["cause"] = cause_head
        elif is_poc_fail(res_base) and is_poc_success(res_head):
            is_compile = get_compile_status(res_base)
            pair_entry = {
                "appears": head_ver,
                "not appears": base_ver,
                "BASE_TAG": base_ver,
                "HEAD_TAG": head_ver,
                "seek_patch": False,
                "compile": is_compile,
                "ordering_basis": "maven_release_date",
                "baseline_release_date": curr_row["_release_date"].isoformat(timespec="seconds") if curr_row["_release_date"] else None,
                "target_release_date": next_row["_release_date"].isoformat(timespec="seconds") if next_row["_release_date"] else None,
                "baseline_truth": normalize_truth_label(curr_row.get("true_affected_version")),
                "target_truth": normalize_truth_label(next_row.get("true_affected_version")),
            }
            if not is_compile:
                pair_entry["cause"] = cause_base

        if pair_entry:
            version_pairs.append(pair_entry)
    return version_pairs


def main() -> int:
    args = parse_args()
    cve_filter = {item.strip() for item in (args.cve or []) if str(item).strip()}

    if not os.path.exists(args.excel):
        raise SystemExit(f"找不到输入 Excel: {args.excel}")

    repo_map = load_repo_mapping(args.ghrepo_json)
    gav_map = load_gav_mapping(args.mvn_test_dir, cve_filter or None)
    history_cache = load_history_cache(args.cache_json)

    df = pd.read_excel(args.excel)
    df.columns = [str(col).strip().lower() for col in df.columns]
    df = df.dropna(subset=["cve_id", "version"])
    if cve_filter:
        df = df[df["cve_id"].astype(str).isin(cve_filter)]

    results = []
    counters = Counter()

    for cve_id, group in df.groupby("cve_id", sort=False):
        cve_id = str(cve_id).strip()
        gav = resolve_gav(cve_id, repo_map, gav_map)
        if not gav or ":" not in gav:
            counters["missing_gav"] += 1
            continue

        history = get_release_history_cached(gav, history_cache, refresh_cache=args.refresh_cache)
        if not history:
            counters["missing_release_history"] += 1
            continue

        owner = repo_map.get(cve_id, {}).get("owner", "unknown")
        repo_name = repo_map.get(cve_id, {}).get("repo_name", "unknown")
        description = repo_map.get(cve_id, {}).get("description", "")

        rows = []
        for _, row in group.iterrows():
            rows.append(
                {
                    "version": str(row["version"]).strip(),
                    "execution_result": row.get("execution result"),
                    "cause": "" if pd.isna(row.get("cause")) else str(row.get("cause")),
                    "true_affected_version": row.get("true affected version"),
                }
            )

        ordered_rows, unresolved_versions = sort_rows_by_release_date(rows, history)
        version_pairs = collect_version_pairs(ordered_rows)
        if not version_pairs:
            counters["no_boundary_pairs"] += 1
            continue

        repaired_versions = [
            item["version"]
            for item in summarize_ordered_rows(ordered_rows)
            if item["true_affected_version"] == "not affected"
        ]

        results.append(
            {
                "CVE_ID": cve_id,
                "owner": owner,
                "repo_name": repo_name,
                "artifact": gav,
                "description": description,
                "ordering_basis": "maven_release_date",
                "release_history_count": len(history),
                "release_ordered_versions": summarize_ordered_rows(ordered_rows),
                "repaired_versions_by_release_time": repaired_versions,
                "unresolved_versions": unresolved_versions,
                "version_pair": version_pairs,
            }
        )
        counters["written_entries"] += 1
        if unresolved_versions:
            counters["entries_with_unresolved_versions"] += 1

    save_json(args.output_json, results)
    save_history_cache(args.cache_json, history_cache)

    print(
        json.dumps(
            {
                "output_json": args.output_json,
                "cache_json": args.cache_json,
                "total_entries": len(results),
                "stats": dict(counters),
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
