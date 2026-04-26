#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import pandas as pd
import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.dirname(SCRIPT_DIR)
DIFFTRACE_DIR = os.path.dirname(DEMO_DIR)
CODE_DIR = os.path.dirname(DIFFTRACE_DIR)
WORKSPACE_DIR = os.path.dirname(CODE_DIR)
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from utils import get_release_history, normalize_version  # noqa: E402


DEFAULT_EXCEL_PATH = os.path.join(WORKSPACE_DIR, "dataset", "execution_result.xlsx")
DEFAULT_GHREPO_PATH = os.path.join(WORKSPACE_DIR, "dataset", "cve_ghrepo.json")
DEFAULT_MVN_TEST_DIR = os.path.join(WORKSPACE_DIR, "dataset", "mvn_test")
DEFAULT_DISCLOSED_VERSION_PATH = os.path.join(
    WORKSPACE_DIR, "code", "PoCEmpirical", "reproduce", "disclosed-version.txt"
)
DEFAULT_CACHE_PATH = os.path.join(WORKSPACE_DIR, "dataset", "maven_release_history_cache.json")
DEFAULT_ARTIFACT_LOOKUP_CACHE_PATH = os.path.join(WORKSPACE_DIR, "dataset", "maven_artifact_lookup_cache.json")
DEFAULT_OUTPUT_PATH = os.path.join(WORKSPACE_DIR, "dataset", "list", "cve_list_v2.json")

TAGS_CACHE: Dict[str, List[str]] = {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "模仿 version_switch.py 生成 cve_list_v2.json，但会先按 Maven 发布时间推断主线/分支，"
            "只在同一分支内比较相邻版本。"
        )
    )
    parser.add_argument("--excel", default=DEFAULT_EXCEL_PATH, help=f"输入 Excel，默认 {DEFAULT_EXCEL_PATH}")
    parser.add_argument("--ghrepo-json", default=DEFAULT_GHREPO_PATH, help=f"CVE 元信息 JSON，默认 {DEFAULT_GHREPO_PATH}")
    parser.add_argument("--mvn-test-dir", default=DEFAULT_MVN_TEST_DIR, help=f"mvn_test 目录，默认 {DEFAULT_MVN_TEST_DIR}")
    parser.add_argument(
        "--disclosed-version-file",
        default=DEFAULT_DISCLOSED_VERSION_PATH,
        help=f"PoC disclosed-version.txt 路径，默认 {DEFAULT_DISCLOSED_VERSION_PATH}",
    )
    parser.add_argument("--cache-json", default=DEFAULT_CACHE_PATH, help=f"Maven 发布时间缓存 JSON，默认 {DEFAULT_CACHE_PATH}")
    parser.add_argument(
        "--artifact-cache-json",
        default=DEFAULT_ARTIFACT_LOOKUP_CACHE_PATH,
        help=f"library -> artifact 候选缓存 JSON，默认 {DEFAULT_ARTIFACT_LOOKUP_CACHE_PATH}",
    )
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_PATH, help=f"输出 cve_list_v2.json，默认 {DEFAULT_OUTPUT_PATH}")
    parser.add_argument("--fork-window-days", type=float, default=1.0, help="认定为 fork/sibling variant 的时间窗口（天），默认 1.0")
    parser.add_argument("--cve", action="append", help="仅处理指定 CVE，可多次传入")
    parser.add_argument("--refresh-cache", action="store_true", help="忽略本地 Maven 发布时间缓存，重新拉取")
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN", ""), help="可选 GitHub token，用于更稳定地抓取 tags")
    parser.add_argument("--github-tag-pages", type=int, default=5, help="抓取 GitHub tags 的最大页数，默认 5")
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
        json.dump(payload, f, indent=4, ensure_ascii=False)


def load_repo_mapping(json_path: str) -> Dict[str, Dict[str, object]]:
    raw = load_json(json_path, {})
    mapping: Dict[str, Dict[str, object]] = {}
    if not isinstance(raw, dict):
        return mapping
    for cve_id, info in raw.items():
        if not isinstance(info, dict):
            continue
        mapping[str(cve_id).strip()] = {
            "owner": str(info.get("owner", "unknown") or "unknown").strip(),
            "repo_name": str(info.get("repo", "unknown") or "unknown").strip(),
            "description": str(info.get("description", "") or ""),
            "cwe": info.get("cwe") or [],
            "github_url": str(info.get("github_url", "") or ""),
        }
    return mapping


def load_gav_mapping(mvn_test_dir: str, cve_filter: Optional[set] = None) -> Dict[str, str]:
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


def get_library_from_gav(gav: str) -> str:
    gav = str(gav or "").strip()
    if ":" not in gav:
        return ""
    return gav.split(":", 1)[1].strip()


def normalize_library_key(library: str) -> str:
    return str(library or "").strip().lower()


def add_library_candidate(target: Dict[str, set], library: str, gav: str) -> None:
    library_key = normalize_library_key(library)
    gav = str(gav or "").strip()
    if not library_key or ":" not in gav:
        return
    target[library_key].add(gav)


def append_unique_value(target: Dict[str, List[str]], key: str, value: str) -> None:
    key = str(key or "").strip()
    value = str(value or "").strip()
    if not key or not value:
        return
    bucket = target[key]
    if value not in bucket:
        bucket.append(value)


def load_disclosed_metadata(path: str) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, set]]:
    cve_to_gavs: Dict[str, List[str]] = defaultdict(list)
    cve_to_libraries: Dict[str, List[str]] = defaultdict(list)
    library_to_gavs: Dict[str, set] = defaultdict(set)
    if not os.path.exists(path):
        return {}, {}, library_to_gavs
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split("\t") if part.strip()]
            if len(parts) < 2:
                continue
            gav, cve_id = parts[0], parts[1]
            if gav.count(":") < 1 or not cve_id.upper().startswith("CVE-"):
                continue
            library = get_library_from_gav(gav)
            append_unique_value(cve_to_gavs, cve_id, gav)
            if library:
                append_unique_value(cve_to_libraries, cve_id, library)
                add_library_candidate(library_to_gavs, library, gav)
    return dict(cve_to_gavs), dict(cve_to_libraries), library_to_gavs


def build_library_candidate_map(
    disclosed_library_map: Dict[str, set],
    mvn_test_map: Dict[str, str],
    history_cache: Dict[str, List[Dict[str, str]]],
) -> Dict[str, set]:
    merged: Dict[str, set] = defaultdict(set)
    for library_key, gavs in disclosed_library_map.items():
        merged[library_key].update(gavs)
    for gav in mvn_test_map.values():
        add_library_candidate(merged, get_library_from_gav(gav), gav)
    for gav in history_cache.keys():
        add_library_candidate(merged, get_library_from_gav(gav), gav)
    return merged


def parse_gav_from_description(description: str) -> Optional[str]:
    if not description:
        return None
    marker = "package "
    lower = description.lower()
    idx = lower.find(marker)
    if idx == -1:
        return None
    tail = description[idx + len(marker):].split()[0].strip().rstrip(',.;"\'“”').strip('"\'“”')
    if ":" in tail:
        return tail
    return None


def load_artifact_lookup_cache(path: str) -> Dict[str, List[str]]:
    raw = load_json(path, {})
    if not isinstance(raw, dict):
        return {}
    normalized: Dict[str, List[str]] = {}
    for library, candidates in raw.items():
        if isinstance(candidates, list):
            cleaned = sorted({str(item).strip() for item in candidates if str(item).strip().count(":") >= 1})
            if cleaned:
                normalized[normalize_library_key(library)] = cleaned
    return normalized


def save_artifact_lookup_cache(path: str, cache: Dict[str, List[str]]) -> None:
    save_json(path, {key: sorted(set(value)) for key, value in cache.items() if value})


def search_gav_candidates_by_library(library: str, cache: Dict[str, List[str]]) -> List[str]:
    library_key = normalize_library_key(library)
    if not library_key:
        return []
    if library_key in cache:
        return cache[library_key]

    url = "https://search.maven.org/solrsearch/select"
    candidates: List[str] = []
    try:
        response = requests.get(
            url,
            params={
                "q": f'a:"{library}"',
                "rows": 100,
                "wt": "json",
            },
            timeout=20,
        )
        response.raise_for_status()
        docs = response.json().get("response", {}).get("docs", [])
        seen = set()
        for doc in docs:
            group_id = str(doc.get("g") or "").strip()
            artifact_id = str(doc.get("a") or "").strip()
            if not group_id or normalize_library_key(artifact_id) != library_key:
                continue
            gav = f"{group_id}:{artifact_id}"
            if gav not in seen:
                seen.add(gav)
                candidates.append(gav)
    except Exception:
        candidates = []

    cache[library_key] = candidates
    return candidates


def choose_best_gav_candidate(
    candidates: List[str],
    observed_versions: List[str],
    history_cache: Dict[str, List[Dict[str, str]]],
    refresh_cache: bool = False,
) -> Optional[str]:
    unique_candidates = []
    seen = set()
    for candidate in candidates:
        candidate = str(candidate or "").strip()
        if not candidate or candidate in seen or ":" not in candidate:
            continue
        unique_candidates.append(candidate)
        seen.add(candidate)
    if not unique_candidates:
        return None
    if len(unique_candidates) == 1:
        return unique_candidates[0]

    observed_exact = {str(version).strip() for version in observed_versions if str(version).strip()}
    observed_normalized = {normalize_version(version) for version in observed_exact if normalize_version(version)}
    best_gav = None
    best_score = (-1, -1, -1, "")
    for candidate in unique_candidates:
        history = get_release_history_cached(candidate, history_cache, refresh_cache=refresh_cache)
        release_versions = {str(item["version"]).strip() for item in history}
        release_normalized = {normalize_version(version) for version in release_versions if normalize_version(version)}
        exact_hits = len(observed_exact & release_versions)
        normalized_hits = len(observed_normalized & release_normalized)
        score = (exact_hits, normalized_hits, len(history), candidate)
        if score > best_score:
            best_score = score
            best_gav = candidate

    if best_score[0] <= 0 and best_score[1] <= 0:
        return None
    return best_gav


def ordered_unique(values: List[str]) -> List[str]:
    ordered: List[str] = []
    seen = set()
    for value in values:
        value = str(value or "").strip()
        if not value or value in seen:
            continue
        ordered.append(value)
        seen.add(value)
    return ordered


def extract_group_libraries(group: pd.DataFrame) -> List[str]:
    if "library" not in group.columns:
        return []
    values = [str(value).strip() for value in group["library"].dropna().tolist() if str(value).strip()]
    if not values:
        return []
    return [value for value, _ in Counter(values).most_common()]


def filter_candidates_by_library(candidates: List[str], libraries: List[str]) -> List[str]:
    normalized_libraries = {normalize_library_key(library) for library in libraries if normalize_library_key(library)}
    unique_candidates = ordered_unique(candidates)
    if not normalized_libraries:
        return unique_candidates
    matched = [
        gav for gav in unique_candidates if normalize_library_key(get_library_from_gav(gav)) in normalized_libraries
    ]
    return matched or unique_candidates


def resolve_gav(
    cve_id: str,
    repo_map: Dict[str, Dict[str, object]],
    mvn_test_map: Dict[str, str],
    disclosed_gav_map: Dict[str, List[str]],
    disclosed_library_map: Dict[str, List[str]],
    library_candidate_map: Dict[str, set],
    artifact_lookup_cache: Dict[str, List[str]],
    observed_versions: List[str],
    excel_libraries: List[str],
    history_cache: Dict[str, List[Dict[str, str]]],
    refresh_cache: bool = False,
) -> Tuple[Optional[str], str, str]:
    candidate_pool: List[str] = []
    candidate_sources: Dict[str, str] = {}

    def add_candidate(gav: str, source: str) -> None:
        gav = str(gav or "").strip()
        if not gav or ":" not in gav:
            return
        if gav not in candidate_sources:
            candidate_pool.append(gav)
            candidate_sources[gav] = source

    mvn_gav = mvn_test_map.get(cve_id)
    if mvn_gav:
        add_candidate(mvn_gav, "mvn_test")

    disclosed_gavs = disclosed_gav_map.get(cve_id, [])
    for gav in disclosed_gavs:
        add_candidate(gav, "disclosed")

    description = str(repo_map.get(cve_id, {}).get("description", "") or "")
    description_gav = parse_gav_from_description(description)
    if description_gav:
        add_candidate(description_gav, "description")

    excel_libraries = ordered_unique(excel_libraries)
    disclosed_libraries = ordered_unique(disclosed_library_map.get(cve_id, []))
    candidate_libraries = ordered_unique(excel_libraries + disclosed_libraries)
    excel_library_keys = {normalize_library_key(library) for library in excel_libraries if normalize_library_key(library)}
    direct_library_keys = {
        normalize_library_key(get_library_from_gav(gav))
        for gav in candidate_pool
        if normalize_library_key(get_library_from_gav(gav))
    }
    needs_excel_validation = (
        len(disclosed_gavs) > 1
        or len(direct_library_keys) > 1
        or len(excel_library_keys) > 1
        or (excel_library_keys and any(library_key not in excel_library_keys for library_key in direct_library_keys))
    )

    if candidate_pool and not needs_excel_validation:
        chosen = candidate_pool[0]
        return chosen, get_library_from_gav(chosen), candidate_sources[chosen]

    for library in candidate_libraries:
        library_key = normalize_library_key(library)
        if not library_key:
            continue
        for gav in sorted(library_candidate_map.get(library_key, set())):
            add_candidate(gav, "library_local")
        for gav in search_gav_candidates_by_library(library, artifact_lookup_cache):
            add_candidate(gav, "library_maven_search")

    filtered_candidates = filter_candidates_by_library(candidate_pool, excel_libraries)
    chosen = choose_best_gav_candidate(filtered_candidates, observed_versions, history_cache, refresh_cache=refresh_cache)
    if not chosen and len(filtered_candidates) == 1:
        chosen = filtered_candidates[0]
    if not chosen and candidate_pool:
        chosen = filter_candidates_by_library(candidate_pool, candidate_libraries)[0]

    if chosen:
        source = candidate_sources.get(chosen, "library_local")
        resolution = source if not needs_excel_validation else f"{source}_excel_validated"
        return chosen, get_library_from_gav(chosen), resolution

    library = candidate_libraries[0] if candidate_libraries else ""
    if not library:
        return None, "", "missing_library"
    return None, library, "unresolved"


def history_from_cache_entries(entries: List[Dict[str, str]]) -> List[Dict[str, object]]:
    restored = []
    for entry in entries:
        version = str(entry.get("version") or "").strip()
        release_date = str(entry.get("release_date") or "").strip()
        if not version or not release_date:
            continue
        try:
            restored.append(
                {
                    "version": version,
                    "release_date": datetime.fromisoformat(release_date),
                }
            )
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
            cache[str(gav)] = normalized_entries
    return cache


def save_history_cache(path: str, cache: Dict[str, List[Dict[str, str]]]) -> None:
    save_json(path, cache)


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
    return collected


def build_semver_key(version: str) -> Tuple[int, ...]:
    normalized = normalize_version(version)
    if not normalized:
        return tuple()
    return tuple(int(part) for part in normalized.split(".") if part != "")


def get_release_history_cached(
    gav: str,
    cache: Dict[str, List[Dict[str, str]]],
    refresh_cache: bool = False,
) -> List[Dict[str, object]]:
    if not refresh_cache and gav in cache:
        restored = history_from_cache_entries(cache[gav])
        if restored:
            return sorted(restored, key=lambda item: (item["release_date"], build_semver_key(item["version"]), item["version"]))

    group_id, artifact_id = gav.split(":", 1)
    history: List[Dict[str, object]] = []
    try:
        history = fetch_full_release_history(group_id, artifact_id)
    except Exception:
        history = get_release_history(group_id, artifact_id)
    history = sorted(history, key=lambda item: (item["release_date"], build_semver_key(item["version"]), item["version"]))
    if history:
        cache[gav] = history_to_cache_entries(history)
    return history


PRE_RELEASE_SUFFIX_RE = re.compile(r"(?:rc|cr|pr|preview|alpha|beta|m|milestone)-?\d*$", re.I)
RUNTIME_SUFFIX_RE = re.compile(r"(?:java|jdk|jre)-?(\d+)$", re.I)
DOT_PRE_RELEASE_RE = re.compile(r"^(.*?)[.]((?:rc|cr|pr|preview|alpha|beta|m|milestone)\d+)$", re.I)


def split_base_and_suffix(version: str) -> Tuple[str, str]:
    version = str(version).strip()
    if "-" in version:
        base, suffix = version.split("-", 1)
        return base.strip(), suffix.strip()
    dot_match = DOT_PRE_RELEASE_RE.fullmatch(version)
    if dot_match:
        return dot_match.group(1).strip(), dot_match.group(2).strip()
    return version, ""


def format_semver_key(parts: Tuple[int, ...]) -> str:
    return ".".join(str(part) for part in parts if part is not None)


def get_line_key(semver_key: Tuple[int, ...]) -> str:
    if not semver_key:
        return "unknown"
    if len(semver_key) == 1:
        return str(semver_key[0])
    return f"{semver_key[0]}.{semver_key[1]}"


def normalize_suffix_family(suffix: str) -> str:
    suffix = str(suffix or "").strip().lower().replace("_", "-")
    if not suffix:
        return "stable"
    runtime_match = RUNTIME_SUFFIX_RE.fullmatch(suffix)
    if runtime_match:
        return f"runtime-{runtime_match.group(1)}"
    if PRE_RELEASE_SUFFIX_RE.fullmatch(suffix):
        return "pre-release"
    normalized = re.sub(r"\d+$", "", suffix).strip("-")
    normalized = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")
    return f"suffix-{normalized or suffix or 'unknown'}"


def classify_branch_kind(suffix: str) -> str:
    suffix = str(suffix or "").strip().lower().replace("_", "-")
    if not suffix:
        return "stable"
    if PRE_RELEASE_SUFFIX_RE.fullmatch(suffix):
        return "pre-release"
    if RUNTIME_SUFFIX_RE.fullmatch(suffix):
        return "runtime-fork"
    return "suffix-fork"


def build_suffix_sort_key(suffix: str) -> Tuple[int, str, int, str]:
    normalized = str(suffix or "").strip().lower().replace("_", "-")
    if not normalized:
        return (0, "", 0, "")
    match = re.fullmatch(r"([a-z]+)-?(\d+)?", normalized)
    if not match:
        return (99, normalized, 0, normalized)
    phase = match.group(1)
    number = int(match.group(2) or 0)
    phase_rank = {
        "alpha": 1,
        "beta": 2,
        "milestone": 3,
        "m": 3,
        "preview": 4,
        "pr": 4,
        "cr": 5,
        "rc": 5,
        "java": 10,
        "jdk": 10,
        "jre": 10,
    }.get(phase, 50)
    return (phase_rank, phase, number, normalized)


def build_version_order_key(entry: Dict[str, object]) -> Tuple[Tuple[int, ...], int, Tuple[int, str, int, str], str]:
    semver_key = tuple(entry.get("semver_key") or ())
    suffix = str(entry.get("suffix") or "")
    normalized = suffix.strip().lower().replace("_", "-")
    if not normalized:
        stage_rank = 1
    elif PRE_RELEASE_SUFFIX_RE.fullmatch(normalized):
        stage_rank = 0
    else:
        stage_rank = 2
    return (semver_key, stage_rank, build_suffix_sort_key(suffix), str(entry.get("version") or ""))


def build_provisional_branch_key(entry: Dict[str, object]) -> Tuple[str, str]:
    branch_kind = str(entry["branch_kind"])
    line_key = str(entry["line_key"])
    base_version = str(entry["base_version"])
    suffix_family = str(entry["suffix_family"])

    if branch_kind == "pre-release":
        return f"fork@{base_version}#pre", "pre-release"
    if branch_kind == "runtime-fork":
        return f"fork@{line_key}#{suffix_family}", suffix_family
    return f"fork@{base_version}#{suffix_family}", suffix_family


def enrich_release_history(history: List[Dict[str, object]]) -> List[Dict[str, object]]:
    enriched = []
    for item in history:
        version = str(item["version"]).strip()
        base_version, suffix = split_base_and_suffix(version)
        semver_key = build_semver_key(base_version)
        normalized_core = normalize_version(base_version)
        line_key = get_line_key(semver_key)
        suffix_family = normalize_suffix_family(suffix)
        branch_kind = classify_branch_kind(suffix)
        enriched.append(
            {
                "version": version,
                "release_date": item["release_date"],
                "base_version": base_version,
                "suffix": suffix,
                "suffix_family": suffix_family,
                "branch_kind": branch_kind,
                "normalized_core": normalized_core,
                "semver_key": semver_key,
                "line_key": line_key,
                "suffix_sort_key": build_suffix_sort_key(suffix),
            }
        )
    enriched.sort(
        key=lambda item: (
            item["release_date"],
            item["line_key"],
            item["semver_key"],
            item["suffix_sort_key"],
            item["version"],
        )
    )
    return enriched


def choose_anchor_main_entry(
    first_entry: Dict[str, object],
    stable_entries: List[Dict[str, object]],
    stable_by_exact_core: Dict[str, Dict[str, object]],
    fork_window_days: float,
) -> Optional[Dict[str, object]]:
    if not stable_entries:
        return None

    threshold = timedelta(days=fork_window_days)
    exact_anchor = stable_by_exact_core.get(first_entry["normalized_core"])
    release_date = first_entry["release_date"]
    line_key = first_entry["line_key"]

    def latest_before(entries: List[Dict[str, object]]) -> Optional[Dict[str, object]]:
        historical = [entry for entry in entries if entry["release_date"] <= release_date]
        if not historical:
            return None
        return max(
            historical,
            key=lambda entry: (
                entry["release_date"],
                entry["semver_key"],
                entry["version"],
            ),
        )

    same_line_entries = [entry for entry in stable_entries if entry["line_key"] == line_key]
    same_line_before = latest_before(same_line_entries)
    if same_line_before is not None:
        return same_line_before

    global_before = latest_before(stable_entries)
    if global_before is not None:
        return global_before

    candidates_same_line = [
        entry
        for entry in stable_entries
        if entry["line_key"] == line_key
        and abs(entry["release_date"] - release_date) <= threshold
    ]
    if candidates_same_line:
        return min(
            candidates_same_line,
            key=lambda entry: (
                abs(entry["release_date"] - release_date),
                entry["release_date"],
                entry["version"],
            ),
        )

    if exact_anchor is not None and abs(exact_anchor["release_date"] - release_date) <= threshold:
        return exact_anchor

    candidates_global = [
        entry for entry in stable_entries if abs(entry["release_date"] - release_date) <= threshold
    ]
    if candidates_global:
        return min(
            candidates_global,
            key=lambda entry: (
                abs(entry["release_date"] - release_date),
                entry["release_date"],
                entry["version"],
            ),
        )

    return exact_anchor


def infer_release_branches(
    history: List[Dict[str, object]],
    fork_window_days: float,
) -> Tuple[List[Dict[str, object]], List[List[Dict[str, object]]]]:
    stable_entries = [entry for entry in history if entry["branch_kind"] == "stable"]
    stable_entries.sort(
        key=lambda item: (
            item["release_date"],
            item["semver_key"],
            item["version"],
        )
    )

    branches: List[Dict[str, object]] = []
    main_entries: List[Dict[str, object]] = []
    anchored_row_by_line: Dict[str, int] = {}
    anchored_entry_by_line: Dict[str, Dict[str, object]] = {}
    grouped_stable_backports: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    branch_meta: Dict[str, Dict[str, object]] = {}
    last_main_semver: Tuple[int, ...] = tuple()

    for entry in stable_entries:
        semver_key = tuple(entry.get("semver_key") or ())
        line_key = str(entry.get("line_key") or "unknown")
        is_main_candidate = not main_entries or semver_key >= last_main_semver

        if is_main_candidate:
            row_index = len(main_entries)
            main_entries.append(entry)
            last_main_semver = semver_key
            anchored_row_by_line[line_key] = row_index
            anchored_entry_by_line[line_key] = entry
            entry["branch_key"] = "main"
            entry["branch_family"] = "main"
            entry["branch_kind"] = "stable"
            entry["branch_index"] = row_index
            entry["matrix_row"] = row_index
            entry["matrix_col"] = 0
            continue

        branch_key = f"stable@{line_key}"
        grouped_stable_backports[branch_key].append(entry)
        anchor_row = anchored_row_by_line.get(line_key)
        anchor_entry = anchored_entry_by_line.get(line_key)
        branch_meta.setdefault(
            branch_key,
            {
                "branch_key": branch_key,
                "family": "stable-line",
                "kind": "stable-backport",
                "entries": [],
                "forked_from": "main",
                "fork_anchor_version": anchor_entry["version"] if anchor_entry is not None else None,
                "fork_anchor_release_date": (
                    anchor_entry["release_date"].isoformat(timespec="seconds") if anchor_entry is not None else None
                ),
                "is_fork_branch": True,
                "matrix_row": anchor_row,
                "matrix_start_col": None,
                "matrix_end_col": None,
            },
        )
        if anchor_entry is None and branch_meta[branch_key].get("fork_anchor_version") is None:
            branch_meta[branch_key]["fork_anchor_version"] = entry["base_version"]

    main_branch = {
        "branch_key": "main",
        "family": "main",
        "kind": "stable",
        "entries": main_entries,
        "forked_from": None,
        "fork_anchor_version": None,
        "fork_anchor_release_date": None,
        "is_fork_branch": False,
        "matrix_row": None,
        "matrix_start_col": 0,
        "matrix_end_col": 0,
    }
    branches.append(main_branch)

    for idx, entry in enumerate(main_entries):
        entry["branch_key"] = "main"
        entry["branch_family"] = "main"
        entry["branch_kind"] = "stable"
        entry["branch_index"] = idx
        entry["matrix_row"] = idx
        entry["matrix_col"] = 0

    stable_by_exact_core = {entry["normalized_core"]: entry for entry in main_entries if entry["normalized_core"]}

    side_branches: List[Dict[str, object]] = []
    for branch_key, entries in grouped_stable_backports.items():
        entries.sort(
            key=lambda item: (
                item["release_date"],
                item["semver_key"],
                item["version"],
            )
        )
        branch = branch_meta[branch_key]
        branch["entries"] = entries
        if branch.get("matrix_row") is None:
            line_key = branch_key.split("@", 1)[1]
            anchor_row = anchored_row_by_line.get(line_key)
            anchor_entry = anchored_entry_by_line.get(line_key)
            if anchor_row is not None:
                branch["matrix_row"] = int(anchor_row)
            if anchor_entry is not None:
                branch["fork_anchor_version"] = anchor_entry["version"]
                branch["fork_anchor_release_date"] = anchor_entry["release_date"].isoformat(timespec="seconds")
        side_branches.append(branch)

    grouped_forks: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for entry in history:
        if entry["branch_kind"] == "stable":
            continue
        branch_key, family = build_provisional_branch_key(entry)
        grouped_forks[branch_key].append(entry)
        branch_meta.setdefault(
            branch_key,
            {
                "branch_key": branch_key,
                "family": family,
                "kind": entry["branch_kind"],
                "entries": [],
                "forked_from": "main",
                "fork_anchor_version": None,
                "fork_anchor_release_date": None,
                "is_fork_branch": True,
                "matrix_row": None,
                "matrix_start_col": None,
                "matrix_end_col": None,
            },
        )

    for branch_key, entries in grouped_forks.items():
        entries.sort(
            key=lambda item: (
                item["release_date"],
                item["semver_key"],
                item["suffix_sort_key"],
                item["version"],
            )
        )
        branch = branch_meta[branch_key]
        branch["entries"] = entries
        first_entry = entries[0]
        anchor_entry = choose_anchor_main_entry(first_entry, main_entries, stable_by_exact_core, fork_window_days)
        if anchor_entry is not None:
            branch["fork_anchor_version"] = anchor_entry["version"]
            branch["fork_anchor_release_date"] = anchor_entry["release_date"].isoformat(timespec="seconds")
            branch["matrix_row"] = int(anchor_entry["matrix_row"])
        else:
            branch["fork_anchor_version"] = first_entry["base_version"]
        side_branches.append(branch)

    row_to_forks: Dict[int, List[Dict[str, object]]] = defaultdict(list)
    detached_forks: List[Dict[str, object]] = []
    for branch in side_branches:
        matrix_row = branch.get("matrix_row")
        if matrix_row is None:
            detached_forks.append(branch)
        else:
            row_to_forks[int(matrix_row)].append(branch)

    branch_matrix: List[List[Dict[str, object]]] = []
    for row_index, main_entry in enumerate(main_entries):
        row_cells: List[Dict[str, object]] = [
            {
                "row": row_index,
                "col": 0,
                "branch_key": "main",
                "branch_kind": "stable",
                "branch_family": "main",
                "version": main_entry["version"],
                "release_date": main_entry["release_date"].isoformat(timespec="seconds"),
            }
        ]
        col_cursor = 1
        ordered_branches = sorted(
            row_to_forks.get(row_index, []),
            key=lambda item: (
                0 if item.get("kind") == "stable-backport" else 1,
                item["entries"][0]["release_date"] if item["entries"] else datetime.max,
                item["branch_key"],
            ),
        )
        for fork_order, branch in enumerate(ordered_branches, start=1):
            branch["matrix_row"] = row_index
            branch["matrix_start_col"] = col_cursor
            for branch_index, entry in enumerate(branch["entries"]):
                entry["branch_key"] = branch["branch_key"]
                entry["branch_family"] = branch["family"]
                entry["branch_kind"] = branch["kind"]
                entry["branch_index"] = branch_index
                entry["matrix_row"] = row_index
                entry["matrix_col"] = col_cursor + branch_index
                row_cells.append(
                    {
                        "row": row_index,
                        "col": col_cursor + branch_index,
                        "branch_key": branch["branch_key"],
                        "branch_kind": branch["kind"],
                        "branch_family": branch["family"],
                        "version": entry["version"],
                        "release_date": entry["release_date"].isoformat(timespec="seconds"),
                        "fork_anchor_version": branch["fork_anchor_version"],
                        "fork_order": fork_order,
                    }
                )
            branch["matrix_end_col"] = col_cursor + len(branch["entries"]) - 1
            col_cursor += len(branch["entries"])
        branch_matrix.append(row_cells)

    next_row_index = len(branch_matrix)
    for branch in sorted(
        detached_forks,
        key=lambda item: (
            item["entries"][0]["release_date"] if item["entries"] else datetime.max,
            item["branch_key"],
        ),
    ):
        branch["matrix_row"] = next_row_index
        branch["matrix_start_col"] = 1
        branch["matrix_end_col"] = len(branch["entries"])
        row_cells = [
            {
                "row": next_row_index,
                "col": 0,
                "branch_key": "main",
                "branch_kind": "stable",
                "branch_family": "main",
                "version": None,
                "release_date": None,
            }
        ]
        for branch_index, entry in enumerate(branch["entries"]):
            entry["branch_key"] = branch["branch_key"]
            entry["branch_family"] = branch["family"]
            entry["branch_kind"] = branch["kind"]
            entry["branch_index"] = branch_index
            entry["matrix_row"] = next_row_index
            entry["matrix_col"] = branch_index + 1
            row_cells.append(
                {
                    "row": next_row_index,
                    "col": branch_index + 1,
                    "branch_key": branch["branch_key"],
                    "branch_kind": branch["kind"],
                    "branch_family": branch["family"],
                    "version": entry["version"],
                    "release_date": entry["release_date"].isoformat(timespec="seconds"),
                    "fork_anchor_version": branch["fork_anchor_version"],
                    "fork_order": 1,
                }
            )
        branch_matrix.append(row_cells)
        next_row_index += 1

    branches.extend(
        sorted(
            side_branches,
            key=lambda branch: (
                branch.get("matrix_row") if branch.get("matrix_row") is not None else 10**9,
                branch["matrix_start_col"] if branch.get("matrix_start_col") is not None else 10**9,
                branch["entries"][0]["release_date"] if branch["entries"] else datetime.max,
                branch["branch_key"],
            ),
        )
    )
    return branches, branch_matrix


def build_release_index(history: List[Dict[str, object]]) -> Tuple[Dict[str, Dict[str, object]], Dict[str, List[Dict[str, object]]]]:
    exact: Dict[str, Dict[str, object]] = {}
    normalized: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for entry in history:
        exact[entry["version"]] = entry
        normalized[normalize_version(entry["version"])] .append(entry)
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


def is_poc_success(status) -> bool:
    return str(status).strip().upper() == "APPEARS"


def is_poc_fail(status) -> bool:
    return str(status).strip().upper() in {"BUILD_SUCCESS", "BUILD_FAILURE_OTHER"}


def get_compile_status(status) -> bool:
    normalized = str(status).strip().upper()
    if normalized == "BUILD_FAILURE_OTHER":
        return False
    return normalized in {"BUILD_SUCCESS", "APPEARS"}


def should_skip_same_generation_pair(left_row: Dict[str, object], right_row: Dict[str, object]) -> bool:
    if left_row["version"] == right_row["version"]:
        return False
    if left_row.get("_normalized_core") != right_row.get("_normalized_core"):
        return False
    left_kind = str(left_row.get("_branch_kind") or "")
    right_kind = str(right_row.get("_branch_kind") or "")
    if "pre-release" in {left_kind, right_kind}:
        return False
    return True


def build_tested_matrix_rows(
    rows: List[dict], history: List[Dict[str, object]]
) -> Tuple[Dict[str, List[dict]], List[dict], List[str]]:
    grouped: Dict[str, List[dict]] = defaultdict(list)
    unresolved_versions: List[str] = []
    resolved_by_version: Dict[str, dict] = {}

    for row in rows:
        version = str(row["version"]).strip()
        release_entry = resolve_release_entry(version, history)
        if release_entry is None:
            unresolved_versions.append(version)
            continue
        enriched_row = {
            **row,
            "_release_date": release_entry["release_date"],
            "_normalized_core": release_entry["normalized_core"],
            "_branch_key": release_entry["branch_key"],
            "_branch_family": release_entry["branch_family"],
            "_branch_kind": release_entry["branch_kind"],
            "_branch_index": release_entry["branch_index"],
            "_branch_version": release_entry["version"],
            "_matrix_row": release_entry.get("matrix_row"),
            "_matrix_col": release_entry.get("matrix_col"),
        }
        existing = resolved_by_version.get(version)
        if existing is None or enriched_row["_original_index"] < existing["_original_index"]:
            resolved_by_version[version] = enriched_row

    tested_rows = sorted(
        resolved_by_version.values(),
        key=lambda item: (
            item["_matrix_row"] if item.get("_matrix_row") is not None else 10**9,
            item["_matrix_col"] if item.get("_matrix_col") is not None else 10**9,
            item["_release_date"],
            item["_original_index"],
        ),
    )
    for row in tested_rows:
        grouped[row["_branch_key"]].append(row)
    return grouped, tested_rows, unresolved_versions


def build_version_pair_entry(
    curr_row: Dict[str, object],
    next_row: Dict[str, object],
    comparison_axis: str,
    release_lineage: str,
) -> Optional[Dict[str, object]]:
    base_ver = str(curr_row["version"])
    head_ver = str(next_row["version"])
    res_base = curr_row["execution_result"]
    res_head = next_row["execution_result"]
    cause_base = str(curr_row.get("cause") or "")
    cause_head = str(next_row.get("cause") or "")

    if is_poc_success(res_base) and is_poc_fail(res_head):
        is_compile = get_compile_status(res_head)
        return {
            "appears": base_ver,
            "not appears": head_ver,
            "BASE_TAG": "unknown",
            "HEAD_TAG": "unknown",
            "COMPARE_URL": "unknown",
            "seek_patch": True,
            "compile": is_compile,
            "cause": cause_head if not is_compile else "",
            "ordering_basis": "branch_aware_release_time",
            "release_lineage": release_lineage,
            "comparison_axis": comparison_axis,
            "baseline_release_date": curr_row["_release_date"].isoformat(timespec="seconds"),
            "target_release_date": next_row["_release_date"].isoformat(timespec="seconds"),
            "baseline_matrix_row": curr_row.get("_matrix_row"),
            "baseline_matrix_col": curr_row.get("_matrix_col"),
            "target_matrix_row": next_row.get("_matrix_row"),
            "target_matrix_col": next_row.get("_matrix_col"),
        }
    if is_poc_fail(res_base) and is_poc_success(res_head):
        is_compile = get_compile_status(res_base)
        return {
            "appears": head_ver,
            "not appears": base_ver,
            "BASE_TAG": "unknown",
            "HEAD_TAG": "unknown",
            "COMPARE_URL": "unknown",
            "seek_patch": False,
            "compile": is_compile,
            "cause": cause_base if not is_compile else "",
            "ordering_basis": "branch_aware_release_time",
            "release_lineage": release_lineage,
            "comparison_axis": comparison_axis,
            "baseline_release_date": curr_row["_release_date"].isoformat(timespec="seconds"),
            "target_release_date": next_row["_release_date"].isoformat(timespec="seconds"),
            "baseline_matrix_row": curr_row.get("_matrix_row"),
            "baseline_matrix_col": curr_row.get("_matrix_col"),
            "target_matrix_row": next_row.get("_matrix_row"),
            "target_matrix_col": next_row.get("_matrix_col"),
        }
    return None


def collect_matrix_version_pairs(
    branch_matrix: List[List[Dict[str, object]]],
    tested_rows: List[dict],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    tested_by_version = {str(row["version"]): row for row in tested_rows}
    version_pairs: List[Dict[str, object]] = []
    skipped_same_generation: List[Dict[str, object]] = []
    seen_adjacency = set()

    def process_neighbor(
        current_cell: Dict[str, object],
        next_cell: Dict[str, object],
        comparison_axis: str,
        release_lineage: str,
    ) -> None:
        current_version = str(current_cell.get("version") or "").strip()
        next_version = str(next_cell.get("version") or "").strip()
        if not current_version or not next_version:
            return
        curr_row = tested_by_version.get(current_version)
        next_row = tested_by_version.get(next_version)
        if curr_row is None or next_row is None:
            return

        adjacency_key = (
            current_version,
            next_version,
            comparison_axis,
            curr_row.get("_matrix_row"),
            curr_row.get("_matrix_col"),
            next_row.get("_matrix_row"),
            next_row.get("_matrix_col"),
        )
        if adjacency_key in seen_adjacency:
            return
        seen_adjacency.add(adjacency_key)

        if should_skip_same_generation_pair(curr_row, next_row):
            skipped_same_generation.append(
                {
                    "comparison_axis": comparison_axis,
                    "release_lineage": release_lineage,
                    "left": current_version,
                    "right": next_version,
                    "left_matrix_row": curr_row.get("_matrix_row"),
                    "left_matrix_col": curr_row.get("_matrix_col"),
                    "right_matrix_row": next_row.get("_matrix_row"),
                    "right_matrix_col": next_row.get("_matrix_col"),
                }
            )
            return

        pair_entry = build_version_pair_entry(curr_row, next_row, comparison_axis, release_lineage)
        if pair_entry:
            version_pairs.append(pair_entry)

    for row_index, row_cells in enumerate(branch_matrix):
        for col_index, current_cell in enumerate(row_cells):
            if col_index + 1 < len(row_cells):
                process_neighbor(
                    current_cell,
                    row_cells[col_index + 1],
                    "row",
                    f"row[{row_index}]",
                )
            if row_index + 1 < len(branch_matrix) and col_index < len(branch_matrix[row_index + 1]):
                process_neighbor(
                    current_cell,
                    branch_matrix[row_index + 1][col_index],
                    "column",
                    f"col[{col_index}]",
                )

    return version_pairs, skipped_same_generation


def build_branch_summary(
    branch_rows: Dict[str, List[dict]],
    branches: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    used_branch_keys = set(branch_rows.keys())
    branch_lookup = {branch["branch_key"]: branch for branch in branches}
    summary = []
    ordered_branch_keys = sorted(
        used_branch_keys,
        key=lambda branch_key: (
            0 if branch_key == "main" else 1,
            branch_lookup.get(branch_key, {}).get("matrix_row") if branch_lookup.get(branch_key, {}).get("matrix_row") is not None else 10**9,
            branch_lookup.get(branch_key, {}).get("matrix_start_col") if branch_lookup.get(branch_key, {}).get("matrix_start_col") is not None else 10**9,
            branch_key,
        ),
    )
    for branch_key in ordered_branch_keys:
        branch = branch_lookup.get(branch_key)
        if not branch:
            continue
        tested_versions = [row["version"] for row in branch_rows.get(branch_key, [])]
        summary.append(
            {
                "branch_key": branch_key,
                "branch_family": branch["family"],
                "branch_kind": branch.get("kind"),
                "is_fork_branch": bool(branch.get("is_fork_branch")),
                "forked_from": branch.get("forked_from"),
                "fork_anchor_version": branch.get("fork_anchor_version"),
                "fork_anchor_release_date": branch.get("fork_anchor_release_date"),
                "matrix_row": branch.get("matrix_row"),
                "matrix_start_col": branch.get("matrix_start_col"),
                "matrix_end_col": branch.get("matrix_end_col"),
                "tested_versions": tested_versions,
                "release_dates": [
                    entry["release_date"].isoformat(timespec="seconds")
                    for entry in branch.get("entries", [])
                ],
            }
        )
    return summary


def get_github_tags(owner: str, repo: str, token: str, max_pages: int) -> List[str]:
    if owner == "unknown" or repo == "unknown":
        return []
    cache_key = f"{owner}/{repo}/{max_pages}"
    if cache_key in TAGS_CACHE:
        return TAGS_CACHE[cache_key]

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "branch-aware-version-switch",
    }
    if token:
        headers["Authorization"] = f"Bearer {token.strip()}"

    all_tags: List[str] = []
    for page in range(1, max_pages + 1):
        api_url = f"https://api.github.com/repos/{owner}/{repo}/tags"
        try:
            response = requests.get(
                api_url,
                headers=headers,
                params={"per_page": 100, "page": page},
                timeout=20,
            )
            if response.status_code != 200:
                break
            data = response.json()
            if not data:
                break
            all_tags.extend([str(tag.get("name") or "").strip() for tag in data if tag.get("name")])
        except Exception:
            break

    TAGS_CACHE[cache_key] = all_tags
    return all_tags


def match_best_tag(version_str: str, available_tags: List[str]) -> str:
    if not version_str or str(version_str).lower() == "unknown":
        return "unknown"

    dot_v = str(version_str)
    under_v = dot_v.replace(".", "_")
    prefixes = ["", "v", "REL", "release-", "wicket-", "XSTREAM_", "xstream-", "v_", "r"]

    for prefix in prefixes:
        if f"{prefix}{dot_v}" in available_tags:
            return f"{prefix}{dot_v}"
        if f"{prefix}{under_v}" in available_tags:
            return f"{prefix}{under_v}"

    p_dot = re.compile(rf"{re.escape(dot_v)}(?![.\d_])")
    p_under = re.compile(rf"{re.escape(under_v)}(?![.\d_])")
    for tag in available_tags:
        if p_dot.search(tag) or p_under.search(tag):
            return tag
    return "unknown"


def enrich_pairs_with_tags(
    owner: str,
    repo: str,
    pairs: List[Dict[str, object]],
    github_token: str,
    github_tag_pages: int,
) -> None:
    tags = get_github_tags(owner, repo, github_token, github_tag_pages)
    for pair in pairs:
        base_version = pair["not appears"] if not pair["seek_patch"] else pair["appears"]
        head_version = pair["appears"] if not pair["seek_patch"] else pair["not appears"]
        matched_base = match_best_tag(str(base_version), tags)
        matched_head = match_best_tag(str(head_version), tags)
        pair["BASE_TAG"] = matched_base
        pair["HEAD_TAG"] = matched_head
        if matched_base != "unknown" and matched_head != "unknown" and owner != "unknown" and repo != "unknown":
            pair["COMPARE_URL"] = f"https://github.com/{owner}/{repo}/compare/{matched_base}...{matched_head}"


def main() -> int:
    args = parse_args()
    cve_filter = {str(item).strip() for item in (args.cve or []) if str(item).strip()}

    if not os.path.exists(args.excel):
        raise SystemExit(f"找不到输入 Excel: {args.excel}")

    repo_map = load_repo_mapping(args.ghrepo_json)
    mvn_test_map = load_gav_mapping(args.mvn_test_dir, cve_filter or None)
    disclosed_gav_map, disclosed_library_by_cve, disclosed_library_candidates = load_disclosed_metadata(args.disclosed_version_file)
    history_cache = load_history_cache(args.cache_json)
    artifact_lookup_cache = load_artifact_lookup_cache(args.artifact_cache_json)
    library_candidate_map = build_library_candidate_map(disclosed_library_candidates, mvn_test_map, history_cache)

    df = pd.read_excel(args.excel)
    df.columns = [str(col).strip().lower() for col in df.columns]
    df = df.dropna(subset=["cve_id", "version"])
    df["cve_id"] = df["cve_id"].astype(str).str.strip()
    if cve_filter:
        df = df[df["cve_id"].isin(cve_filter)]

    results: Dict[str, Dict[str, object]] = {}
    counters: Counter = Counter()

    for cve_id, group in df.groupby("cve_id", sort=False):
        cve_id = str(cve_id).strip()
        repo_info = repo_map.get(cve_id, {})
        owner = str(repo_info.get("owner", "unknown") or "unknown")
        repo_name = str(repo_info.get("repo_name", "unknown") or "unknown")
        description = str(repo_info.get("description", "") or "")
        cwe = repo_info.get("cwe") or []
        excel_libraries = extract_group_libraries(group)
        library = (excel_libraries[0] if excel_libraries else "") or next(iter(disclosed_library_by_cve.get(cve_id, [])), "")
        observed_versions = [str(value).strip() for value in group["version"].tolist() if str(value).strip()]

        gav, resolved_library, artifact_resolution = resolve_gav(
            cve_id=cve_id,
            repo_map=repo_map,
            mvn_test_map=mvn_test_map,
            disclosed_gav_map=disclosed_gav_map,
            disclosed_library_map=disclosed_library_by_cve,
            library_candidate_map=library_candidate_map,
            artifact_lookup_cache=artifact_lookup_cache,
            observed_versions=observed_versions,
            excel_libraries=excel_libraries,
            history_cache=history_cache,
            refresh_cache=args.refresh_cache,
        )
        library = resolved_library or library
        if not gav or ":" not in gav:
            counters["missing_gav"] += 1
            results[cve_id] = {
                "OWNER": owner,
                "REPO": repo_name,
                "description": description,
                "cwe": cwe,
                "library": library,
                "artifact": "unknown",
                "artifact_resolution": artifact_resolution,
                "ordering_basis": "branch_aware_release_time",
                "fork_window_days": args.fork_window_days,
                "branch_summary": [],
                "unresolved_versions": observed_versions,
                "skipped_same_generation_pairs": [],
                "version_pair": [],
            }
            counters["written_entries"] += 1
            counters["entries_without_artifact"] += 1
            continue

        add_library_candidate(library_candidate_map, library or get_library_from_gav(gav), gav)

        history = get_release_history_cached(gav, history_cache, refresh_cache=args.refresh_cache)
        if not history:
            counters["missing_release_history"] += 1
            results[cve_id] = {
                "OWNER": owner,
                "REPO": repo_name,
                "description": description,
                "cwe": cwe,
                "library": library or get_library_from_gav(gav),
                "artifact": gav,
                "artifact_resolution": artifact_resolution,
                "ordering_basis": "branch_aware_release_time",
                "fork_window_days": args.fork_window_days,
                "branch_summary": [],
                "unresolved_versions": observed_versions,
                "skipped_same_generation_pairs": [],
                "version_pair": [],
            }
            counters["written_entries"] += 1
            counters["entries_without_release_history"] += 1
            continue

        enriched_history = enrich_release_history(history)
        branches, branch_matrix = infer_release_branches(enriched_history, args.fork_window_days)

        rows = []
        for original_index, (_, row) in enumerate(group.iterrows()):
            rows.append(
                {
                    "version": str(row["version"]).strip(),
                    "execution_result": row.get("execution result"),
                    "cause": "" if pd.isna(row.get("cause")) else str(row.get("cause")),
                    "_original_index": original_index,
                }
            )

        tested_rows_by_branch, tested_matrix_rows, unresolved_versions = build_tested_matrix_rows(rows, enriched_history)
        version_pairs, skipped_same_generation = collect_matrix_version_pairs(branch_matrix, tested_matrix_rows)
        if not version_pairs:
            counters["no_boundary_pairs"] += 1

        enrich_pairs_with_tags(owner, repo_name, version_pairs, args.github_token, args.github_tag_pages)

        results[cve_id] = {
            "OWNER": owner,
            "REPO": repo_name,
            "description": description,
            "cwe": cwe,
            "library": library or get_library_from_gav(gav),
            "artifact": gav,
            "artifact_resolution": artifact_resolution,
            "ordering_basis": "branch_aware_release_time",
            "fork_window_days": args.fork_window_days,
            "branch_summary": build_branch_summary(tested_rows_by_branch, branches),
            "branch_matrix": branch_matrix,
            "unresolved_versions": unresolved_versions,
            "skipped_same_generation_pairs": skipped_same_generation,
            "version_pair": version_pairs,
        }
        counters["written_entries"] += 1
        if unresolved_versions:
            counters["entries_with_unresolved_versions"] += 1
        if skipped_same_generation:
            counters["entries_with_same_generation_skips"] += 1
        if not version_pairs:
            counters["entries_without_boundary_pairs"] += 1

    save_json(args.output_json, results)
    save_history_cache(args.cache_json, history_cache)
    save_artifact_lookup_cache(args.artifact_cache_json, artifact_lookup_cache)

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
