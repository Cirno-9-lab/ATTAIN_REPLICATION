#!/usr/bin/env python3
"""统计 batch-driver-logs 中的结果种类及个数。"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
from typing import Counter, DefaultDict, Dict, Iterable, List, Tuple

from target_paths import default_demo_target_root

STATUS_PATTERN = re.compile(r"^Status:\s*(?P<status>.+?)\s*$", re.MULTILINE)

FALLBACK_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("exploit_demo_not_found", re.compile(r"Exploit demo not found", re.IGNORECASE)),
    ("timeout_hint", re.compile(r"timed?\s*out|TimeoutExpired", re.IGNORECASE)),
    ("result_path_only", re.compile(r"^Result:\s+.+$", re.MULTILINE)),
]


def parse_args() -> argparse.Namespace:
    default_log_dir = default_demo_target_root() / "seek-patch-false-results" / "batch-driver-logs"
    parser = argparse.ArgumentParser(description="统计 batch-driver-logs 中的结果种类及个数")
    parser.add_argument(
        "--log-dir",
        default=str(default_log_dir),
        help=f"日志目录，默认: {default_log_dir}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 格式输出统计结果",
    )
    parser.add_argument(
        "--show-files",
        action="store_true",
        help="额外打印每种结果对应的日志文件名",
    )
    return parser.parse_args()


def classify_log_content(content: str) -> str:
    match = STATUS_PATTERN.search(content)
    if match:
        return match.group("status").strip()

    stripped = content.strip()
    if not stripped:
        return "empty_log"

    for label, pattern in FALLBACK_PATTERNS:
        if pattern.search(content):
            return label

    return "unknown"


def iter_log_files(log_dir: pathlib.Path) -> Iterable[pathlib.Path]:
    return sorted(path for path in log_dir.iterdir() if path.is_file())


def read_case_result_status(log_dir: pathlib.Path, log_path: pathlib.Path) -> Tuple[str, str]:
    case_id = log_path.stem
    result_path = log_dir.parent / "cases" / case_id / "case-result.json"
    if not result_path.exists():
        return "missing_case_result", "missing_case_result"

    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "invalid_case_result_json", "invalid_case_result_json"

    status = str(payload.get("status") or "unknown").strip()
    failure_subtype = str(payload.get("failure_subtype") or "none").strip()
    return status, failure_subtype


def build_summary(log_dir: pathlib.Path) -> Dict[str, object]:
    log_content_counts: Counter[str] = collections.Counter()
    case_status_counts: Counter[str] = collections.Counter()
    failure_subtype_counts: Counter[str] = collections.Counter()
    files_by_log_kind: DefaultDict[str, List[str]] = collections.defaultdict(list)
    files_by_case_status: DefaultDict[str, List[str]] = collections.defaultdict(list)
    total_files = 0

    for log_path in iter_log_files(log_dir):
        total_files += 1
        content = log_path.read_text(encoding="utf-8", errors="replace")

        log_kind = classify_log_content(content)
        log_content_counts[log_kind] += 1
        files_by_log_kind[log_kind].append(log_path.name)

        case_status, failure_subtype = read_case_result_status(log_dir, log_path)
        case_status_counts[case_status] += 1
        failure_subtype_counts[failure_subtype] += 1
        files_by_case_status[case_status].append(log_path.name)

    return {
        "log_dir": str(log_dir),
        "total_files": total_files,
        "log_content_counts": dict(sorted(log_content_counts.items(), key=lambda item: (-item[1], item[0]))),
        "case_result_status_counts": dict(sorted(case_status_counts.items(), key=lambda item: (-item[1], item[0]))),
        "case_result_failure_subtype_counts": dict(sorted(failure_subtype_counts.items(), key=lambda item: (-item[1], item[0]))),
        "files_by_log_kind": dict(files_by_log_kind),
        "files_by_case_status": dict(files_by_case_status),
    }


def print_count_block(title: str, counts: Dict[str, int], files_by_key: Dict[str, List[str]], show_files: bool) -> None:
    print(f"{title}:")
    for key, count in counts.items():
        print(f"  {key}: {count}")
        if show_files:
            for name in files_by_key.get(key, []):
                print(f"    - {name}")


def main() -> int:
    args = parse_args()
    log_dir = pathlib.Path(args.log_dir).expanduser().resolve()

    if not log_dir.exists():
        raise SystemExit(f"日志目录不存在: {log_dir}")
    if not log_dir.is_dir():
        raise SystemExit(f"给定路径不是目录: {log_dir}")

    summary = build_summary(log_dir)

    if args.json:
        payload = {
            "log_dir": summary["log_dir"],
            "total_files": summary["total_files"],
            "log_content_counts": summary["log_content_counts"],
            "case_result_status_counts": summary["case_result_status_counts"],
            "case_result_failure_subtype_counts": summary["case_result_failure_subtype_counts"],
        }
        if args.show_files:
            payload["files_by_log_kind"] = {
                key: summary["files_by_log_kind"][key]
                for key in sorted(summary["files_by_log_kind"])
            }
            payload["files_by_case_status"] = {
                key: summary["files_by_case_status"][key]
                for key in sorted(summary["files_by_case_status"])
            }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"log_dir: {summary['log_dir']}")
        print(f"log_dir_total_files: {summary['total_files']}")
        print_count_block(
            "log_content_counts",
            summary["log_content_counts"],
            summary["files_by_log_kind"],
            args.show_files,
        )
        print_count_block(
            "case_result_status_counts",
            summary["case_result_status_counts"],
            summary["files_by_case_status"],
            args.show_files,
        )
        print_count_block(
            "case_result_failure_subtype_counts",
            summary["case_result_failure_subtype_counts"],
            {},
            False,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
