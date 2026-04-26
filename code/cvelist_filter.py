#!/usr/bin/env python3
import argparse
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional


VERSION_NUMBER_RE = re.compile(r"\d+")


def extract_major(version: Any) -> Optional[int]:
    if version is None:
        return None
    match = VERSION_NUMBER_RE.search(str(version))
    if not match:
        return None
    return int(match.group(0))


def should_filter_pair(version_pair: Dict[str, Any], major_gap_threshold: int) -> bool:
    appears_major = extract_major(version_pair.get("appears"))
    not_appears_major = extract_major(version_pair.get("not appears"))

    if appears_major is None or not_appears_major is None:
        return False

    return abs(appears_major - not_appears_major) >= major_gap_threshold


def filter_cve_list(
    data: Dict[str, Any],
    major_gap_threshold: int,
    drop_empty_cves: bool,
) -> tuple[Dict[str, Any], Dict[str, int]]:
    filtered: Dict[str, Any] = {}
    total_pairs = 0
    removed_pairs = 0
    removed_cves = 0

    for cve_id, cve_info in data.items():
        cve_copy = deepcopy(cve_info)
        version_pairs = list(cve_copy.get("version_pair", []))
        total_pairs += len(version_pairs)

        kept_pairs = []
        for pair in version_pairs:
            if should_filter_pair(pair, major_gap_threshold):
                removed_pairs += 1
                continue
            kept_pairs.append(pair)

        cve_copy["version_pair"] = kept_pairs

        if drop_empty_cves and version_pairs and not kept_pairs:
            removed_cves += 1
            continue

        filtered[cve_id] = cve_copy

    stats = {
        "total_cves": len(data),
        "total_pairs": total_pairs,
        "removed_pairs": removed_pairs,
        "removed_cves": removed_cves,
        "kept_cves": len(filtered),
        "kept_pairs": total_pairs - removed_pairs,
    }
    return filtered, stats


def parse_args() -> argparse.Namespace:
    script_path = Path(__file__).resolve()
    workspace_dir = script_path.parent.parent
    default_input = workspace_dir / "dataset" / "list" / "cve_list.json"
    default_output = workspace_dir / "dataset" / "list" / "cve_list_filtered.json"

    parser = argparse.ArgumentParser(
        description="过滤 appears 和 not appears 跨多个大版本的 version_pair。"
    )
    parser.add_argument("--input", type=Path, default=default_input, help="输入 JSON 文件路径")
    parser.add_argument("--output", type=Path, default=default_output, help="输出 JSON 文件路径")
    parser.add_argument(
        "--major-gap-threshold",
        type=int,
        default=2,
        help="当主版本号差值大于等于该值时过滤，默认 2",
    )
    parser.add_argument(
        "--keep-empty-cves",
        action="store_true",
        help="保留过滤后 version_pair 为空的 CVE",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.major_gap_threshold < 1:
        raise ValueError("--major-gap-threshold 必须大于等于 1")

    with args.input.open("r", encoding="utf-8") as f:
        data = json.load(f)

    filtered, stats = filter_cve_list(
        data=data,
        major_gap_threshold=args.major_gap_threshold,
        drop_empty_cves=not args.keep_empty_cves,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        json.dump(filtered, f, ensure_ascii=False, indent=4)

    print(f"输入文件: {args.input}")
    print(f"输出文件: {args.output}")
    print(f"主版本差阈值: {args.major_gap_threshold}")
    print(f"CVE 总数: {stats['total_cves']}")
    print(f"version_pair 总数: {stats['total_pairs']}")
    print(f"过滤掉的 version_pair: {stats['removed_pairs']}")
    print(f"过滤掉的空 CVE: {stats['removed_cves']}")
    print(f"保留的 CVE: {stats['kept_cves']}")
    print(f"保留的 version_pair: {stats['kept_pairs']}")


if __name__ == "__main__":
    main()
