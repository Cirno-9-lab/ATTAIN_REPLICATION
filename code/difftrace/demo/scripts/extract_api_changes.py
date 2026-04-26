#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import sys
from typing import Dict, List, Optional, Tuple


CLASS_DECL_RE = re.compile(r"\b(class|interface|enum)\s+([A-Za-z0-9_$.]+)")
MEMBER_NAME_RE = re.compile(r"([A-Za-z0-9_$.<>$]+)\s*\(")
FIELD_NAME_RE = re.compile(r"([A-Za-z0-9_$]+);$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert javap API dumps into a structured API change summary.")
    parser.add_argument("analysis_dir", help="Analysis directory that contains version-diff/api-raw.")
    parser.add_argument("--output", help="Optional output path. Defaults to <analysis_dir>/version-diff/api-change-summary.json")
    return parser.parse_args()


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def write_json(path: pathlib.Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def class_name_from_dump(text: str, fallback: str) -> str:
    for line in text.splitlines():
        match = CLASS_DECL_RE.search(line)
        if match:
            return match.group(2)
    return fallback


def parse_signature_block(text: str, fallback_class_name: str) -> Dict[str, object]:
    class_name = class_name_from_dump(text, fallback_class_name)
    simple_name = class_name.split(".")[-1].split("$")[-1]
    members = {
        "class_name": class_name,
        "constructors": [],
        "methods": [],
        "fields": [],
    }

    pending_line: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("$") or line.startswith("Compiled from") or line in {"{", "}"}:
            continue
        if line.startswith("descriptor:"):
            descriptor = line.split("descriptor:", 1)[1].strip()
            if pending_line:
                consume_member_line(pending_line, descriptor, simple_name, members)
                pending_line = None
            continue
        if line.endswith(";"):
            pending_line = line

    members["constructors"].sort()
    members["methods"].sort()
    members["fields"].sort()
    return members


def consume_member_line(declaration: str, descriptor: str, simple_name: str, members: Dict[str, List[str]]) -> None:
    if "(" in declaration and ")" in declaration:
        name_match = MEMBER_NAME_RE.search(declaration)
        if not name_match:
            return
        name = name_match.group(1).split(".")[-1]
        encoded = f"{name}{descriptor}"
        if name == simple_name:
            members["constructors"].append(encoded)
        else:
            members["methods"].append(encoded)
        return

    field_match = FIELD_NAME_RE.search(declaration)
    if field_match:
        members["fields"].append(f"{field_match.group(1)}:{descriptor}")


def relative_class_name(relative_path: pathlib.Path) -> str:
    return str(relative_path).replace(".txt", "").replace("/", ".")


def load_member_map(root: pathlib.Path, side: str) -> Dict[str, Dict[str, object]]:
    base_dir = root / "api-raw" / side
    results: Dict[str, Dict[str, object]] = {}
    if not base_dir.exists():
        return results
    for path in sorted(base_dir.rglob("*.txt")):
        relative_path = path.relative_to(base_dir)
        fallback_class_name = relative_class_name(relative_path)
        results[fallback_class_name] = parse_signature_block(read_text(path), fallback_class_name)
    return results


def diff_members(before: List[str], after: List[str]) -> Tuple[List[str], List[str]]:
    before_set = set(before)
    after_set = set(after)
    removed = sorted(before_set - after_set)
    added = sorted(after_set - before_set)
    return removed, added


def flatten_breaking_changes(changed_classes: Dict[str, Dict[str, object]]) -> List[Dict[str, str]]:
    flattened: List[Dict[str, str]] = []
    for class_name, class_changes in sorted(changed_classes.items()):
        for key in (
            "removed_constructors",
            "removed_methods",
            "removed_fields",
            "removed_classes",
        ):
            for symbol in class_changes.get(key, []):
                flattened.append({
                    "class_name": class_name,
                    "change_type": key,
                    "symbol": symbol,
                })
    return flattened


def generate_api_change_summary(analysis_dir: pathlib.Path, output_path: Optional[pathlib.Path] = None) -> Dict[str, object]:
    analysis_dir = analysis_dir.expanduser().resolve()
    version_diff_root = analysis_dir / "version-diff"
    baseline_map = load_member_map(version_diff_root, "baseline")
    target_map = load_member_map(version_diff_root, "target")

    baseline_classes = set(baseline_map.keys())
    target_classes = set(target_map.keys())
    removed_classes = sorted(baseline_classes - target_classes)
    added_classes = sorted(target_classes - baseline_classes)
    shared_classes = sorted(baseline_classes & target_classes)

    changed_classes: Dict[str, Dict[str, object]] = {}
    for class_name in shared_classes:
        baseline = baseline_map[class_name]
        target = target_map[class_name]
        removed_ctors, added_ctors = diff_members(baseline["constructors"], target["constructors"])
        removed_methods, added_methods = diff_members(baseline["methods"], target["methods"])
        removed_fields, added_fields = diff_members(baseline["fields"], target["fields"])
        if not any([removed_ctors, added_ctors, removed_methods, added_methods, removed_fields, added_fields]):
            continue
        changed_classes[class_name] = {
            "removed_constructors": removed_ctors,
            "added_constructors": added_ctors,
            "removed_methods": removed_methods,
            "added_methods": added_methods,
            "removed_fields": removed_fields,
            "added_fields": added_fields,
        }

    summary = {
        "analysis_dir": str(analysis_dir),
        "version_diff_root": str(version_diff_root),
        "removed_classes": removed_classes,
        "added_classes": added_classes,
        "changed_classes": changed_classes,
        "breaking_change_candidates": flatten_breaking_changes(changed_classes),
        "stats": {
            "removed_class_count": len(removed_classes),
            "added_class_count": len(added_classes),
            "changed_class_count": len(changed_classes),
            "breaking_change_candidate_count": len(flatten_breaking_changes(changed_classes)),
        },
    }

    resolved_output = output_path or (version_diff_root / "api-change-summary.json")
    write_json(resolved_output, summary)
    return summary


def main() -> int:
    args = parse_args()
    summary = generate_api_change_summary(
        analysis_dir=pathlib.Path(args.analysis_dir),
        output_path=pathlib.Path(args.output).expanduser().resolve() if args.output else None,
    )
    json.dump(summary, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
