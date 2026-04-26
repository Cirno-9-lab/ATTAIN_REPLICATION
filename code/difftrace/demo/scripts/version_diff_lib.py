#!/usr/bin/env python3

import os
import pathlib
import re
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from trace_workflow_lib import ArtifactCoordinate, read_text, run_command, unified_diff_text, write_json, write_text


@dataclass
class ArtifactDiffResult:
    root: pathlib.Path
    baseline_jar: pathlib.Path
    target_jar: pathlib.Path
    baseline_pom: pathlib.Path
    target_pom: pathlib.Path
    changed_classes: List[str]
    added_classes: List[str]
    removed_classes: List[str]


def local_maven_repository() -> pathlib.Path:
    return pathlib.Path.home() / ".m2" / "repository"


def resolve_artifact_file(coordinate: ArtifactCoordinate, version: str, extension: str) -> pathlib.Path:
    artifact_dir = local_maven_repository() / coordinate.group_id.replace(".", "/") / coordinate.artifact_id / version
    artifact_file = artifact_dir / "{}-{}.{}".format(coordinate.artifact_id, version, extension)
    if not artifact_file.exists():
        raise SystemExit("Artifact file does not exist: {}".format(artifact_file))
    return artifact_file


def read_jar_class_entries(jar_path: pathlib.Path) -> Dict[str, bytes]:
    entries: Dict[str, bytes] = {}
    with zipfile.ZipFile(str(jar_path), "r") as archive:
        for name in archive.namelist():
            if not name.endswith(".class"):
                continue
            entries[name] = archive.read(name)
    return entries


def class_entry_to_name(entry: str) -> str:
    return entry[:-6].replace("/", ".")


def diff_output_path(root: pathlib.Path, directory: str, class_entry: str) -> pathlib.Path:
    return root / directory / (class_entry[:-6] + ".diff")


def raw_output_path(root: pathlib.Path, directory: str, label: str, class_entry: str) -> pathlib.Path:
    return root / directory / label / (class_entry[:-6] + ".txt")


def normalize_class_prefix(prefix: str) -> str:
    normalized = str(prefix or "").strip().replace(".", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    normalized = normalized.lstrip("/")
    if normalized and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def class_prefix_filters_from_env() -> List[str]:
    raw_value = os.environ.get("DIFFTRACE_VERSION_DIFF_CLASS_PREFIXES", "")
    filters: List[str] = []
    for token in re.split(r"[,;\s]+", raw_value):
        normalized = normalize_class_prefix(token)
        if normalized and normalized not in filters:
            filters.append(normalized)
    return filters


def filter_class_entries(class_entries: Dict[str, bytes], prefixes: Sequence[str]) -> Dict[str, bytes]:
    normalized_prefixes = [normalize_class_prefix(prefix) for prefix in prefixes if normalize_class_prefix(prefix)]
    if not normalized_prefixes:
        return class_entries
    return {
        name: payload
        for name, payload in class_entries.items()
        if any(name.startswith(prefix) for prefix in normalized_prefixes)
    }


def javap_dump(jar_path: pathlib.Path, class_name: str, include_code: bool) -> str:
    command = [
        "javap",
        "-classpath",
        str(jar_path),
        "-p",
        "-c" if include_code else "-s",
        class_name,
    ]
    result = run_command(command, cwd=jar_path.parent)
    header = "$ {}\n".format(result.command_str())
    return header + result.output


def write_class_diff(
    root: pathlib.Path,
    diff_directory: str,
    raw_directory: str,
    class_entry: str,
    baseline_label: str,
    baseline_dump: str,
    target_label: str,
    target_dump: str,
) -> None:
    baseline_path = raw_output_path(root, raw_directory, "baseline", class_entry)
    target_path = raw_output_path(root, raw_directory, "target", class_entry)
    write_text(baseline_path, baseline_dump)
    write_text(target_path, target_dump)

    diff_text = unified_diff_text(
        baseline_dump.splitlines(True),
        target_dump.splitlines(True),
        fromfile=baseline_label,
        tofile=target_label,
    )
    write_text(diff_output_path(root, diff_directory, class_entry), diff_text or "(no textual diff)\n")


def write_class_outputs(
    root: pathlib.Path,
    class_entry: str,
    baseline_version: str,
    target_version: str,
    baseline_dump: str,
    target_dump: str,
    baseline_api_dump: str,
    target_api_dump: str,
) -> None:
    class_name = class_entry_to_name(class_entry)
    write_class_diff(
        root=root,
        diff_directory="diffs",
        raw_directory="raw",
        class_entry=class_entry,
        baseline_label="{}:{}".format(baseline_version, class_name),
        baseline_dump=baseline_dump,
        target_label="{}:{}".format(target_version, class_name),
        target_dump=target_dump,
    )
    write_class_diff(
        root=root,
        diff_directory="api-diffs",
        raw_directory="api-raw",
        class_entry=class_entry,
        baseline_label="{}:{}".format(baseline_version, class_name),
        baseline_dump=baseline_api_dump,
        target_label="{}:{}".format(target_version, class_name),
        target_dump=target_api_dump,
    )


def write_llm_guide(root: pathlib.Path) -> None:
    guide = "\n".join(
        [
            "Use these files in this order when selecting relevant version diff hunks:",
            "1. summary.json for counts and quick class previews.",
            "2. removed-classes.txt and added-classes.txt for missing or introduced classes.",
            "3. api-diffs/*.diff for signature-level changes that are easiest for an LLM to read.",
            "4. diffs/*.diff for bytecode-level behavior changes from javap -c -p when API diffs are not enough.",
            "5. pom.diff when the dependency metadata itself changed.",
            "",
            "The api-diffs directory contains javap -p -s output without method bodies.",
            "The diffs directory contains javap -c -p output with bytecode instructions.",
        ]
    )
    write_text(root / "llm-guide.txt", guide + "\n")


def generate_artifact_diff(
    coordinate: ArtifactCoordinate,
    baseline_version: str,
    target_version: str,
    output_root: pathlib.Path,
) -> ArtifactDiffResult:
    output_root.mkdir(parents=True, exist_ok=True)

    baseline_jar = resolve_artifact_file(coordinate, baseline_version, "jar")
    target_jar = resolve_artifact_file(coordinate, target_version, "jar")
    baseline_pom = resolve_artifact_file(coordinate, baseline_version, "pom")
    target_pom = resolve_artifact_file(coordinate, target_version, "pom")

    class_prefix_filters = class_prefix_filters_from_env()
    baseline_classes = filter_class_entries(read_jar_class_entries(baseline_jar), class_prefix_filters)
    target_classes = filter_class_entries(read_jar_class_entries(target_jar), class_prefix_filters)

    baseline_entries = set(baseline_classes.keys())
    target_entries = set(target_classes.keys())
    added_classes = sorted(target_entries - baseline_entries)
    removed_classes = sorted(baseline_entries - target_entries)
    common_classes = sorted(baseline_entries & target_entries)
    changed_classes = [entry for entry in common_classes if baseline_classes[entry] != target_classes[entry]]

    write_text(output_root / "baseline-pom.xml", read_text(baseline_pom))
    write_text(output_root / "target-pom.xml", read_text(target_pom))
    pom_diff = unified_diff_text(
        read_text(baseline_pom).splitlines(True),
        read_text(target_pom).splitlines(True),
        fromfile=str(baseline_pom),
        tofile=str(target_pom),
    )
    write_text(output_root / "pom.diff", pom_diff or "(no pom diff)\n")

    write_text(output_root / "added-classes.txt", "\n".join(added_classes) + ("\n" if added_classes else ""))
    write_text(output_root / "removed-classes.txt", "\n".join(removed_classes) + ("\n" if removed_classes else ""))
    write_text(output_root / "changed-classes.txt", "\n".join(changed_classes) + ("\n" if changed_classes else ""))
    write_llm_guide(output_root)

    for class_entry in changed_classes:
        class_name = class_entry_to_name(class_entry)
        write_class_outputs(
            root=output_root,
            class_entry=class_entry,
            baseline_version=baseline_version,
            target_version=target_version,
            baseline_dump=javap_dump(baseline_jar, class_name, include_code=True),
            target_dump=javap_dump(target_jar, class_name, include_code=True),
            baseline_api_dump=javap_dump(baseline_jar, class_name, include_code=False),
            target_api_dump=javap_dump(target_jar, class_name, include_code=False),
        )

    for class_entry in added_classes:
        class_name = class_entry_to_name(class_entry)
        write_class_outputs(
            root=output_root,
            class_entry=class_entry,
            baseline_version=baseline_version,
            target_version=target_version,
            baseline_dump="",
            target_dump=javap_dump(target_jar, class_name, include_code=True),
            baseline_api_dump="",
            target_api_dump=javap_dump(target_jar, class_name, include_code=False),
        )

    for class_entry in removed_classes:
        class_name = class_entry_to_name(class_entry)
        write_class_outputs(
            root=output_root,
            class_entry=class_entry,
            baseline_version=baseline_version,
            target_version=target_version,
            baseline_dump=javap_dump(baseline_jar, class_name, include_code=True),
            target_dump="",
            baseline_api_dump=javap_dump(baseline_jar, class_name, include_code=False),
            target_api_dump="",
        )

    summary = {
        "artifact": coordinate.gav(),
        "baseline_version": baseline_version,
        "target_version": target_version,
        "baseline_jar": str(baseline_jar),
        "target_jar": str(target_jar),
        "baseline_pom": str(baseline_pom),
        "target_pom": str(target_pom),
        "class_prefix_filters": class_prefix_filters,
        "llm_guide": "llm-guide.txt",
        "api_diff_directory": "api-diffs",
        "bytecode_diff_directory": "diffs",
        "changed_class_count": len(changed_classes),
        "added_class_count": len(added_classes),
        "removed_class_count": len(removed_classes),
        "changed_classes_preview": changed_classes[:50],
        "added_classes_preview": added_classes[:50],
        "removed_classes_preview": removed_classes[:50],
    }
    write_json(output_root / "summary.json", summary)

    return ArtifactDiffResult(
        root=output_root,
        baseline_jar=baseline_jar,
        target_jar=target_jar,
        baseline_pom=baseline_pom,
        target_pom=target_pom,
        changed_classes=changed_classes,
        added_classes=added_classes,
        removed_classes=removed_classes,
    )


def _normalize_diff_relative_path(diff_relative_path: str) -> pathlib.Path:
    relative = pathlib.Path(diff_relative_path)
    if not relative.parts:
        raise ValueError("Empty diff_relative_path")
    if relative.parts[0] == "version-diff":
        relative = pathlib.Path(*relative.parts[1:])
    if not relative.parts:
        raise ValueError("diff_relative_path must point inside version-diff")
    return relative



def _resolve_raw_context_paths(diff_root: pathlib.Path, diff_relative_path: str) -> Tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    relative = _normalize_diff_relative_path(diff_relative_path)
    category = relative.parts[0]
    if category == "api-diffs":
        raw_dir = diff_root / "api-raw"
    elif category == "diffs":
        raw_dir = diff_root / "raw"
    else:
        raise ValueError("Unsupported diff directory: {}".format(category))

    class_relative = pathlib.Path(*relative.parts[1:]).with_suffix(".txt")
    return (
        diff_root / relative,
        raw_dir / "baseline" / class_relative,
        raw_dir / "target" / class_relative,
    )



def _read_lines(path: pathlib.Path) -> List[str]:
    if not path.exists() or not path.is_file():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()



def _coerce_anchor_terms(text: str) -> List[str]:
    if not text:
        return []
    candidates = re.split(r"[,\n]+", text)
    tokens: List[str] = []
    seen = set()
    for candidate in candidates:
        candidate = candidate.strip().strip('"')
        if len(candidate) < 3:
            continue
        if candidate not in seen:
            seen.add(candidate)
            tokens.append(candidate)
        for token in re.findall(r"[A-Za-z_$][A-Za-z0-9_$.<>#:/()-]{2,}", candidate):
            if token not in seen:
                seen.add(token)
                tokens.append(token)
    return tokens[:24]



def _extract_anchor_terms_from_diff(diff_lines: Sequence[str], max_terms: int = 24) -> List[str]:
    anchors: List[str] = []
    seen = set()
    for line in diff_lines:
        if not line:
            continue
        if line.startswith(("+++", "---", "@@")):
            continue
        if line[0] not in "+-":
            continue
        content = line[1:].strip()
        if not content:
            continue
        for token in _coerce_anchor_terms(content):
            if token not in seen:
                seen.add(token)
                anchors.append(token)
            if len(anchors) >= max_terms:
                return anchors
    return anchors



def _find_best_anchor_line(lines: Sequence[str], anchor_terms: Sequence[str]) -> Optional[int]:
    normalized_terms = [term.lower() for term in anchor_terms if term and len(term) >= 3]
    if not lines or not normalized_terms:
        return None

    best_line: Optional[int] = None
    best_score = 0
    for index, line in enumerate(lines, start=1):
        haystack = line.lower()
        score = 0
        for term in normalized_terms:
            if term in haystack:
                score += max(1, min(4, len(term) // 10 + 1))
        if score > best_score:
            best_score = score
            best_line = index
    return best_line



def _line_window(total_lines: int, center_line: int, context_lines: int) -> Tuple[int, int]:
    if total_lines <= 0:
        return (0, 0)
    start = max(1, center_line - context_lines)
    end = min(total_lines, center_line + context_lines)
    return (start, end)



def _render_preview(lines: Sequence[str], start_line: int, end_line: int) -> str:
    if not lines or start_line <= 0 or end_line <= 0:
        return ""
    rendered = []
    for index in range(start_line, end_line + 1):
        rendered.append("{:05d}: {}".format(index, lines[index - 1]))
    return "\n".join(rendered)



def _resolve_context_scope(scope: str) -> List[str]:
    normalized = (scope or "all").strip().lower()
    if normalized in {"all", "*"}:
        return ["api-raw", "raw"]
    if normalized in {"api", "api-raw"}:
        return ["api-raw"]
    if normalized in {"bytecode", "raw", "diff"}:
        return ["raw"]
    raise ValueError("Unsupported context scope: {}".format(scope))



def load_version_diff_context(
    diff_root: pathlib.Path,
    diff_relative_path: str,
    hunk_hint: str = "",
    diff_start_line: Optional[int] = None,
    diff_end_line: Optional[int] = None,
    context_lines: int = 20,
) -> Dict[str, object]:
    """Resolve raw baseline/target files for a diff and return a context preview around the best anchor."""
    diff_path, baseline_raw, target_raw = _resolve_raw_context_paths(diff_root, diff_relative_path)
    diff_lines = _read_lines(diff_path)
    baseline_lines = _read_lines(baseline_raw)
    target_lines = _read_lines(target_raw)

    snippet_start = max(1, diff_start_line or 1)
    snippet_end = min(len(diff_lines), diff_end_line or len(diff_lines))
    diff_excerpt_lines = diff_lines[snippet_start - 1:snippet_end] if diff_lines else []

    anchor_terms = _coerce_anchor_terms(hunk_hint)
    anchor_terms.extend(
        term for term in _extract_anchor_terms_from_diff(diff_excerpt_lines or diff_lines)
        if term not in anchor_terms
    )

    baseline_anchor = _find_best_anchor_line(baseline_lines, anchor_terms)
    target_anchor = _find_best_anchor_line(target_lines, anchor_terms)
    baseline_start, baseline_end = _line_window(len(baseline_lines), baseline_anchor or 1, context_lines)
    target_start, target_end = _line_window(len(target_lines), target_anchor or 1, context_lines)

    return {
        "diff_path": str(diff_path),
        "baseline_raw_path": str(baseline_raw),
        "target_raw_path": str(target_raw),
        "matched_anchor_terms": anchor_terms[:12],
        "diff_excerpt_start_line": snippet_start if diff_lines else 0,
        "diff_excerpt_end_line": snippet_end if diff_lines else 0,
        "diff_excerpt": _render_preview(diff_lines, snippet_start, snippet_end) if diff_lines else "",
        "baseline_context": {
            "anchor_line": baseline_anchor,
            "start_line": baseline_start,
            "end_line": baseline_end,
            "preview": _render_preview(baseline_lines, baseline_start, baseline_end),
        },
        "target_context": {
            "anchor_line": target_anchor,
            "start_line": target_start,
            "end_line": target_end,
            "preview": _render_preview(target_lines, target_start, target_end),
        },
    }



def search_version_diff_context(
    diff_root: pathlib.Path,
    query: str,
    limit: int = 10,
    scope: str = "all",
) -> List[Dict[str, object]]:
    tokens = [token.lower() for token in _coerce_anchor_terms(query)]
    if not tokens:
        return []

    results: List[Tuple[int, str, int, str, str, str]] = []
    for directory in _resolve_context_scope(scope):
        for variant in ("baseline", "target"):
            base_dir = diff_root / directory / variant
            if not base_dir.exists():
                continue
            for file_path in sorted(base_dir.rglob("*.txt")):
                try:
                    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                relative = file_path.relative_to(diff_root).as_posix()
                for index, line in enumerate(lines, start=1):
                    haystack = line.lower()
                    score = sum(1 for token in tokens if token in haystack)
                    if score <= 0:
                        continue
                    results.append((score, relative, index, line.strip(), directory, variant))

    results.sort(key=lambda item: (-item[0], item[1], item[2]))
    rendered: List[Dict[str, object]] = []
    for score, relative, line_number, line_text, directory, variant in results[: max(1, limit)]:
        rendered.append(
            {
                "score": score,
                "path": relative,
                "line": line_number,
                "scope": directory,
                "variant": variant,
                "text": line_text,
            }
        )
    return rendered
