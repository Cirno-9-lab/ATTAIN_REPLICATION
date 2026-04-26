#!/usr/bin/env python3

import argparse
import csv
import json
import os
import pathlib
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from llm_hunk_selector import (
    DIRECT_DIFF_PROMPT_VERSION,
    HUNK_JUDGMENT_PROMPT_VERSION,
    LLMAnalysisConfig,
    run_llm_hunk_judgment_sync,
    run_llm_vulnerability_judgment_sync,
)
from version_diff_lib import load_version_diff_context


REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
DEFAULT_OUTPUT_JSON = REPO_ROOT / "dataset" / "llm_hunk_analysis.json"
DEFAULT_OUTPUT_CSV = REPO_ROOT / "dataset" / "llm_hunk_analysis.csv"
DEFAULT_LLM_MODEL = "deepseek-v3"
DEFAULT_LLM_BASE_URL = "https://api.chatanywhere.tech/v1"
SECTION_NAMES = ["Diagnosis", "Selected Hunks", "Supporting Evidence", "Open Questions"]

VERDICT_VULNERABILITY_NOT_PRESENT = "vulnerability_not_present"
VERDICT_EXPLOIT_INVALID_DUE_TO_VERSION_CHANGE = "exploit_invalid_due_to_version_change"
VERDICT_UNDETERMINED = "undetermined"

VULNERABILITY_STATUS_NO = "no"
VULNERABILITY_STATUS_POSSIBLY_YES = "possibly_yes"
VULNERABILITY_STATUS_UNKNOWN = "unknown"

MIN_VULNERABILITY_PRESENCE_SCORE = 0
MAX_VULNERABILITY_PRESENCE_SCORE = 100
VULNERABILITY_PRESENCE_SCORE_NO_THRESHOLD = 45
VULNERABILITY_PRESENCE_SCORE_YES_THRESHOLD = 80

STRONG_VULNERABILITY_ABSENT_SIGNALS: Sequence[Tuple[str, str]] = [
    ("subtype_validator", r"\bsubtypevalidator\b|_validatesubtype"),
    (
        "target_added_validation_guard",
        r"\b(add(?:ed|s|ing)?|introduc(?:ed|es|ing)?|gain(?:ed|s)?|new)\b.{0,120}\b(validat\w+|validator|guard|check|reject\w+|invalid|sanitize\w+|filter\w+)\b",
    ),
    (
        "validation_helper_added",
        r"\b(ispayloadvalid|validate[a-z_]*|payload[- ]validation|invalid payload|decodingexception|validateqname|validatencname|validatename)\b",
    ),
    (
        "security_gate",
        r"\b(anytypepermission|notypepermission|explicittypepermission|typepermission|allowtypes?|denytypes?|allowlist|whitelist|blacklist)\b",
    ),
    (
        "blocking_language",
        r"\b(reject(?:ed|s|ing)?|block(?:ed|s|ing)?|prevent(?:ed|s|ing)?|forbid(?:den|s|ding)?|disallow(?:ed|s|ing)?|den(?:y|ied|ies)|mitigat(?:e|es|ed|ion)|hardening|security fix|patched?)\b",
    ),
    (
        "xxe_or_entity_resolution_block",
        r"(?:xxe|entity resol\w+|external entit\w+).{0,30}\b(disabl\w+|block\w+|prevent\w+|off)\b",
    ),
]

WEAK_VULNERABILITY_ABSENT_SIGNALS: Sequence[Tuple[str, str]] = [
    ("runtime_checks", r"\b(additional|extra|new|stricter)\s+(runtime\s+)?checks?\b"),
    ("validator_or_validation_failure", r"\bvalidator\b|\bvalidation failures?\b|\binvalid subtype\b|\binvalid payload\b"),
    ("security_term", r"\bsecurity\b"),
]

STRONG_EXPLOIT_CHANGE_SIGNALS: Sequence[Tuple[str, str]] = [
    (
        "removed_or_missing_api",
        r"\b(missing symbol|cannot find symbol|removed from target|target (?:lacks?|miss(?:es|ing))|no longer exists in target|compile failure due to missing)\b",
    ),
    (
        "compatibility_breakage",
        r"\b(verifyerror|linkageerror|binary incompat|class[- ]layout|stack/frame|classloading|loader confusion|mixed[^\n]{0,40}classpath|incompatible mix|compat replay)\b",
    ),
    (
        "symbol_resolution_breakage",
        r"\b(nosuchmethod(?:error)?|nosuchfield(?:error)?|classnotfound(?:exception)?|noclassdeffound(?:error)?)\b",
    ),
    ("api_shape_change", r"\b(signature|constructor|visibility|descriptor|field layout|api-level removals?)\b"),
    ("refactor_or_rework", r"\b(refactor(?:ed|ing)?|rework(?:ed|ing)?|abstract/internal api|threadlocal|initialization order|api reorganization|rename[ds]?)\b"),
]

WEAK_EXPLOIT_CHANGE_SIGNALS: Sequence[Tuple[str, str]] = [
    ("behavior_change", r"\bbehavior(?:al)? change\b|\bdifferent code path\b|\bfallback\b|\btrace divergence\b"),
    ("runtime_or_factory_breakage", r"\b(mapper|codec|factory|classpath|runtime mismatch|binary replay)\b"),
]

UNCERTAINTY_SIGNALS: Sequence[Tuple[str, str]] = [
    ("hedged_language", r"\b(most likely|plausible|plausibly|could|may|might)\b"),
    ("needs_more_context", r"\bif needed\b|\bcan you provide\b|\bwould confirm\b"),
]

STRUCTURAL_EXPLOIT_FAILURE_SUBTYPES = {
    "binary_incompatibility",
    "missing_class",
    "missing_method",
    "signature_change",
    "constructor_signature_change",
}

STRUCTURAL_FAILURE_SCENARIOS = {"process_failure", "compile_failure", "execution_failure"}
DIFF_PATH_PATTERN = re.compile(r"((?:version-diff/)?(?:api-diffs|diffs)/[^\s)]+?\.diff)")
SELECTED_EVIDENCE_PATH_PATTERN = re.compile(
    r"((?:version-diff/)?(?:api-diffs|diffs)/[^\s)]+?\.diff|version-diff/pom\.diff|version-diff/summary\.json|dependency-tree\.diff|trace-diff-summary\.txt|(?:baseline|target)-observation-excerpt\.txt|target-prepare-generator-excerpt\.txt|execution-observations\.json)"
)
SUPPLEMENTAL_JUDGMENT_PATHS = [
    "trace-diff-summary.txt",
    "target-observation-excerpt.txt",
    "baseline-observation-excerpt.txt",
    "target-prepare-generator-excerpt.txt",
    "dependency-tree.diff",
    "execution-observations.json",
    "version-diff/pom.diff",
    "version-diff/summary.json",
]
NUMBERED_ITEM_PATTERN = re.compile(r"^\d+[\.)]\s+")
INLINE_DIFF_LINE_PATTERN = re.compile(r"^\s*(?:--- |\+\+\+ |@@ |diff --git |index |[+-][^+-])")
MAX_DIRECT_DIFF_LINES = 80
MAX_DIRECT_DIFF_CHARS = 5200
MAX_DIRECT_DIFF_HUNKS = 5
MAX_SUPPLEMENTAL_JUDGMENT_ITEMS = 4
MAX_ALIGNED_CONTEXT_LINES = 36
MAX_ALIGNED_CONTEXT_CHARS = 2600
WEAK_HUNK_BASENAME_PATTERN = re.compile(r"\$\d+\.diff$", flags=re.IGNORECASE)
LOGGER_NOISE_PATTERN = re.compile(r"\b(?:internalloggerfactory|internallogger|loggerfactory)\b", flags=re.IGNORECASE)
SWITCH_MAP_PATTERN = re.compile(r"\$switchmap|switch\s*map", flags=re.IGNORECASE)
ENUM_REORDER_PATTERN = re.compile(r"\benum\b.{0,80}\b(?:ordinal|values\(\))\b", flags=re.IGNORECASE | re.DOTALL)
FIX_KEYWORD_PATTERN = re.compile(
    r"\b(validate\w*|validator\w*|validation|guard\w*|check\w*|reject\w*|invalid|sanitize\w*|block\w*|filter\w*|hardening|security fix|patched?)\b",
    flags=re.IGNORECASE,
)
COMPATIBILITY_ONLY_FAILURE_SUBTYPES = STRUCTURAL_EXPLOIT_FAILURE_SUBTYPES | {
    "asm_instrumentation_failure",
    "dependency_resolution_failure",
    "toolchain_incompatibility",
    "trace_agent_initialization_failure",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate per-case llm-hunk-analysis.md outputs into a JSON/CSV table for downstream "
            "analysis and plotting."
        )
    )
    parser.add_argument(
        "--batch-summary",
        required=True,
        help="Path to the batch-summary.json that provides case metadata and analysis_dir.",
    )
    parser.add_argument(
        "--status-filter",
        default="trace_diff,execution_failure",
        help="Comma-separated case.status values to include. Default: trace_diff,execution_failure",
    )
    parser.add_argument(
        "--output-json",
        default=str(DEFAULT_OUTPUT_JSON),
        help=f"Path to output JSON summary. Default: {DEFAULT_OUTPUT_JSON}",
    )
    parser.add_argument(
        "--output-csv",
        default=str(DEFAULT_OUTPUT_CSV),
        help=f"Path to output CSV summary. Default: {DEFAULT_OUTPUT_CSV}",
    )
    parser.add_argument(
        "--require-final-response",
        action="store_true",
        help="Only aggregate cases whose llm-hunk-analysis.md contains a parsed Final response block.",
    )
    parser.add_argument(
        "--judgment-mode",
        choices=["rule", "llm", "hybrid"],
        default="hybrid",
        help=(
            "How to derive the final vulnerability judgment. "
            "rule = heuristic scoring only; llm = deepseek-v3 only; "
            "hybrid = prefer cached/generated LLM judgment and fall back to rule. Default: hybrid"
        ),
    )
    parser.add_argument(
        "--llm-model",
        default=DEFAULT_LLM_MODEL,
        help=f"LLM model name for the final judgment stage. Default: {DEFAULT_LLM_MODEL}",
    )
    parser.add_argument(
        "--llm-base-url",
        default=DEFAULT_LLM_BASE_URL,
        help=f"LLM base URL for the final judgment stage. Default: {DEFAULT_LLM_BASE_URL}",
    )
    parser.add_argument(
        "--llm-api-key",
        default=None,
        help="Optional API key for final judgment. Defaults to CHATANYWHERE_API_KEY or OPENAI_API_KEY.",
    )
    parser.add_argument(
        "--refresh-llm-judgment",
        action="store_true",
        help="Regenerate analysis_dir/llm-vulnerability-judgment.json even if it already exists.",
    )
    return parser.parse_args()


def iter_selected_cases(summary: dict, status_filter: Iterable[str]) -> Iterable[dict]:
    """迭代需要送入 LLM 聚合的 case。

    默认只选择 status 在 status_filter 集合中的 case（例如 trace_diff / execution_failure）。
    但对于 seek_patch=false 的特殊场景，如果 case.status 是 no_diff，也强制保留，
    避免这类“未找到有效 trace 差异”的对照样本完全缺失于后续评估。
    """

    wanted = {status.strip() for status in status_filter if status.strip()}
    for case in summary.get("cases", []):
        status = case.get("status")
        seek_patch = case.get("seek_patch")
        if isinstance(seek_patch, bool):
            seek_patch_false = seek_patch is False
        elif seek_patch is None:
            seek_patch_false = False
        else:
            seek_patch_false = str(seek_patch).strip().lower() == "false"

        if wanted and status not in wanted:
            # 例外：no_diff + seek_patch=false 也要参与后续聚合
            if not (status == "no_diff" and seek_patch_false):
                continue
        yield case


def extract_final_response(markdown_text: str) -> Optional[str]:
    marker = "Final response:"
    if marker not in markdown_text:
        return None
    tail = markdown_text.split(marker)[-1].strip()
    return tail or None


def normalize_section_heading(raw_heading: str) -> str:
    normalized = raw_heading.strip()
    normalized = re.sub(r"^#+\s*", "", normalized)
    normalized = re.sub(r"^(?:[-*+]\s+|\d+[\.)]\s+)", "", normalized)
    normalized = re.sub(r"^\*\*(.*?)\*\*$", r"\1", normalized)
    normalized = normalized.strip().strip(":：").strip()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def parse_sections(final_response: str) -> Dict[str, str]:
    sections: Dict[str, List[str]] = {name: [] for name in SECTION_NAMES}
    current: Optional[str] = None
    for raw_line in final_response.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            continue
        normalized_heading = normalize_section_heading(stripped)
        if normalized_heading in sections:
            current = normalized_heading
            continue
        if current is not None:
            sections[current].append(raw_line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def normalize_diff_path(path: object) -> str:
    raw = str(path or "").strip()
    if not raw:
        return ""
    if raw.startswith("version-diff/"):
        return raw
    if raw.startswith(("api-diffs/", "diffs/")):
        return f"version-diff/{raw}"
    return raw



def classify_evidence_kind(path: object) -> str:
    normalized = normalize_diff_path(path)
    if normalized.startswith("version-diff/api-diffs/"):
        return "api_diff"
    if normalized.startswith("version-diff/diffs/"):
        return "bytecode_diff"
    if normalized == "version-diff/pom.diff":
        return "pom_diff"
    if normalized == "version-diff/summary.json":
        return "version_diff_summary"
    if normalized == "dependency-tree.diff":
        return "dependency_tree_diff"
    if normalized == "trace-diff-summary.txt":
        return "trace_summary"
    if normalized.endswith("-observation-excerpt.txt"):
        return "observation_excerpt"
    if normalized == "execution-observations.json":
        return "execution_observations"
    return "generic_file"



def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for item in items:
        normalized = str(item or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _coerce_string_list(value: object) -> List[str]:
    if isinstance(value, list):
        return _dedupe_preserve_order(str(item).strip() for item in value if str(item).strip())
    if value in (None, ""):
        return []
    return _dedupe_preserve_order(str(value).split(","))


def trace_invalid_reasons_from_case(case: dict, scenario: Optional[dict] = None) -> List[str]:
    direct = _coerce_string_list(case.get("trace_invalid_reasons"))
    if direct:
        return direct
    if scenario:
        direct = _coerce_string_list(scenario.get("trace_invalid_reasons"))
        if direct:
            return direct
    return []


def has_effective_trace_difference(case: dict, scenario: Optional[dict] = None) -> bool:
    direct = case.get("trace_has_effective_difference")
    if direct in (True, False):
        return bool(direct)
    if scenario is not None:
        scenario_value = scenario.get("trace_has_effective_difference")
        if scenario_value in (True, False):
            return bool(scenario_value)
    raw = case.get("trace_has_difference")
    if raw in (None, "") and scenario is not None:
        raw = scenario.get("trace_has_difference")
    return bool(raw) and not trace_invalid_reasons_from_case(case, scenario)


def _payload_weak_signal_reasons(payload: Dict[str, object]) -> List[str]:
    normalized_path = normalize_diff_path(payload.get("path"))
    evidence_kind = classify_evidence_kind(normalized_path)
    basename = pathlib.PurePosixPath(normalized_path).name.lower() if normalized_path else ""
    combined_text = "\n".join(
        str(payload.get(key) or "") for key in ("details", "diff_excerpt")
    )
    lowered_text = combined_text.lower()

    reasons: List[str] = []
    if evidence_kind not in {"api_diff", "bytecode_diff"}:
        reasons.append("fallback_evidence")
    if WEAK_HUNK_BASENAME_PATTERN.search(basename):
        reasons.append("synthetic_inner_class")
    if SWITCH_MAP_PATTERN.search(lowered_text) or ENUM_REORDER_PATTERN.search(lowered_text):
        reasons.append("switch_map_or_enum_reorder")
    if LOGGER_NOISE_PATTERN.search(basename + "\n" + lowered_text) and not FIX_KEYWORD_PATTERN.search(combined_text):
        reasons.append("logger_only_change")
    return _dedupe_preserve_order(reasons)


def _annotate_payload_signal_metadata(
    payload: Dict[str, object],
    trace_invalid_reasons: Optional[List[str]] = None,
) -> Dict[str, object]:
    annotated = dict(payload)
    weak_signal_reasons = _payload_weak_signal_reasons(annotated)
    normalized_path = normalize_diff_path(annotated.get("path"))
    if normalized_path == "trace-diff-summary.txt" and trace_invalid_reasons:
        weak_signal_reasons = _dedupe_preserve_order(
            list(weak_signal_reasons) + ["invalid_trace_summary"]
        )

    signal_weight = 1.0
    if "invalid_trace_summary" in weak_signal_reasons:
        signal_weight = 0.0
    elif any(
        reason in weak_signal_reasons
        for reason in {"synthetic_inner_class", "switch_map_or_enum_reorder", "logger_only_change"}
    ):
        signal_weight = 0.25
    elif "fallback_evidence" in weak_signal_reasons:
        signal_weight = 0.35

    annotated["weak_signal_reasons"] = weak_signal_reasons
    annotated["signal_weight"] = signal_weight
    if normalized_path == "trace-diff-summary.txt" and trace_invalid_reasons:
        details = str(annotated.get("details") or "").strip()
        caution = "Signal caution: trace summary was auto-marked invalid ({})".format(
            ", ".join(trace_invalid_reasons)
        )
        annotated["details"] = "\n".join(part for part in [details, caution] if part)
    return annotated


def _payload_signal_weight(payload: Optional[Dict[str, object]]) -> float:
    if not payload:
        return 1.0
    try:
        return float(payload.get("signal_weight", 1.0))
    except (TypeError, ValueError):
        return 1.0


def truncate_multiline_text(text: str, max_lines: int = MAX_DIRECT_DIFF_LINES, max_chars: int = MAX_DIRECT_DIFF_CHARS) -> str:
    raw_lines = text.splitlines()
    clipped_lines = raw_lines[: max(1, max_lines)]
    clipped = "\n".join(clipped_lines)
    truncated = len(raw_lines) > len(clipped_lines)
    if len(clipped) > max_chars:
        clipped = clipped[:max_chars].rstrip()
        newline_index = clipped.rfind("\n")
        if newline_index > 0:
            clipped = clipped[:newline_index]
        truncated = True
    if truncated:
        clipped = clipped.rstrip() + "\n...(truncated)"
    return clipped



def extract_inline_diff_excerpt(details_text: str) -> str:
    lines = []
    for raw_line in details_text.splitlines():
        if INLINE_DIFF_LINE_PATTERN.match(raw_line):
            lines.append(raw_line.rstrip())
    if not lines:
        return ""
    return truncate_multiline_text("\n".join(lines))



def _read_text_if_exists(path: pathlib.Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")



def _paired_bytecode_diff_path(diff_path: str) -> str:
    normalized = normalize_diff_path(diff_path)
    if not normalized.startswith("version-diff/api-diffs/"):
        return ""
    return normalized.replace("version-diff/api-diffs/", "version-diff/diffs/", 1)



def _looks_like_shallow_api_hunk(diff_path: str, diff_excerpt: str) -> bool:
    normalized = normalize_diff_path(diff_path)
    if not normalized.startswith("version-diff/api-diffs/"):
        return False
    signal_lines = [
        line.strip()
        for line in diff_excerpt.splitlines()
        if line.strip().startswith(("+", "-")) and not line.strip().startswith(("+++", "---", "+$", "-$"))
    ]
    if not signal_lines:
        return True
    declaration_only_lines = []
    for line in signal_lines:
        stripped = line[1:].strip()
        is_declaration_only = any(
            marker in stripped
            for marker in (" class ", " interface ", " enum ", "descriptor:", "Compiled from", "flags:")
        )
        is_field_like = "(" not in stripped and ")" not in stripped and stripped.endswith(";")
        is_signature_like = "(" in stripped and ")" in stripped and "descriptor:" not in stripped and " throws " not in stripped
        if is_declaration_only or is_field_like or is_signature_like:
            declaration_only_lines.append(line)
    if len(signal_lines) <= 8 and len(declaration_only_lines) == len(signal_lines):
        return True
    if len(signal_lines) <= 10 and not FIX_KEYWORD_PATTERN.search("\n".join(signal_lines)):
        if all("Code:" not in line and "invoke" not in line for line in signal_lines):
            return True
    return False



def _should_force_paired_bytecode_context(diff_path: str, diff_excerpt: str) -> bool:
    normalized = normalize_diff_path(diff_path)
    if not normalized.startswith("version-diff/api-diffs/"):
        return False
    basename = pathlib.PurePosixPath(normalized).name.lower()
    if LOGGER_NOISE_PATTERN.search(basename):
        return False
    if "$" not in basename:
        return True
    return bool(FIX_KEYWORD_PATTERN.search(diff_excerpt) and not WEAK_HUNK_BASENAME_PATTERN.search(basename))



def _build_paired_bytecode_excerpt(analysis_root: pathlib.Path, diff_path: str) -> str:
    paired_path = _paired_bytecode_diff_path(diff_path)
    if not paired_path:
        return ""
    paired_text = _read_text_if_exists(analysis_root / paired_path)
    if not paired_text:
        return ""
    return truncate_multiline_text(paired_text, max_lines=64, max_chars=4200)



def _top_level_sibling_diff_paths(diff_path: str) -> List[str]:
    normalized = normalize_diff_path(diff_path)
    pure_path = pathlib.PurePosixPath(normalized)
    basename = pure_path.name
    if "$" not in basename or not normalized.startswith("version-diff/"):
        return []

    top_level_name = basename.split("$", 1)[0] + ".diff"
    sibling_paths: List[str] = []
    sibling_paths.append(str(pure_path.with_name(top_level_name)))
    if normalized.startswith("version-diff/diffs/"):
        sibling_paths.append(normalized.replace("version-diff/diffs/", "version-diff/api-diffs/", 1).rsplit("/", 1)[0] + "/" + top_level_name)
    elif normalized.startswith("version-diff/api-diffs/"):
        sibling_paths.append(normalized.replace("version-diff/api-diffs/", "version-diff/diffs/", 1).rsplit("/", 1)[0] + "/" + top_level_name)
    return unique_preserve_order(path for path in sibling_paths if path != normalized)



def _should_expand_with_raw_context(diff_path: str, evidence_kind: str, diff_excerpt: str, paired_bytecode_path: str = "") -> bool:
    normalized = normalize_diff_path(diff_path)
    if evidence_kind not in {"api_diff", "bytecode_diff"}:
        return False
    basename = pathlib.PurePosixPath(normalized).name.lower()
    if LOGGER_NOISE_PATTERN.search(basename):
        return False
    if "$" not in basename:
        return True
    if paired_bytecode_path:
        return True
    return bool(FIX_KEYWORD_PATTERN.search(diff_excerpt))



def _build_aligned_raw_context_excerpt(analysis_root: pathlib.Path, diff_path: str, diff_excerpt: str) -> str:
    normalized = normalize_diff_path(diff_path)
    try:
        context_payload = load_version_diff_context(
            diff_root=analysis_root / "version-diff",
            diff_relative_path=normalized,
            hunk_hint=diff_excerpt,
            context_lines=8,
        )
    except Exception:
        return ""

    baseline_context = context_payload.get("baseline_context") or {}
    target_context = context_payload.get("target_context") or {}
    baseline_preview = str(baseline_context.get("preview") or "").strip()
    target_preview = str(target_context.get("preview") or "").strip()
    if not baseline_preview and not target_preview:
        return ""

    lines = ["Aligned raw context preview:"]
    matched_terms = context_payload.get("matched_anchor_terms") or []
    if matched_terms:
        lines.append("matched_anchor_terms: {}".format(", ".join(str(term) for term in list(matched_terms)[:8])))
    if baseline_preview:
        lines.extend([
            "baseline_context (anchor line {}):".format(baseline_context.get("anchor_line") or "?"),
            baseline_preview,
        ])
    if target_preview:
        lines.extend([
            "target_context (anchor line {}):".format(target_context.get("anchor_line") or "?"),
            target_preview,
        ])
    return truncate_multiline_text(
        "\n".join(lines),
        max_lines=MAX_ALIGNED_CONTEXT_LINES,
        max_chars=MAX_ALIGNED_CONTEXT_CHARS,
    )



def _build_payload_from_path(
    analysis_root: pathlib.Path,
    normalized_path: str,
    details: str = "",
    inline_excerpt: str = "",
) -> Dict[str, object]:
    diff_excerpt, evidence_kind = _build_evidence_excerpt(analysis_root, normalized_path, details, inline_excerpt)

    paired_bytecode_path = ""
    if evidence_kind == "api_diff" and (
        _looks_like_shallow_api_hunk(normalized_path, diff_excerpt)
        or _should_force_paired_bytecode_context(normalized_path, diff_excerpt)
    ):
        paired_bytecode_path = _paired_bytecode_diff_path(normalized_path)
        paired_excerpt = _build_paired_bytecode_excerpt(analysis_root, normalized_path)
        if paired_excerpt:
            diff_excerpt = truncate_multiline_text(
                "\n\n".join(
                    part
                    for part in [
                        diff_excerpt,
                        "Related bytecode diff context (auto-expanded from {}):\n{}".format(
                            paired_bytecode_path,
                            paired_excerpt,
                        ),
                    ]
                    if part
                ),
                max_lines=MAX_DIRECT_DIFF_LINES,
                max_chars=MAX_DIRECT_DIFF_CHARS,
            )
            details = "\n".join(
                part
                for part in [
                    details,
                    "Auto-expanded with paired bytecode diff context from {}".format(paired_bytecode_path),
                ]
                if part
            )

    if _should_expand_with_raw_context(normalized_path, evidence_kind, diff_excerpt, paired_bytecode_path):
        raw_context_excerpt = _build_aligned_raw_context_excerpt(analysis_root, normalized_path, diff_excerpt)
        if raw_context_excerpt:
            diff_excerpt = truncate_multiline_text(
                "\n\n".join(part for part in [diff_excerpt, raw_context_excerpt] if part),
                max_lines=MAX_DIRECT_DIFF_LINES,
                max_chars=MAX_DIRECT_DIFF_CHARS,
            )
            details = "\n".join(
                part
                for part in [details, "Auto-expanded with aligned raw baseline/target context."]
                if part
            )

    return {
        "path": normalized_path,
        "details": details,
        "diff_excerpt": diff_excerpt,
        "paired_bytecode_path": paired_bytecode_path or None,
        "evidence_kind": evidence_kind,
    }



def _payload_has_supported_concrete_context(payload: Optional[Dict[str, object]]) -> bool:
    if not payload:
        return False
    normalized_path = normalize_diff_path(payload.get("path"))
    evidence_kind = classify_evidence_kind(normalized_path)
    if evidence_kind not in {"api_diff", "bytecode_diff"}:
        return False
    if _payload_signal_weight(payload) < 0.75:
        return False
    basename = pathlib.PurePosixPath(normalized_path).name.lower() if normalized_path else ""
    if WEAK_HUNK_BASENAME_PATTERN.search(basename):
        return False
    diff_excerpt = str(payload.get("diff_excerpt") or "")
    if "Aligned raw context preview:" in diff_excerpt:
        return True
    if evidence_kind == "api_diff" and payload.get("paired_bytecode_path"):
        return True
    if evidence_kind == "bytecode_diff" and ("invoke" in diff_excerpt or "Code:" in diff_excerpt):
        return True
    if FIX_KEYWORD_PATTERN.search(diff_excerpt):
        return True
    return not _looks_like_shallow_api_hunk(normalized_path, diff_excerpt)



def parse_selected_hunks(selected_hunks_text: str) -> List[Dict[str, str]]:
    hunks: List[Dict[str, str]] = []
    current: Optional[Dict[str, List[str]]] = None
    for raw_line in selected_hunks_text.splitlines():
        stripped = raw_line.strip()
        path_match = SELECTED_EVIDENCE_PATH_PATTERN.search(stripped)
        if path_match and (stripped.startswith("- ") or NUMBERED_ITEM_PATTERN.match(stripped)):
            if current is not None:
                details_text = "\n".join(current["details"]).strip()
                hunks.append(
                    {
                        "path": normalize_diff_path(current["path"]),
                        "details": details_text,
                        "inline_diff_excerpt": extract_inline_diff_excerpt(details_text),
                    }
                )
            current = {"path": path_match.group(1), "details": []}
            normalized = re.sub(r"^(?:-\s+|\d+[\.)]\s+)", "", stripped, count=1)
            tail = normalized.replace(path_match.group(1), "", 1).strip(" :-")
            if tail:
                current["details"].append(tail)
            continue
        if current is not None:
            current["details"].append(raw_line)
    if current is not None:
        details_text = "\n".join(current["details"]).strip()
        hunks.append(
            {
                "path": normalize_diff_path(current["path"]),
                "details": details_text,
                "inline_diff_excerpt": extract_inline_diff_excerpt(details_text),
            }
        )

    if hunks:
        return hunks

    fallback_paths: List[str] = []
    for match in SELECTED_EVIDENCE_PATH_PATTERN.finditer(selected_hunks_text):
        path = normalize_diff_path(match.group(1))
        if path and path not in fallback_paths:
            fallback_paths.append(path)
    return [{"path": path, "details": "", "inline_diff_excerpt": ""} for path in fallback_paths]



def _build_version_diff_summary_excerpt(analysis_root: pathlib.Path) -> str:
    summary_path = analysis_root / "version-diff" / "summary.json"
    if not summary_path.exists() or not summary_path.is_file():
        return ""
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except Exception:
        return truncate_multiline_text(_read_text_if_exists(summary_path), max_lines=24, max_chars=1600)
    if not isinstance(payload, dict):
        return ""
    lines = [
        "changed_class_count={}".format(payload.get("changed_class_count", "?")),
        "added_class_count={}".format(payload.get("added_class_count", "?")),
        "removed_class_count={}".format(payload.get("removed_class_count", "?")),
    ]
    changed_preview = payload.get("changed_classes_preview")
    if isinstance(changed_preview, list) and changed_preview:
        lines.append("changed_classes_preview={}".format(", ".join(str(item) for item in changed_preview[:5])))
    return "\n".join(lines)



def _build_evidence_excerpt(
    analysis_root: pathlib.Path,
    normalized_path: str,
    details: str,
    inline_excerpt: str,
) -> Tuple[str, str]:
    evidence_kind = classify_evidence_kind(normalized_path)
    excerpt = inline_excerpt
    if evidence_kind == "version_diff_summary":
        excerpt = _build_version_diff_summary_excerpt(analysis_root)
    if not excerpt:
        excerpt = truncate_multiline_text(_read_text_if_exists(analysis_root / normalized_path), max_lines=24, max_chars=1800)
    if not excerpt:
        excerpt = truncate_multiline_text(details, max_lines=24, max_chars=1600)
    return excerpt, evidence_kind



def build_hunk_payloads(analysis_root: pathlib.Path, selected_hunks: List[Dict[str, str]]) -> List[Dict[str, str]]:
    payloads: List[Dict[str, str]] = []
    for item in selected_hunks[:MAX_DIRECT_DIFF_HUNKS]:
        normalized_path = normalize_diff_path(item.get("path"))
        if not normalized_path:
            continue
        details = str(item.get("details") or "").strip()
        inline_excerpt = str(item.get("inline_diff_excerpt") or "").strip()
        payloads.append(_build_payload_from_path(analysis_root, normalized_path, details, inline_excerpt))
    return payloads



def build_judgment_payloads(
    analysis_root: pathlib.Path,
    case: dict,
    scenario: dict,
    selected_hunk_payloads: List[Dict[str, str]],
) -> List[Dict[str, str]]:
    trace_invalid_reasons = trace_invalid_reasons_from_case(case, scenario)
    payloads = [
        _annotate_payload_signal_metadata(dict(item), trace_invalid_reasons)
        for item in selected_hunk_payloads
    ]
    existing_paths = {normalize_diff_path(item.get("path")) for item in payloads if item.get("path")}

    for payload in list(payloads):
        normalized_path = normalize_diff_path(payload.get("path"))
        if classify_evidence_kind(normalized_path) not in {"api_diff", "bytecode_diff"}:
            continue
        for sibling_path in _top_level_sibling_diff_paths(normalized_path):
            if sibling_path in existing_paths:
                continue
            sibling_resolved = analysis_root / sibling_path
            if not sibling_resolved.exists() or not sibling_resolved.is_file():
                continue
            payloads.append(
                _annotate_payload_signal_metadata(
                    _build_payload_from_path(
                        analysis_root,
                        sibling_path,
                        details="Auto-added related top-level class diff for broader class-level context.",
                    ),
                    trace_invalid_reasons,
                )
            )
            existing_paths.add(sibling_path)
            if len(payloads) >= MAX_DIRECT_DIFF_HUNKS + MAX_SUPPLEMENTAL_JUDGMENT_ITEMS:
                return payloads

    concrete_payloads = [
        payload for payload in payloads if classify_evidence_kind(payload.get("path")) in {"api_diff", "bytecode_diff"}
    ]
    has_supported_concrete_payload = any(_payload_has_supported_concrete_context(payload) for payload in concrete_payloads)

    if concrete_payloads and has_supported_concrete_payload:
        return payloads

    candidate_paths: List[str] = []
    if has_effective_trace_difference(case, scenario):
        candidate = normalize_diff_path(scenario.get("trace_summary_file"))
        if candidate:
            candidate_paths.append(candidate)
    for key in ["failure_excerpt_file", "dependency_tree_diff"]:
        candidate = normalize_diff_path(scenario.get(key))
        if candidate:
            candidate_paths.append(candidate)
    candidate_paths.extend(SUPPLEMENTAL_JUDGMENT_PATHS)

    for candidate in unique_preserve_order(candidate_paths):
        normalized_path = normalize_diff_path(candidate)
        if not normalized_path or normalized_path in existing_paths:
            continue
        if normalized_path == "trace-diff-summary.txt" and trace_invalid_reasons:
            continue
        resolved = analysis_root / normalized_path
        if not resolved.exists() or not resolved.is_file():
            continue
        raw_text = _read_text_if_exists(resolved).strip()
        if not raw_text:
            continue
        if normalized_path == "dependency-tree.diff" and raw_text == "(no dependency tree diff)":
            continue
        payloads.append(
            _annotate_payload_signal_metadata(
                _build_payload_from_path(
                    analysis_root,
                    normalized_path,
                    details="Auto-added supplemental judgment evidence.",
                ),
                trace_invalid_reasons,
            )
        )
        existing_paths.add(normalized_path)
        if len(payloads) >= MAX_DIRECT_DIFF_HUNKS + MAX_SUPPLEMENTAL_JUDGMENT_ITEMS:
            break
    return payloads


def shorten_text(text: str, limit: int = 240) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    ordered = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def clamp_vulnerability_presence_score(value: object, default: int = 50) -> int:
    try:
        numeric = int(round(float(value)))
    except (TypeError, ValueError):
        numeric = default
    return max(MIN_VULNERABILITY_PRESENCE_SCORE, min(MAX_VULNERABILITY_PRESENCE_SCORE, numeric))


def _strength_points_for_fix(value: str) -> int:
    return {
        "none": 0,
        "weak": 8,
        "medium": 18,
        "strong": 30,
    }.get(str(value).strip().lower(), 0)



def _strength_points_for_exploit(value: str) -> int:
    return {
        "none": 0,
        "weak": 6,
        "medium": 14,
        "strong": 24,
    }.get(str(value).strip().lower(), 0)



def _confidence_points(value: str) -> int:
    return {
        "low": 0,
        "medium": 2,
        "high": 4,
    }.get(str(value).strip().lower(), 0)



def _fix_text_bonus(text: str) -> int:
    if not text:
        return 0
    bonus = 0
    patterns = [
        (26, r"\b(ispayloadvalid|_validatesubtype|subtypevalidator|validateqname|validatencname|validatename)\b"),
        (18, r"\b(payload[- ]validation|validation logic|validation routine|invalid payload|decodingexception|reject(?:ed|s|ing)?|block(?:ed|s|ing)?)\b"),
        (16, r"\b(add(?:ed|s|ing)?|introduc(?:ed|es|ing)?|gain(?:ed|s)?|new)\b.{0,80}\b(validat\w+|validator|guard|check|reject\w+|invalid)\b"),
    ]
    for points, pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL):
            bonus += points
    return bonus



def _exploit_text_bonus(text: str) -> int:
    if not text:
        return 0
    bonus = 0
    patterns = [
        (14, r"\b(missing symbol|cannot find symbol|nosuchmethod(?:error)?|nosuchfield(?:error)?|classnotfound(?:exception)?|noclassdeffound(?:error)?)\b"),
        (5, r"\b(binary incompat|compat replay|classpath|loader confusion|verifyerror|linkageerror|arrayindexoutofboundsexception)\b"),
        (3, r"\b(api reorganization|rename[ds]?|refactor(?:ed|ing)?)\b"),
    ]
    for points, pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL):
            bonus += points
    return bonus



def derive_llm_vulnerability_presence_score(
    final_failure_reason: str,
    vulnerability_presence_verdict: str,
    judgment_confidence: str,
    fix_evidence_strength: str,
    exploit_breakage_evidence_strength: str,
    evidence_text: str,
) -> int:
    base_score = {
        VULNERABILITY_STATUS_NO: 32,
        VULNERABILITY_STATUS_POSSIBLY_YES: 68,
        VULNERABILITY_STATUS_UNKNOWN: 50,
    }.get(vulnerability_presence_verdict, 50)
    reason_offset = {
        VERDICT_VULNERABILITY_NOT_PRESENT: -12,
        VERDICT_EXPLOIT_INVALID_DUE_TO_VERSION_CHANGE: 8,
        VERDICT_UNDETERMINED: 0,
    }.get(final_failure_reason, 0)
    score = base_score + reason_offset
    score += _strength_points_for_exploit(exploit_breakage_evidence_strength)
    score -= _strength_points_for_fix(fix_evidence_strength)
    score += _exploit_text_bonus(evidence_text)
    score -= _fix_text_bonus(evidence_text)

    confidence_offset = _confidence_points(judgment_confidence)
    if score > 50:
        score += confidence_offset
    elif score < 50:
        score -= confidence_offset

    return clamp_vulnerability_presence_score(score)



def derive_rule_vulnerability_presence_score(
    vulnerability_not_present_score: int,
    exploit_invalid_score: int,
    uncertainty_count: int,
) -> int:
    raw_score = 50 + 5 * (exploit_invalid_score - vulnerability_not_present_score)
    if uncertainty_count > 0:
        pull_factor = max(0.35, 1.0 - 0.25 * uncertainty_count)
        raw_score = 50 + (raw_score - 50) * pull_factor
    return clamp_vulnerability_presence_score(raw_score)


def match_signal_patterns(text: str, patterns: Sequence[Tuple[str, str]]) -> List[str]:
    matched: List[str] = []
    for signal_name, pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL):
            matched.append(signal_name)
    return matched


def _has_direct_fix_path_signal(text: str) -> bool:
    if not text:
        return False
    plain_language = re.search(
        r"\b(removed recursive|recursive (?:construction|conversion|wrapp\w+) removed|removed collection conversion|removed map conversion|removed iteration and conversion code|constructor returns immediately|removed collection conversion logic in constructor|target trace enters once and exits|reproduction changes from failure to success|self-referential collections? no longer recurse)\b",
        text,
        flags=re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    raw_diff_shape = bool(
        re.search(r"^\+\s+\d+:\s+return\b", text, flags=re.MULTILINE)
        and re.search(
            r"-.*(?:java/util/Collection|java/util/Map|org/codehaus/jettison/json/JSONArray|org/codehaus/jettison/json/JSONObject)",
            text,
            flags=re.IGNORECASE | re.MULTILINE | re.DOTALL,
        )
    )
    return bool(plain_language or raw_diff_shape)


def build_verdict_text(
    case: dict,
    scenario: dict,
    sections: Dict[str, str],
    selected_hunks: List[Dict[str, str]],
    hunk_payloads: Optional[List[Dict[str, str]]] = None,
    hunk_judgments: Optional[List[Dict[str, Any]]] = None,
) -> str:
    text_parts = [
        case.get("status") or "",
        case.get("failure_kind") or "",
        case.get("failure_subtype") or "",
        case.get("baseline_execution_observation") or "",
        case.get("target_execution_observation") or "",
        str(case.get("trace_has_difference") or ""),
        json.dumps(case.get("first_divergence") or {}, ensure_ascii=False),
        str(case.get("baseline_enter_count") or ""),
        str(case.get("target_enter_count") or ""),
        scenario.get("scenario_type") or "",
        sections.get("Diagnosis", ""),
        sections.get("Selected Hunks", ""),
        sections.get("Supporting Evidence", ""),
        sections.get("Open Questions", ""),
        "\n".join(item.get("path", "") for item in selected_hunks),
        "\n".join(item.get("details", "") for item in selected_hunks),
        "\n".join(item.get("diff_excerpt", "") for item in (hunk_payloads or [])),
        "\n".join(item.get("judgment", "") for item in (hunk_judgments or [])),
        "\n".join("\n".join(item.get("key_evidence", [])) for item in (hunk_judgments or [])),
        "\n".join(item.get("reasoning", "") for item in (hunk_judgments or [])),
    ]
    return "\n".join(part for part in text_parts if part).strip()


def infer_final_judgment(
    case: dict,
    scenario: dict,
    sections: Dict[str, str],
    selected_hunks: List[Dict[str, str]],
    hunk_payloads: Optional[List[Dict[str, str]]] = None,
    hunk_judgments: Optional[List[Dict[str, Any]]] = None,
) -> dict:
    verdict_text = build_verdict_text(case, scenario, sections, selected_hunks, hunk_payloads, hunk_judgments)

    vulnerability_signals: List[str] = []
    exploit_change_signals: List[str] = []
    uncertainty_signals: List[str] = []
    vulnerability_score = 0.0
    exploit_change_score = 0.0

    strong_vulnerability_matches = match_signal_patterns(verdict_text, STRONG_VULNERABILITY_ABSENT_SIGNALS)
    weak_vulnerability_matches = match_signal_patterns(verdict_text, WEAK_VULNERABILITY_ABSENT_SIGNALS)
    strong_exploit_matches = match_signal_patterns(verdict_text, STRONG_EXPLOIT_CHANGE_SIGNALS)
    weak_exploit_matches = match_signal_patterns(verdict_text, WEAK_EXPLOIT_CHANGE_SIGNALS)
    uncertainty_matches = match_signal_patterns(verdict_text, UNCERTAINTY_SIGNALS)

    vulnerability_signals.extend(strong_vulnerability_matches)
    vulnerability_signals.extend(weak_vulnerability_matches)
    uncertainty_signals.extend(uncertainty_matches)

    vulnerability_score += 3 * len(strong_vulnerability_matches)
    vulnerability_score += 1 * len(weak_vulnerability_matches)

    compatibility_like_matches = [
        match
        for match in strong_exploit_matches
        if match in {"compatibility_breakage", "symbol_resolution_breakage", "api_shape_change", "refactor_or_rework"}
    ]
    non_compat_exploit_matches = [match for match in strong_exploit_matches if match not in compatibility_like_matches]
    weak_compatibility_matches = [
        match for match in weak_exploit_matches if match in {"behavior_change", "runtime_or_factory_breakage"}
    ]
    weak_non_compat_matches = [match for match in weak_exploit_matches if match not in weak_compatibility_matches]

    exploit_change_signals.extend(non_compat_exploit_matches)
    exploit_change_signals.extend(weak_non_compat_matches)
    uncertainty_signals.extend(f"text_{match}" for match in compatibility_like_matches)
    uncertainty_signals.extend(f"text_{match}" for match in weak_compatibility_matches)

    exploit_change_score += 3 * len(non_compat_exploit_matches)
    exploit_change_score += 0.75 * len(weak_non_compat_matches)
    exploit_change_score += 1.25 * len(compatibility_like_matches)
    exploit_change_score += 0.35 * len(weak_compatibility_matches)

    baseline_observation = case.get("baseline_execution_observation")
    target_observation = case.get("target_execution_observation")
    target_success = target_observation == "success"
    baseline_failed = baseline_observation not in (None, "", "success")
    raw_trace_has_difference = bool(case.get("trace_has_difference"))
    effective_trace_difference = has_effective_trace_difference(case, scenario)
    trace_invalid_reasons = trace_invalid_reasons_from_case(case, scenario)

    if trace_invalid_reasons:
        uncertainty_signals.extend(f"invalid_trace_{reason}" for reason in trace_invalid_reasons)

    payload_by_path: Dict[str, Dict[str, object]] = {}
    for payload in hunk_payloads or []:
        normalized_path = normalize_diff_path(payload.get("path"))
        if normalized_path and normalized_path not in payload_by_path:
            payload_by_path[normalized_path] = payload

    strong_fix_evidence_present = False
    weighted_fix_hunk_points = 0.0

    for payload in hunk_payloads or []:
        signal_weight = _payload_signal_weight(payload)
        for reason in payload.get("weak_signal_reasons") or []:
            uncertainty_signals.append(f"weak_hunk_{reason}")
        diff_excerpt = str(payload.get("diff_excerpt") or "")
        if signal_weight >= 0.75 and _has_direct_fix_path_signal(diff_excerpt):
            vulnerability_score += 4
            vulnerability_signals.append("direct_vulnerable_path_removed")
            strong_fix_evidence_present = True

    for item in hunk_judgments or []:
        judgment = str(item.get("judgment") or "").strip().lower()
        confidence_points = _confidence_points(item.get("confidence"))
        payload = payload_by_path.get(normalize_diff_path(item.get("hunk_path")))
        signal_weight = _payload_signal_weight(payload)
        scaled_points = (confidence_points + 1) * signal_weight
        if judgment == "fix_evidence":
            vulnerability_score += scaled_points
            vulnerability_signals.append(f"hunk_fix_evidence_{item.get('confidence')}")
            weighted_fix_hunk_points += scaled_points
            if signal_weight >= 0.75 and confidence_points >= 2:
                strong_fix_evidence_present = True
        elif judgment == "exploit_breakage_evidence":
            exploit_change_score += scaled_points
            exploit_change_signals.append(f"hunk_exploit_breakage_{item.get('confidence')}")

    if weighted_fix_hunk_points >= 2.5:
        strong_fix_evidence_present = True

    compatibility_breakage_present = False
    if case.get("status") == "execution_failure" and not target_success:
        compatibility_breakage_present = True
        uncertainty_signals.append("status_execution_failure")
        if not strong_fix_evidence_present:
            exploit_change_score += 1.0
            exploit_change_signals.append("status_execution_failure")

    failure_subtype = case.get("failure_subtype")
    if failure_subtype in COMPATIBILITY_ONLY_FAILURE_SUBTYPES and not target_success:
        compatibility_breakage_present = True
        uncertainty_signals.append(f"compatibility_failure_subtype_{failure_subtype}")
        if not strong_fix_evidence_present:
            exploit_change_score += 1.5
            exploit_change_signals.append(f"failure_subtype_{failure_subtype}")

    scenario_type = scenario.get("scenario_type")
    if scenario_type in STRUCTURAL_FAILURE_SCENARIOS and not target_success:
        compatibility_breakage_present = True
        uncertainty_signals.append(f"compatibility_scenario_{scenario_type}")
        if not strong_fix_evidence_present:
            exploit_change_score += 0.5
            exploit_change_signals.append(f"scenario_type_{scenario_type}")

    if target_success and baseline_failed:
        vulnerability_score += 2
        vulnerability_signals.append("target_success_baseline_not_success")

    if effective_trace_difference and target_success and baseline_failed:
        vulnerability_score += 2
        vulnerability_signals.append("trace_diff_with_target_success")

    first_divergence = case.get("first_divergence") or {}
    if effective_trace_difference and isinstance(first_divergence, dict) and str(first_divergence.get("target") or "") == "<trace ended>":
        vulnerability_score += 2
        vulnerability_signals.append("target_trace_ended_at_first_divergence")

    baseline_enter_count = case.get("baseline_enter_count")
    target_enter_count = case.get("target_enter_count")
    try:
        baseline_enter_value = int(baseline_enter_count)
        target_enter_value = int(target_enter_count)
    except (TypeError, ValueError):
        baseline_enter_value = None
        target_enter_value = None
    if (
        effective_trace_difference
        and baseline_enter_value is not None
        and target_enter_value is not None
        and baseline_enter_value > max(4, target_enter_value * 4)
        and target_enter_value <= 1
    ):
        vulnerability_score += 2
        vulnerability_signals.append("baseline_recurses_target_exits")

    if raw_trace_has_difference and not effective_trace_difference:
        uncertainty_signals.append("raw_trace_difference_filtered")

    if sections.get("Open Questions"):
        uncertainty_signals.append("open_questions_present")

    vulnerability_signals = unique_preserve_order(vulnerability_signals)
    exploit_change_signals = unique_preserve_order(exploit_change_signals)
    uncertainty_signals = unique_preserve_order(uncertainty_signals)

    vulnerability_presence_score = derive_rule_vulnerability_presence_score(
        vulnerability_not_present_score=vulnerability_score,
        exploit_invalid_score=exploit_change_score,
        uncertainty_count=len(uncertainty_signals),
    )

    if vulnerability_presence_score <= VULNERABILITY_PRESENCE_SCORE_NO_THRESHOLD:
        final_failure_reason = VERDICT_VULNERABILITY_NOT_PRESENT
        vulnerability_status = VULNERABILITY_STATUS_NO
    elif vulnerability_presence_score >= VULNERABILITY_PRESENCE_SCORE_YES_THRESHOLD:
        final_failure_reason = VERDICT_EXPLOIT_INVALID_DUE_TO_VERSION_CHANGE
        vulnerability_status = VULNERABILITY_STATUS_POSSIBLY_YES
    else:
        final_failure_reason = VERDICT_UNDETERMINED
        vulnerability_status = VULNERABILITY_STATUS_UNKNOWN

    if final_failure_reason == VERDICT_UNDETERMINED:
        judgment_confidence = "low"
    else:
        primary_signals = (
            vulnerability_signals
            if final_failure_reason == VERDICT_VULNERABILITY_NOT_PRESENT
            else exploit_change_signals
        )
        confidence_points = abs(vulnerability_presence_score - 50) // 10
        if len(primary_signals) >= 2:
            confidence_points += 1
        confidence_points -= min(2, len(uncertainty_signals))
        if confidence_points >= 4:
            judgment_confidence = "high"
        elif confidence_points >= 2:
            judgment_confidence = "medium"
        else:
            judgment_confidence = "low"

    if final_failure_reason == VERDICT_VULNERABILITY_NOT_PRESENT:
        judgment_rationale = (
            "The strongest signals point to target-side blocking or hardening logic "
            f"({', '.join(vulnerability_signals[:4]) or 'no explicit signal'}), so the PoC failure is "
            "more consistent with the vulnerability no longer being reachable/present than with a pure "
            "compatibility break."
        )
    elif final_failure_reason == VERDICT_EXPLOIT_INVALID_DUE_TO_VERSION_CHANGE:
        judgment_rationale = (
            "The strongest signals point to dependency/API/runtime incompatibilities "
            f"({', '.join(exploit_change_signals[:4]) or 'no explicit signal'}), so the PoC failure is "
            "more consistent with the exploit or replay path breaking after version changes; the underlying "
            "vulnerability cannot be ruled out from this evidence alone."
        )
    elif compatibility_breakage_present or trace_invalid_reasons:
        judgment_rationale = (
            "The available evidence is dominated by compatibility/runtime noise or filtered trace divergence "
            f"({', '.join((trace_invalid_reasons or [])[:3]) or 'no effective trace signal'}), so this case is "
            "better treated as undetermined than as direct evidence of vulnerability persistence."
        )
    else:
        judgment_rationale = (
            "The current evidence mixes compatibility-change and behavior-change signals or leaves too many "
            "open questions, so vulnerability existence cannot be determined confidently from the available "
            "LLM diagnosis and diff evidence."
        )

    return {
        "vulnerability_presence_score": vulnerability_presence_score,
        "final_failure_reason": final_failure_reason,
        "vulnerability_presence_verdict": vulnerability_status,
        "judgment_confidence": judgment_confidence,
        "judgment_scores": {
            "vulnerability_not_present": round(vulnerability_score, 2),
            "exploit_invalid_due_to_version_change": round(exploit_change_score, 2),
        },
        "judgment_signals": {
            "vulnerability_not_present": vulnerability_signals,
            "exploit_invalid_due_to_version_change": exploit_change_signals,
            "uncertainty": uncertainty_signals,
        },
        "strong_fix_evidence_present": strong_fix_evidence_present,
        "compatibility_breakage_present": compatibility_breakage_present,
        "trace_evidence_effective": effective_trace_difference,
        "judgment_rationale": judgment_rationale,
        "judgment_rationale_short": shorten_text(judgment_rationale),
    }


def resolve_llm_api_key(args: argparse.Namespace) -> Optional[str]:
    return args.llm_api_key or os.environ.get("CHATANYWHERE_API_KEY") or os.environ.get("OPENAI_API_KEY")


def normalize_llm_judgment(payload: Dict[str, Any]) -> Dict[str, Any]:
    final_failure_reason = str(payload.get("final_failure_reason", VERDICT_UNDETERMINED)).strip().lower()
    if final_failure_reason not in {
        VERDICT_VULNERABILITY_NOT_PRESENT,
        VERDICT_EXPLOIT_INVALID_DUE_TO_VERSION_CHANGE,
        VERDICT_UNDETERMINED,
    }:
        final_failure_reason = VERDICT_UNDETERMINED

    vulnerability_presence_verdict = str(
        payload.get("vulnerability_presence_verdict", VULNERABILITY_STATUS_UNKNOWN)
    ).strip().lower()
    if vulnerability_presence_verdict not in {
        VULNERABILITY_STATUS_NO,
        VULNERABILITY_STATUS_POSSIBLY_YES,
        VULNERABILITY_STATUS_UNKNOWN,
    }:
        vulnerability_presence_verdict = VULNERABILITY_STATUS_UNKNOWN

    judgment_confidence = str(payload.get("judgment_confidence", "low")).strip().lower()
    if judgment_confidence not in {"high", "medium", "low"}:
        judgment_confidence = "low"

    fix_evidence_strength = str(payload.get("fix_evidence_strength", "none")).strip().lower()
    if fix_evidence_strength not in {"strong", "medium", "weak", "none"}:
        fix_evidence_strength = "none"

    exploit_breakage_evidence_strength = str(
        payload.get("exploit_breakage_evidence_strength", "none")
    ).strip().lower()
    if exploit_breakage_evidence_strength not in {"strong", "medium", "weak", "none"}:
        exploit_breakage_evidence_strength = "none"

    key_evidence = payload.get("key_evidence")
    if not isinstance(key_evidence, list):
        key_evidence = []
    key_evidence = [str(item).strip() for item in key_evidence if str(item).strip()][:8]

    judgment_rationale = str(payload.get("judgment_rationale", "")).strip()
    if not judgment_rationale:
        judgment_rationale = (
            "The final LLM judgment did not provide a usable rationale, so the result should be treated as low confidence."
        )

    raw_score = payload.get("vulnerability_presence_score")
    evidence_text = "\n".join(key_evidence + [judgment_rationale])
    vulnerability_presence_score = clamp_vulnerability_presence_score(
        raw_score,
        default=derive_llm_vulnerability_presence_score(
            final_failure_reason=final_failure_reason,
            vulnerability_presence_verdict=vulnerability_presence_verdict,
            judgment_confidence=judgment_confidence,
            fix_evidence_strength=fix_evidence_strength,
            exploit_breakage_evidence_strength=exploit_breakage_evidence_strength,
            evidence_text=evidence_text,
        ),
    )
    if raw_score in (None, ""):
        if vulnerability_presence_score <= VULNERABILITY_PRESENCE_SCORE_NO_THRESHOLD:
            final_failure_reason = VERDICT_VULNERABILITY_NOT_PRESENT
            vulnerability_presence_verdict = VULNERABILITY_STATUS_NO
        elif vulnerability_presence_score >= VULNERABILITY_PRESENCE_SCORE_YES_THRESHOLD:
            final_failure_reason = VERDICT_EXPLOIT_INVALID_DUE_TO_VERSION_CHANGE
            vulnerability_presence_verdict = VULNERABILITY_STATUS_POSSIBLY_YES
        else:
            final_failure_reason = VERDICT_UNDETERMINED
            vulnerability_presence_verdict = VULNERABILITY_STATUS_UNKNOWN

    return {
        "prompt_version": str(payload.get("prompt_version") or ""),
        "vulnerability_presence_score": vulnerability_presence_score,
        "final_failure_reason": final_failure_reason,
        "vulnerability_presence_verdict": vulnerability_presence_verdict,
        "judgment_confidence": judgment_confidence,
        "judgment_rationale": judgment_rationale,
        "judgment_rationale_short": shorten_text(judgment_rationale),
        "fix_evidence_strength": fix_evidence_strength,
        "exploit_breakage_evidence_strength": exploit_breakage_evidence_strength,
        "llm_key_evidence": key_evidence,
        "judged_hunk_count": payload.get("judged_hunk_count"),
        "judged_hunk_paths": payload.get("judged_hunk_paths") if isinstance(payload.get("judged_hunk_paths"), list) else [],
    }


def normalize_hunk_judgment(payload: Dict[str, Any]) -> Dict[str, Any]:
    judgment = str(payload.get("judgment", "neutral")).strip().lower()
    if judgment not in {"fix_evidence", "exploit_breakage_evidence", "neutral"}:
        judgment = "neutral"

    confidence = str(payload.get("confidence", "low")).strip().lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"

    key_evidence = payload.get("key_evidence")
    if not isinstance(key_evidence, list):
        key_evidence = []
    normalized_evidence = [str(item).strip() for item in key_evidence if str(item).strip()][:8]

    reasoning = str(payload.get("reasoning", "")).strip()
    if not reasoning:
        reasoning = "The per-hunk LLM judgment did not provide a usable rationale."

    return {
        "prompt_version": str(payload.get("prompt_version") or ""),
        "hunk_path": normalize_diff_path(payload.get("hunk_path")),
        "judgment": judgment,
        "confidence": confidence,
        "key_evidence": normalized_evidence,
        "reasoning": reasoning,
        "reasoning_short": shorten_text(reasoning),
    }



def load_cached_hunk_judgments(judgment_path: pathlib.Path) -> Optional[List[Dict[str, Any]]]:
    if not judgment_path.exists() or not judgment_path.is_file():
        return None
    try:
        payload = json.loads(judgment_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if str(payload.get("prompt_version") or "") != HUNK_JUDGMENT_PROMPT_VERSION:
        return None
    judgments = payload.get("judgments")
    if not isinstance(judgments, list):
        return None
    normalized = []
    for item in judgments:
        if not isinstance(item, dict):
            continue
        normalized.append(normalize_hunk_judgment(item))
    return normalized or None



def load_cached_llm_judgment(judgment_path: pathlib.Path) -> Optional[Dict[str, Any]]:
    if not judgment_path.exists() or not judgment_path.is_file():
        return None
    try:
        payload = json.loads(judgment_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return normalize_llm_judgment(payload)


def build_case_payload(case: dict) -> Dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "cve_id": case.get("cve_id"),
        "artifact": case.get("artifact"),
        "baseline_version": case.get("baseline_version"),
        "target_version": case.get("target_version"),
        "status": case.get("status"),
        "failure_kind": case.get("failure_kind"),
        "failure_subtype": case.get("failure_subtype"),
        "baseline_execution_observation": case.get("baseline_execution_observation"),
        "target_execution_observation": case.get("target_execution_observation"),
        "compare_url": case.get("compare_url"),
        "description": case.get("description"),
        "analysis_dir": case.get("analysis_dir"),
        "trace_has_difference": case.get("trace_has_difference"),
        "trace_has_effective_difference": case.get("trace_has_effective_difference"),
        "trace_evidence_valid": case.get("trace_evidence_valid"),
        "trace_invalid_reasons": case.get("trace_invalid_reasons"),
        "first_divergence_is_noise": case.get("first_divergence_is_noise"),
        "first_divergence": case.get("first_divergence"),
        "baseline_enter_count": case.get("baseline_enter_count"),
        "target_enter_count": case.get("target_enter_count"),
    }



def maybe_load_or_generate_hunk_judgments(
    case: dict,
    scenario: dict,
    hunk_payloads: List[Dict[str, str]],
    analysis_root: pathlib.Path,
    args: argparse.Namespace,
    llm_api_key: Optional[str],
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[pathlib.Path], Optional[pathlib.Path]]:
    if args.judgment_mode == "rule" or not hunk_payloads:
        return (None, None, None)

    judgment_path = analysis_root / "llm-hunk-judgments.json"
    error_path = analysis_root / "llm-hunk-judgments.error.txt"

    if judgment_path.exists() and not args.refresh_llm_judgment:
        cached = load_cached_hunk_judgments(judgment_path)
        if cached is not None:
            return (cached, judgment_path, error_path if error_path.exists() else None)

    if not llm_api_key:
        if args.judgment_mode == "llm":
            raise SystemExit(
                "LLM judgment requested but neither CHATANYWHERE_API_KEY nor OPENAI_API_KEY is set, "
                "and --llm-api-key was not provided."
            )
        return (None, judgment_path if judgment_path.exists() else None, error_path if error_path.exists() else None)

    case_payload = build_case_payload(case)
    try:
        judgments = []
        for hunk_payload in hunk_payloads:
            judgment = run_llm_hunk_judgment_sync(
                case_payload=case_payload,
                scenario=scenario,
                hunk_payload=hunk_payload,
                config=LLMAnalysisConfig(
                    model=args.llm_model,
                    base_url=args.llm_base_url,
                    api_key=llm_api_key,
                    max_rounds=1,
                ),
            )
            judgment["diff_excerpt"] = hunk_payload.get("diff_excerpt", "")
            judgments.append(normalize_hunk_judgment(judgment))

        judgment_payload = {
            "prompt_version": HUNK_JUDGMENT_PROMPT_VERSION,
            "judgments": judgments,
        }
        judgment_path.write_text(json.dumps(judgment_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if error_path.exists():
            error_path.unlink()
        return (judgments, judgment_path, None)
    except Exception as error:
        error_path.write_text(
            "LLM per-hunk judgment failed.\n{}: {}\n".format(type(error).__name__, error),
            encoding="utf-8",
        )
        if args.judgment_mode == "llm":
            raise
        return (None, judgment_path if judgment_path.exists() else None, error_path)



def maybe_load_or_generate_llm_judgment(
    case: dict,
    scenario: dict,
    hunk_payloads: List[Dict[str, str]],
    analysis_root: pathlib.Path,
    args: argparse.Namespace,
    llm_api_key: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[pathlib.Path], Optional[pathlib.Path]]:
    if args.judgment_mode == "rule":
        return (None, None, None)

    judgment_path = analysis_root / "llm-vulnerability-judgment.json"
    error_path = analysis_root / "llm-vulnerability-judgment.error.txt"

    if judgment_path.exists() and not args.refresh_llm_judgment:
        cached = load_cached_llm_judgment(judgment_path)
        if cached is not None:
            return (cached, judgment_path, error_path if error_path.exists() else None)

    if not llm_api_key:
        if args.judgment_mode == "llm":
            raise SystemExit(
                "LLM judgment requested but neither CHATANYWHERE_API_KEY nor OPENAI_API_KEY is set, "
                "and --llm-api-key was not provided."
            )
        return (None, judgment_path if judgment_path.exists() else None, error_path if error_path.exists() else None)

    case_payload = build_case_payload(case)
    try:
        judgment = run_llm_vulnerability_judgment_sync(
            case_payload=case_payload,
            scenario=scenario,
            hunk_payloads=hunk_payloads,
            output_path=judgment_path,
            config=LLMAnalysisConfig(
                model=args.llm_model,
                base_url=args.llm_base_url,
                api_key=llm_api_key,
                max_rounds=1,
            ),
        )
        normalized = normalize_llm_judgment(judgment)
        judgment_path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if error_path.exists():
            error_path.unlink()
        return (normalized, judgment_path, None)
    except Exception as error:
        error_path.write_text(
            "LLM vulnerability judgment failed.\n{}: {}\n".format(type(error).__name__, error),
            encoding="utf-8",
        )
        if args.judgment_mode == "llm":
            raise
        return (None, judgment_path if judgment_path.exists() else None, error_path)


def _llm_strong_verdict_lacks_support(
    llm_judgment: Optional[Dict[str, Any]],
    rule_judgment: Dict[str, Any],
    judgment_payloads: Optional[List[Dict[str, object]]],
) -> bool:
    if not llm_judgment:
        return False
    llm_verdict = str(llm_judgment.get("vulnerability_presence_verdict") or "").strip().lower()
    llm_confidence = str(llm_judgment.get("judgment_confidence") or "low").strip().lower()
    if llm_verdict not in {VULNERABILITY_STATUS_NO, VULNERABILITY_STATUS_POSSIBLY_YES}:
        return False
    if llm_confidence == "high":
        return False

    supported_concrete_count = sum(
        1 for payload in (judgment_payloads or []) if _payload_has_supported_concrete_context(payload)
    )
    if supported_concrete_count > 0:
        return False

    if llm_verdict == VULNERABILITY_STATUS_NO:
        return not bool(rule_judgment.get("strong_fix_evidence_present"))

    return (
        not rule_judgment.get("trace_evidence_effective")
        or rule_judgment.get("compatibility_breakage_present")
        or rule_judgment.get("final_failure_reason") == VERDICT_UNDETERMINED
    )



def choose_primary_judgment(
    rule_judgment: Dict[str, Any],
    llm_judgment: Optional[Dict[str, Any]],
    judgment_mode: str,
    hunk_judgments: Optional[List[Dict[str, Any]]] = None,
    judgment_payloads: Optional[List[Dict[str, object]]] = None,
) -> Tuple[Dict[str, Any], str]:
    if judgment_mode == "rule":
        primary = dict(rule_judgment)
        primary.setdefault("fix_evidence_strength", "")
        primary.setdefault("exploit_breakage_evidence_strength", "")
        primary.setdefault("llm_key_evidence", [])
        return (primary, "rule")

    if llm_judgment is None:
        if judgment_mode == "llm":
            raise RuntimeError("LLM judgment mode requested but no final LLM judgment was available")
        primary = dict(rule_judgment)
        primary.setdefault("fix_evidence_strength", "")
        primary.setdefault("exploit_breakage_evidence_strength", "")
        primary.setdefault("llm_key_evidence", [])
        return (primary, "hybrid_fallback_rule")

    fix_hunk_points = sum(
        _confidence_points(item.get("confidence"))
        for item in (hunk_judgments or [])
        if str(item.get("judgment") or "").strip().lower() == "fix_evidence"
    )
    strong_fix_present = bool(rule_judgment.get("strong_fix_evidence_present")) or fix_hunk_points >= 2
    llm_final_reason = llm_judgment.get("final_failure_reason")

    if _llm_strong_verdict_lacks_support(llm_judgment, rule_judgment, judgment_payloads):
        primary = dict(rule_judgment)
        primary.setdefault("fix_evidence_strength", llm_judgment.get("fix_evidence_strength", ""))
        primary.setdefault(
            "exploit_breakage_evidence_strength", llm_judgment.get("exploit_breakage_evidence_strength", "")
        )
        primary.setdefault("llm_key_evidence", llm_judgment.get("llm_key_evidence", []))
        return (primary, "hybrid_override_rule_unsupported_llm")

    if (
        rule_judgment.get("final_failure_reason") == VERDICT_VULNERABILITY_NOT_PRESENT
        and rule_judgment.get("judgment_confidence") in {"high", "medium"}
        and llm_final_reason == VERDICT_EXPLOIT_INVALID_DUE_TO_VERSION_CHANGE
        and strong_fix_present
    ):
        primary = dict(rule_judgment)
        primary.setdefault("fix_evidence_strength", "strong")
        primary.setdefault("exploit_breakage_evidence_strength", "")
        primary.setdefault("llm_key_evidence", [])
        return (primary, "hybrid_override_rule_fix")

    if (
        rule_judgment.get("final_failure_reason") == VERDICT_UNDETERMINED
        and llm_final_reason == VERDICT_EXPLOIT_INVALID_DUE_TO_VERSION_CHANGE
        and rule_judgment.get("compatibility_breakage_present")
        and not rule_judgment.get("trace_evidence_effective")
        and not strong_fix_present
    ):
        primary = dict(rule_judgment)
        primary.setdefault("fix_evidence_strength", llm_judgment.get("fix_evidence_strength", ""))
        primary.setdefault(
            "exploit_breakage_evidence_strength", llm_judgment.get("exploit_breakage_evidence_strength", "")
        )
        primary.setdefault("llm_key_evidence", llm_judgment.get("llm_key_evidence", []))
        return (primary, "hybrid_override_rule_unknown")

    primary = dict(rule_judgment)
    primary.update(llm_judgment)
    return (primary, "llm")


def build_entry(
    case: dict,
    scenario: dict,
    analysis_root: pathlib.Path,
    markdown_text: str,
    args: argparse.Namespace,
    llm_api_key: Optional[str],
) -> Optional[dict]:
    final_response = extract_final_response(markdown_text)
    sections = parse_sections(final_response) if final_response else {name: "" for name in SECTION_NAMES}
    selected_hunks = parse_selected_hunks(sections.get("Selected Hunks", ""))
    selected_hunk_payloads = build_hunk_payloads(analysis_root, selected_hunks)
    judgment_payloads = build_judgment_payloads(analysis_root, case, scenario, selected_hunk_payloads)
    hunk_judgments, hunk_judgment_path, hunk_judgment_error_path = maybe_load_or_generate_hunk_judgments(
        case=case,
        scenario=scenario,
        hunk_payloads=judgment_payloads,
        analysis_root=analysis_root,
        args=args,
        llm_api_key=llm_api_key,
    )
    rule_judgment = infer_final_judgment(case, scenario, sections, selected_hunks, judgment_payloads, hunk_judgments)
    llm_judgment, llm_judgment_path, llm_judgment_error_path = maybe_load_or_generate_llm_judgment(
        case=case,
        scenario=scenario,
        hunk_payloads=judgment_payloads,
        analysis_root=analysis_root,
        args=args,
        llm_api_key=llm_api_key,
    )
    primary_judgment, judgment_source = choose_primary_judgment(
        rule_judgment=rule_judgment,
        llm_judgment=llm_judgment,
        judgment_mode=args.judgment_mode,
        hunk_judgments=hunk_judgments,
        judgment_payloads=judgment_payloads,
    )

    return {
        "case_id": case.get("case_id"),
        "cve_id": case.get("cve_id"),
        "pair_index": case.get("pair_index"),
        "artifact": case.get("artifact"),
        "description": case.get("description") or scenario.get("description"),
        "baseline_version": case.get("baseline_version"),
        "target_version": case.get("target_version"),
        "status": case.get("status"),
        "failure_kind": case.get("failure_kind"),
        "failure_subtype": case.get("failure_subtype"),
        "baseline_execution_observation": case.get("baseline_execution_observation"),
        "target_execution_observation": case.get("target_execution_observation"),
        "compare_url": case.get("compare_url"),
        "analysis_dir": str(analysis_root),
        "llm_output_path": str(analysis_root / "llm-hunk-analysis.md"),
        "llm_hunk_judgment_path": str(hunk_judgment_path) if hunk_judgment_path else None,
        "llm_hunk_judgment_error_path": str(hunk_judgment_error_path) if hunk_judgment_error_path else None,
        "llm_judgment_path": str(llm_judgment_path) if llm_judgment_path else None,
        "llm_judgment_error_path": str(llm_judgment_error_path) if llm_judgment_error_path else None,
        "scenario_type": scenario.get("scenario_type"),
        "trace_keywords": scenario.get("trace_keywords"),
        "trace_has_difference": case.get("trace_has_difference"),
        "trace_has_effective_difference": case.get("trace_has_effective_difference"),
        "trace_evidence_valid": case.get("trace_evidence_valid"),
        "trace_invalid_reasons": case.get("trace_invalid_reasons"),
        "failure_excerpt_keywords": scenario.get("failure_excerpt_keywords"),
        "baseline_command": scenario.get("baseline_command"),
        "target_command": scenario.get("target_command"),
        "has_final_response": final_response is not None,
        "diagnosis": sections.get("Diagnosis", ""),
        "diagnosis_short": shorten_text(sections.get("Diagnosis", "")),
        "selected_hunks_text": sections.get("Selected Hunks", ""),
        "selected_hunk_count": len(selected_hunks),
        "selected_hunk_paths": [item["path"] for item in selected_hunks],
        "selected_hunks": selected_hunks,
        "selected_hunk_payloads": selected_hunk_payloads,
        "judgment_payload_count": len(judgment_payloads),
        "judgment_payloads": judgment_payloads,
        "hunk_judgment_count": len(hunk_judgments or []),
        "hunk_judgments": hunk_judgments,
        "supporting_evidence": sections.get("Supporting Evidence", ""),
        "open_questions": sections.get("Open Questions", ""),
        "final_response_markdown": final_response,
        "judgment_source": judgment_source,
        "rule_judgment": rule_judgment,
        "llm_judgment": llm_judgment,
        **primary_judgment,
    }


def build_invalid_trace_entry(
    case: dict,
    scenario: dict,
    analysis_root: pathlib.Path,
) -> dict:
    """在 seek_patch=false 且 invalid_trace_difference 的场景下，
    构造一个不依赖 LLM 输出的保守条目，直接视为漏洞仍然存在（affected）。
    """

    description = case.get("description") or scenario.get("description")
    trace_invalid_reasons = case.get("trace_invalid_reasons")

    rationale = (
        "Trace 被标记为 invalid_trace_difference，且 seek_patch=false；"
        "在这种设置下低版本不可能刻意修复该 CVE，因此即便 trace 无效，也保守认为漏洞仍然存在。"
    )

    return {
        "case_id": case.get("case_id"),
        "cve_id": case.get("cve_id"),
        "pair_index": case.get("pair_index"),
        "artifact": case.get("artifact"),
        "description": description,
        "baseline_version": case.get("baseline_version"),
        "target_version": case.get("target_version"),
        "status": case.get("status"),
        "failure_kind": case.get("failure_kind"),
        "failure_subtype": case.get("failure_subtype"),
        "baseline_execution_observation": case.get("baseline_execution_observation"),
        "target_execution_observation": case.get("target_execution_observation"),
        "compare_url": case.get("compare_url"),
        "analysis_dir": str(analysis_root),
        "llm_output_path": str(analysis_root / "llm-hunk-analysis.md"),
        "llm_hunk_judgment_path": None,
        "llm_hunk_judgment_error_path": None,
        "llm_judgment_path": None,
        "llm_judgment_error_path": None,
        "scenario_type": scenario.get("scenario_type"),
        "trace_keywords": scenario.get("trace_keywords"),
        "trace_has_difference": case.get("trace_has_difference"),
        "trace_has_effective_difference": case.get("trace_has_effective_difference"),
        "trace_evidence_valid": case.get("trace_evidence_valid"),
        "trace_invalid_reasons": trace_invalid_reasons,
        "failure_excerpt_keywords": scenario.get("failure_excerpt_keywords"),
        "baseline_command": scenario.get("baseline_command"),
        "target_command": scenario.get("target_command"),
        "has_final_response": False,
        "diagnosis": "",
        "diagnosis_short": "",
        "selected_hunks_text": "",
        "selected_hunk_count": 0,
        "selected_hunk_paths": [],
        "selected_hunks": [],
        "selected_hunk_payloads": [],
        "judgment_payload_count": 0,
        "judgment_payloads": [],
        "hunk_judgment_count": 0,
        "hunk_judgments": [],
        "supporting_evidence": "",
        "open_questions": "",
        "final_response_markdown": None,
        "judgment_source": "invalid_trace_auto_rule",
        "rule_judgment": {},
        "llm_judgment": {},
        "prompt_version": None,
        "judgment_scores": {},
        "judgment_signals": {},
        "compatibility_breakage_present": False,
        "trace_evidence_effective": False,
        "judged_hunk_count": 0,
        "judged_hunk_paths": [],
        "strong_fix_evidence_present": False,
        "vulnerability_presence_score": 90,
        "final_failure_reason": "invalid_trace_difference",
        "vulnerability_presence_verdict": "possibly_yes",
        "judgment_confidence": "low",
        "fix_evidence_strength": "",
        "exploit_breakage_evidence_strength": "",
        "llm_key_evidence": [
            "seek_patch=false 且 failure_subtype=invalid_trace_difference，未使用有效 trace 证据，直接保守视为仍受影响。",
        ],
        "judgment_rationale_short": shorten_text(rationale),
        "judgment_rationale": rationale,
        "seek_patch": case.get("seek_patch"),
    }



def main() -> int:
    args = parse_args()
    batch_summary_path = pathlib.Path(args.batch_summary).expanduser().resolve()
    output_json_path = pathlib.Path(args.output_json).expanduser().resolve()
    output_csv_path = pathlib.Path(args.output_csv).expanduser().resolve()
    llm_api_key = resolve_llm_api_key(args)

    summary = json.loads(batch_summary_path.read_text(encoding="utf-8"))
    status_filter = args.status_filter.split(",") if args.status_filter else []
    selected_cases = list(iter_selected_cases(summary, status_filter))

    entries: List[dict] = []
    missing_scenario = 0
    missing_markdown = 0
    missing_final_response = 0

    for case in selected_cases:
        analysis_dir = case.get("analysis_dir")
        if not analysis_dir:
            continue
        analysis_root = pathlib.Path(analysis_dir).expanduser().resolve()
        scenario_path = analysis_root / "llm-scenario.json"
        markdown_path = analysis_root / "llm-hunk-analysis.md"

        if not scenario_path.exists():
            missing_scenario += 1
            continue

        # 特例：seek_patch=false 且 invalid_trace_difference 时，即便没有 llm-hunk-analysis.md，
        # 也直接构造一个“受影响”的保守条目，避免这类 case 完全缺失于后续评估。
        failure_subtype = str(case.get("failure_subtype") or "").strip().lower()
        seek_patch = case.get("seek_patch")
        seek_patch_false = (isinstance(seek_patch, bool) and seek_patch is False) or (
            not isinstance(seek_patch, bool) and str(seek_patch).strip().lower() == "false"
        )

        if not markdown_path.exists():
            if failure_subtype == "invalid_trace_difference" and seek_patch_false:
                scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
                entry = build_invalid_trace_entry(
                    case=case,
                    scenario=scenario,
                    analysis_root=analysis_root,
                )
                entries.append(entry)
                # 对这类特意处理的 case 不计入 missing_markdown，避免误导统计
                continue
            missing_markdown += 1
            continue

        scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
        markdown_text = markdown_path.read_text(encoding="utf-8", errors="replace")
        entry = build_entry(
            case=case,
            scenario=scenario,
            analysis_root=analysis_root,
            markdown_text=markdown_text,
            args=args,
            llm_api_key=llm_api_key,
        )
        if args.require_final_response and not entry["has_final_response"]:
            missing_final_response += 1
            continue
        if not entry["has_final_response"]:
            missing_final_response += 1
        entries.append(entry)

    final_reason_counts = Counter(entry["final_failure_reason"] for entry in entries)
    vulnerability_presence_counts = Counter(entry["vulnerability_presence_verdict"] for entry in entries)
    confidence_counts = Counter(entry["judgment_confidence"] for entry in entries)
    judgment_source_counts = Counter(entry["judgment_source"] for entry in entries)
    llm_judgment_available_count = sum(1 for entry in entries if entry.get("llm_judgment"))

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "batch_summary_path": str(batch_summary_path),
        "score_no_threshold": VULNERABILITY_PRESENCE_SCORE_NO_THRESHOLD,
        "score_yes_threshold": VULNERABILITY_PRESENCE_SCORE_YES_THRESHOLD,
        "status_filter": [status.strip() for status in status_filter if status.strip()],
        "total_cases": len(summary.get("cases", [])),
        "selected_cases": len(selected_cases),
        "aggregated_entries": len(entries),
        "missing_scenario_count": missing_scenario,
        "missing_markdown_count": missing_markdown,
        "missing_final_response_count": missing_final_response,
        "judgment_mode": args.judgment_mode,
        "judgment_source_counts": dict(judgment_source_counts),
        "llm_judgment_available_count": llm_judgment_available_count,
        "final_failure_reason_counts": dict(final_reason_counts),
        "vulnerability_presence_counts": dict(vulnerability_presence_counts),
        "judgment_confidence_counts": dict(confidence_counts),
        "entries": entries,
    }

    output_json_path.parent.mkdir(parents=True, exist_ok=True)
    output_csv_path.parent.mkdir(parents=True, exist_ok=True)
    output_json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    csv_rows = []
    for entry in entries:
        csv_rows.append(
            {
                "case_id": entry["case_id"],
                "cve_id": entry["cve_id"],
                "pair_index": entry["pair_index"],
                "artifact": entry["artifact"],
                "description": entry.get("description") or "",
                "baseline_version": entry["baseline_version"],
                "target_version": entry["target_version"],
                "status": entry["status"],
                "failure_kind": entry["failure_kind"],
                "failure_subtype": entry["failure_subtype"],
                "scenario_type": entry["scenario_type"],
                "selected_hunk_count": entry["selected_hunk_count"],
                "selected_hunk_paths": " ; ".join(entry["selected_hunk_paths"]),
                "hunk_judgment_count": entry.get("hunk_judgment_count") or 0,
                "hunk_judgment_labels": " ; ".join(
                    "{}:{}".format(item.get("hunk_path", ""), item.get("judgment", ""))
                    for item in (entry.get("hunk_judgments") or [])
                ),
                "diagnosis_short": entry["diagnosis_short"],
                "diagnosis": entry["diagnosis"],
                "vulnerability_presence_score": entry["vulnerability_presence_score"],
                "final_failure_reason": entry["final_failure_reason"],
                "vulnerability_presence_verdict": entry["vulnerability_presence_verdict"],
                "judgment_confidence": entry["judgment_confidence"],
                "judgment_source": entry["judgment_source"],
                "fix_evidence_strength": entry.get("fix_evidence_strength", ""),
                "exploit_breakage_evidence_strength": entry.get("exploit_breakage_evidence_strength", ""),
                "llm_key_evidence": " ; ".join(entry.get("llm_key_evidence", [])),
                "judgment_rationale_short": entry["judgment_rationale_short"],
                "judgment_rationale": entry["judgment_rationale"],
                "trace_keywords": entry.get("trace_keywords") or "",
                "failure_excerpt_keywords": entry.get("failure_excerpt_keywords") or "",
                "analysis_dir": entry["analysis_dir"],
                "llm_output_path": entry["llm_output_path"],
                "llm_hunk_judgment_path": entry.get("llm_hunk_judgment_path") or "",
                "llm_judgment_path": entry.get("llm_judgment_path") or "",
            }
        )

    fieldnames = [
        "case_id",
        "cve_id",
        "pair_index",
        "artifact",
        "description",
        "baseline_version",
        "target_version",
        "status",
        "failure_kind",
        "failure_subtype",
        "scenario_type",
        "selected_hunk_count",
        "selected_hunk_paths",
        "hunk_judgment_count",
        "hunk_judgment_labels",
        "diagnosis_short",
        "diagnosis",
        "vulnerability_presence_score",
        "final_failure_reason",
        "vulnerability_presence_verdict",
        "judgment_confidence",
        "judgment_source",
        "fix_evidence_strength",
        "exploit_breakage_evidence_strength",
        "llm_key_evidence",
        "judgment_rationale_short",
        "judgment_rationale",
        "trace_keywords",
        "failure_excerpt_keywords",
        "analysis_dir",
        "llm_output_path",
        "llm_hunk_judgment_path",
        "llm_judgment_path",
    ]
    with output_csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    print(
        "Wrote {} aggregated entries to {} and {} (selected_cases={}, missing_scenario={}, missing_markdown={}, missing_final_response={}, judgment_mode={}, judgment_source_counts={}, final_failure_reason_counts={}, vulnerability_presence_counts={}).".format(
            len(entries),
            output_json_path,
            output_csv_path,
            len(selected_cases),
            missing_scenario,
            missing_markdown,
            missing_final_response,
            args.judgment_mode,
            dict(judgment_source_counts),
            dict(final_reason_counts),
            dict(vulnerability_presence_counts),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
