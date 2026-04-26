#!/usr/bin/env python3

import asyncio
import fnmatch
import json
import pathlib
import re
import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from llm_token_logger import log_llm_usage
from version_diff_lib import load_version_diff_context, search_version_diff_context


@dataclass
class LLMAnalysisConfig:
    model: str
    base_url: str
    api_key: str
    max_rounds: int
    request_timeout_seconds: float = 180.0


ANALYSIS_SECTION_NAMES = ["Diagnosis", "Selected Hunks", "Supporting Evidence", "Open Questions"]
DEFAULT_READ_WINDOW = 120
MAX_READ_LINES = 120
MAX_TOOL_RESULT_LINES = 60
MAX_TOOL_RESULT_CHARS = 3600
MAX_KEYWORD_RESULTS = 8
MAX_CODE_CONTEXT_RESULTS = 6
MAX_PROMPT_KEYWORDS = 12
MAX_INLINE_VALUE_CHARS = 220
MAX_JUDGMENT_HUNKS = 5
MAX_HUNK_DIFF_LINES = 80
MAX_HUNK_DIFF_CHARS = 5200
MAX_HUNK_KEY_EVIDENCE = 8
MAX_REPAIR_CANDIDATE_HUNKS = 5
DIRECT_DIFF_PROMPT_VERSION = "direct_diff_v6"
HUNK_JUDGMENT_PROMPT_VERSION = "per_hunk_v4"
MIN_VULNERABILITY_PRESENCE_SCORE = 0
MAX_VULNERABILITY_PRESENCE_SCORE = 100
CONCRETE_DIFF_PATH_PATTERN = re.compile(r"((?:version-diff/)?(?:api-diffs|diffs)/[^\s)]+?\.diff)")
SUPPLEMENTAL_EVIDENCE_PATH_PATTERN = re.compile(
    r"(version-diff/pom\.diff|dependency-tree\.diff|trace-diff-summary\.txt|(?:baseline|target)-observation-excerpt\.txt|target-prepare-generator-excerpt\.txt|execution-observations\.json)"
)
SELECTED_EVIDENCE_PATH_PATTERN = re.compile(
    r"((?:version-diff/)?(?:api-diffs|diffs)/[^\s)]+?\.diff|version-diff/pom\.diff|dependency-tree\.diff|trace-diff-summary\.txt|(?:baseline|target)-observation-excerpt\.txt|target-prepare-generator-excerpt\.txt|execution-observations\.json)"
)
SUPPLEMENTAL_PROMPT_PATHS = [
    ("trace summary", "trace-diff-summary.txt"),
    ("target failure excerpt", "target-observation-excerpt.txt"),
    ("baseline failure excerpt", "baseline-observation-excerpt.txt"),
    ("target prepare/generator excerpt", "target-prepare-generator-excerpt.txt"),
    ("dependency tree diff", "dependency-tree.diff"),
    ("execution observations", "execution-observations.json"),
    ("pom diff", "version-diff/pom.diff"),
]
JAVA_SYMBOL_PATTERN = re.compile(r"\b(?:[A-Za-z_]\w*(?:[./$][A-Za-z_]\w*){1,12})\b")
CAMEL_CASE_PATTERN = re.compile(r"\b[A-Z][A-Za-z0-9$]{3,}\b")
CLEAR_FIX_SIGNAL_PATTERN = re.compile(
    r"\b(validate\w*|validator\w*|validation|sanitize\w*|guard(?:rail)?s?|check\w*|"
    r"reject(?:ed|s|ing)?|block(?:ed|s|ing)?|escape\w*|canonicaliz\w*|patch(?:ed|es|ing)?|fix(?:ed|es|ing)?)\b",
    flags=re.IGNORECASE,
)
SIMPLE_CASE_SIGNAL_PATTERN = re.compile(
    r"\b(missing class|missing symbol|cannot find symbol|symbol not found|classnotfound(?:exception)?|"
    r"no such method|nosuchmethod(?:error)?|nosuchfield(?:error)?|noclassdeffound(?:error)?|"
    r"linkageerror|verifyerror|arrayindexoutofboundsexception|dependency resolution failure|artifact resolution|version conflict|"
    r"api (?:change|changes|mismatch|reorganization)|binary incompat)\b",
    flags=re.IGNORECASE,
)
LOGGER_NOISE_PATTERN = re.compile(r"\b(?:internalloggerfactory|internallogger|loggerfactory|slf4jlogger)\b", flags=re.IGNORECASE)
GENERIC_SEARCH_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "bad",
    "baseline",
    "case",
    "cases",
    "cve",
    "details",
    "effective",
    "error",
    "errors",
    "exception",
    "fail",
    "failed",
    "failure",
    "failures",
    "file",
    "files",
    "final",
    "first",
    "individual",
    "line",
    "lines",
    "location",
    "please",
    "reason",
    "refer",
    "regression",
    "results",
    "round",
    "run",
    "scenario",
    "selected",
    "skipped",
    "target",
    "test",
    "tests",
    "there",
    "trace",
    "version",
    "versions",
}
VERSION_LIKE_TOKEN_PATTERN = re.compile(
    r"^(?:\d+(?:[._-]\d+){0,5}(?:[A-Za-z]+\d*)?|[A-Za-z]+__\d+|[A-Za-z]*\d+[A-Za-z\d._-]*)$"
)
VULNERABILITY_SEMANTIC_TERM_PATTERN = re.compile(
    r"\b(?:header|headers|validator|validation|validate|decoder|parser|token|whitespace|lineparser|headerparser|"
    r"defaulthttpheaders|httpobjectdecoder|httputil|httpheadervalidationutil|ascii|string|contentdisposition|security)\b",
    flags=re.IGNORECASE,
)
MAIN_CLASS_DIFF_PATTERN = re.compile(r"(?:^|/)([^/$]+)\.diff$", flags=re.IGNORECASE)
SYNTHETIC_CLASS_DIFF_PATTERN = re.compile(r"\$\d+\.diff$", flags=re.IGNORECASE)


def _clamp_vulnerability_presence_score(value: object, default: int = 50) -> int:
    try:
        numeric = int(round(float(value)))
    except (TypeError, ValueError):
        numeric = default
    return max(MIN_VULNERABILITY_PRESENCE_SCORE, min(MAX_VULNERABILITY_PRESENCE_SCORE, numeric))


def _strength_to_fix_score_points(value: str) -> int:
    return {
        "none": 0,
        "weak": 8,
        "medium": 18,
        "strong": 30,
    }.get(str(value).strip().lower(), 0)


def _strength_to_exploit_score_points(value: str) -> int:
    return {
        "none": 0,
        "weak": 6,
        "medium": 14,
        "strong": 24,
    }.get(str(value).strip().lower(), 0)


def _confidence_to_score_points(value: str) -> int:
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


def _derive_vulnerability_presence_score(
    final_failure_reason: str,
    vulnerability_presence_verdict: str,
    judgment_confidence: str,
    fix_strength: str,
    exploit_strength: str,
    evidence_text: str = "",
) -> int:
    verdict_base = {
        "no": 32,
        "possibly_yes": 68,
        "unknown": 50,
    }.get(vulnerability_presence_verdict, 50)
    reason_offset = {
        "vulnerability_not_present": -12,
        "exploit_invalid_due_to_version_change": 8,
        "undetermined": 0,
    }.get(final_failure_reason, 0)
    score = verdict_base + reason_offset
    score += _strength_to_exploit_score_points(exploit_strength)
    score -= _strength_to_fix_score_points(fix_strength)
    score += _exploit_text_bonus(evidence_text)
    score -= _fix_text_bonus(evidence_text)

    confidence_offset = _confidence_to_score_points(judgment_confidence)
    if score > 50:
        score += confidence_offset
    elif score < 50:
        score -= confidence_offset

    return _clamp_vulnerability_presence_score(score)


def _truncate_inline_text(value: object, limit: int = MAX_INLINE_VALUE_CHARS) -> str:
    compact = " ".join(str(value).split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."



def _truncate_multiline_text(
    text: str,
    max_lines: int = MAX_TOOL_RESULT_LINES,
    max_chars: int = MAX_TOOL_RESULT_CHARS,
) -> str:
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
        clipped = clipped.rstrip() + "\n...(truncated; request a narrower window if needed)"
    return clipped



def _is_generic_search_term(term: str, *, keep_logger_terms: bool = False) -> bool:
    lowered = str(term or "").strip().lower()
    if not lowered:
        return True
    compact = lowered.replace(".", "").replace("/", "").replace("$", "")
    if len(compact) < 4:
        return True
    if lowered in GENERIC_SEARCH_STOPWORDS:
        return True
    if lowered.startswith("cve-") or lowered.startswith("cve"):
        return True
    if VERSION_LIKE_TOKEN_PATTERN.match(lowered):
        return True
    if not keep_logger_terms and LOGGER_NOISE_PATTERN.search(lowered):
        return True
    if all(not char.isalpha() for char in lowered):
        return True
    return False



def _sanitize_search_terms(
    value: object,
    *,
    limit: int,
    keep_logger_terms: bool = False,
) -> List[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        raw_items = [str(item) for item in value]
    else:
        raw_items = [str(value)]

    sanitized: List[str] = []
    seen = set()
    for raw_item in raw_items:
        for fragment in re.split(r"[\s,\n]+", raw_item):
            cleaned = fragment.strip().strip("`'\"[](){}:;,.!?")
            if not cleaned or _is_generic_search_term(cleaned, keep_logger_terms=keep_logger_terms):
                continue
            if cleaned in seen:
                continue
            seen.add(cleaned)
            sanitized.append(cleaned)
            if len(sanitized) >= limit:
                return sanitized
    return sanitized



def _extract_trace_focus_terms(analysis_root: pathlib.Path, limit: int = 20) -> List[str]:
    raw_terms: List[str] = []
    trace_summary_path = analysis_root / "trace-diff-summary.txt"
    if trace_summary_path.exists() and trace_summary_path.is_file():
        try:
            trace_summary_text = trace_summary_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            trace_summary_text = ""
    else:
        trace_summary_text = ""
    if trace_summary_text:
        for raw_line in trace_summary_text.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            if stripped.startswith(("baseline:", "target:", "- ")):
                raw_terms.extend(match.group(0) for match in JAVA_SYMBOL_PATTERN.finditer(stripped))
                raw_terms.extend(match.group(0) for match in CAMEL_CASE_PATTERN.finditer(stripped))

    summary_path = analysis_root / "version-diff" / "summary.json"
    if summary_path.exists() and summary_path.is_file():
        try:
            summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            summary_payload = {}
        if isinstance(summary_payload, dict):
            for key in ("changed_classes_preview", "removed_classes_preview", "added_classes_preview"):
                preview_items = summary_payload.get(key)
                if isinstance(preview_items, list):
                    raw_terms.extend(str(item) for item in preview_items[:8])

    prioritized = _sanitize_search_terms(raw_terms, limit=limit * 2, keep_logger_terms=False)
    scored_terms = []
    for index, term in enumerate(prioritized):
        score = 0
        lowered = term.lower()
        if VULNERABILITY_SEMANTIC_TERM_PATTERN.search(lowered):
            score += 8
        if "." in term or "/" in term:
            score += 3
        if "$" not in term:
            score += 2
        scored_terms.append((score, index, term))
    scored_terms.sort(key=lambda item: (-item[0], item[1]))
    return [term for _, _, term in scored_terms[:limit]]



def _extract_seed_keywords(value: object, limit: int = MAX_PROMPT_KEYWORDS) -> List[str]:
    return _sanitize_search_terms(value, limit=limit, keep_logger_terms=False)



def _normalize_section_heading(raw_heading: str) -> str:
    normalized = raw_heading.strip()
    normalized = re.sub(r"^#+\s*", "", normalized)
    normalized = re.sub(r"^(?:[-*+]\s+|\d+[\.)]\s+)", "", normalized)
    normalized = re.sub(r"^\*\*(.*?)\*\*$", r"\1", normalized)
    normalized = normalized.strip().strip(":：").strip()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def _parse_markdown_sections(markdown_text: str) -> Dict[str, str]:
    sections: Dict[str, List[str]] = {name: [] for name in ANALYSIS_SECTION_NAMES}
    current: Optional[str] = None
    for raw_line in markdown_text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            continue
        normalized_heading = _normalize_section_heading(stripped)
        if normalized_heading in sections:
            current = normalized_heading
            continue
        if current is not None:
            sections[current].append(raw_line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}



def _unique_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered



def _extract_selected_hunks_markdown(markdown_text: str) -> str:
    sections = _parse_markdown_sections(markdown_text)
    selected_hunks = sections.get("Selected Hunks", "")
    if selected_hunks.strip():
        return selected_hunks.strip()
    return str(markdown_text or "").strip()



def _extract_selected_evidence_paths_from_markdown(markdown_text: str) -> List[str]:
    selected_hunks = _extract_selected_hunks_markdown(markdown_text)
    paths = [
        _normalize_diff_path(match.group(1))
        for match in SELECTED_EVIDENCE_PATH_PATTERN.finditer(selected_hunks)
    ]
    return _unique_preserve_order([path for path in paths if path])



def _extract_existing_selected_evidence_paths(
    analysis_root: pathlib.Path,
    markdown_text: str,
) -> List[str]:
    existing_paths: List[str] = []
    for path in _extract_selected_evidence_paths_from_markdown(markdown_text):
        resolved = (analysis_root / path).resolve()
        if resolved.exists() and resolved.is_file():
            existing_paths.append(path)
    return _unique_preserve_order(existing_paths)



def _final_response_needs_concrete_diff_repair(
    analysis_root: pathlib.Path,
    markdown_text: str,
) -> bool:
    return not _extract_existing_selected_evidence_paths(analysis_root, markdown_text)



def _normalize_search_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", ".", value.lower()).strip(".")



def _extract_repair_terms(
    analysis_root: pathlib.Path,
    scenario: Dict[str, object],
    markdown_text: str,
) -> List[str]:
    raw_terms: List[str] = []
    raw_terms.extend(_extract_seed_keywords(scenario.get("failure_excerpt_keywords"), limit=16))
    raw_terms.extend(_extract_seed_keywords(scenario.get("trace_keywords"), limit=24))
    raw_terms.extend(_extract_trace_focus_terms(analysis_root, limit=20))
    source_text = str(markdown_text or "")
    raw_terms.extend(match.group(0) for match in JAVA_SYMBOL_PATTERN.finditer(source_text))
    raw_terms.extend(match.group(0) for match in CAMEL_CASE_PATTERN.finditer(source_text))

    filtered: List[str] = []
    seen = set()
    ignored_tails = {"class", "diff", "json", "txt", "java", "log"}
    removable_suffixes = [".class.diff", ".class", ".diff", ".json", ".txt", ".java", ".log"]
    for term in raw_terms:
        cleaned = term.strip()
        lowered = cleaned.lower()
        changed = True
        while changed:
            changed = False
            for suffix in removable_suffixes:
                if lowered.endswith(suffix):
                    cleaned = cleaned[: -len(suffix)]
                    lowered = cleaned.lower()
                    changed = True
        if _is_generic_search_term(cleaned, keep_logger_terms=False):
            continue
        normalized = _normalize_search_token(cleaned)
        if len(normalized.replace(".", "")) < 4:
            continue
        if normalized.split(".")[-1] in ignored_tails:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        filtered.append(cleaned)

    scored_terms = []
    for index, term in enumerate(filtered):
        lowered = term.lower()
        score = 0
        if VULNERABILITY_SEMANTIC_TERM_PATTERN.search(lowered):
            score += 8
        if "." in term or "/" in term:
            score += 4
        if "$" not in term:
            score += 2
        if LOGGER_NOISE_PATTERN.search(lowered):
            score -= 20
        scored_terms.append((score, index, term))
    scored_terms.sort(key=lambda item: (-item[0], item[1]))
    return [term for _, _, term in scored_terms[:48]]



def _iter_available_concrete_diff_paths(analysis_root: pathlib.Path) -> List[str]:
    diff_root = _version_diff_root(analysis_root)
    collected: List[str] = []
    for subdir_name in ["api-diffs", "diffs"]:
        subdir = diff_root / subdir_name
        if not subdir.exists():
            continue
        for file_path in sorted(subdir.rglob("*.diff")):
            collected.append(file_path.relative_to(analysis_root).as_posix())
    return collected



def _iter_available_supporting_evidence_paths(analysis_root: pathlib.Path) -> List[str]:
    collected: List[str] = []
    for relative_path in [path for _, path in SUPPLEMENTAL_PROMPT_PATHS]:
        candidate = analysis_root / relative_path
        if candidate.exists() and candidate.is_file():
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if not text:
                continue
            collected.append(relative_path)
    return _unique_preserve_order(collected)



def _score_diff_path_against_terms(path: str, terms: List[str]) -> int:
    normalized_path = _normalize_search_token(path)
    basename = pathlib.PurePosixPath(path).stem.lower()
    score = 0
    for term in terms:
        normalized_term = _normalize_search_token(term)
        if not normalized_term:
            continue
        tail = normalized_term.split(".")[-1]
        if len(tail) < 4:
            continue
        if tail == basename:
            score += 40
            continue
        if normalized_term in normalized_path:
            score += min(28, 10 + len(tail))
            continue
        if tail in basename:
            score += min(24, 8 + len(tail))
            continue
        if tail in normalized_path:
            score += min(16, 4 + len(tail) // 2)
    if path.startswith("version-diff/api-diffs/"):
        score += 1
    if VULNERABILITY_SEMANTIC_TERM_PATTERN.search(path):
        score += 8
    if MAIN_CLASS_DIFF_PATTERN.search(path) and "$" not in pathlib.PurePosixPath(path).name:
        score += 6
    if SYNTHETIC_CLASS_DIFF_PATTERN.search(path):
        score -= 8
    if LOGGER_NOISE_PATTERN.search(path):
        score -= 24
    return score



def _find_repair_candidate_hunks(
    analysis_root: pathlib.Path,
    scenario: Dict[str, object],
    markdown_text: str,
    limit: int = MAX_REPAIR_CANDIDATE_HUNKS,
) -> List[Dict[str, str]]:
    terms = _extract_repair_terms(analysis_root, scenario, markdown_text)
    scored_paths = []
    for path in _iter_available_concrete_diff_paths(analysis_root):
        score = _score_diff_path_against_terms(path, terms)
        if score <= 0:
            continue
        scored_paths.append((score, path))

    scored_paths.sort(key=lambda item: (-item[0], item[1]))
    selected: List[Dict[str, str]] = []
    seen_class_keys = set()
    for _, path in scored_paths:
        class_key = pathlib.PurePosixPath(path).stem.lower()
        if class_key in seen_class_keys:
            continue
        diff_text = (analysis_root / path).read_text(encoding="utf-8", errors="replace")
        selected.append(
            {
                "path": path,
                "diff_excerpt": _truncate_multiline_text(diff_text, max_lines=20, max_chars=1400),
            }
        )
        seen_class_keys.add(class_key)
        if len(selected) >= max(1, limit):
            break

    if selected:
        return selected

    for path in _iter_available_supporting_evidence_paths(analysis_root):
        try:
            evidence_text = (analysis_root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        selected.append(
            {
                "path": path,
                "diff_excerpt": _truncate_multiline_text(evidence_text, max_lines=20, max_chars=1400),
            }
        )
        if len(selected) >= max(1, limit):
            break
    return selected



def _render_concrete_hunk_bullets(candidate_hunks: List[Dict[str, str]]) -> str:
    rendered: List[str] = []
    for item in candidate_hunks:
        path = str(item.get("path") or "").strip()
        excerpt = str(item.get("diff_excerpt") or "").strip()
        if not path:
            continue
        rendered.append("- {}".format(path))
        if excerpt:
            rendered.extend("  {}".format(line) for line in excerpt.splitlines())
        rendered.append("")
    return "\n".join(rendered).strip()



def _build_concrete_diff_repair_prompt(
    scenario: Dict[str, object],
    previous_response: str,
    candidate_hunks: List[Dict[str, str]],
) -> str:
    has_concrete_diff = any(
        CONCRETE_DIFF_PATH_PATTERN.search(str(item.get("path") or ""))
        for item in candidate_hunks
    )
    lines = [
        "Your previous answer violated the output contract.",
        "Problem: Selected Hunks did not cite any usable evidence file path.",
        "Prefer concrete diff files under version-diff/api-diffs or version-diff/diffs whenever they are available and relevant.",
        "If no concrete code diff is available, you may instead cite fallback evidence files such as trace-diff-summary.txt, *-observation-excerpt.txt, dependency-tree.diff, execution-observations.json, or version-diff/pom.diff.",
        "Do not cite version-diff/llm-guide.txt, removed-classes.txt, or added-classes.txt in Selected Hunks.",
        "Rewrite the final markdown answer now with exactly these sections:",
        "Diagnosis",
        "Selected Hunks",
        "Supporting Evidence",
        "Open Questions",
        (
            "Each Selected Hunks bullet must cite one of the evidence paths below and include a minimal raw excerpt."
            if has_concrete_diff
            else "Each Selected Hunks bullet must cite one of the fallback evidence paths below and include a minimal raw excerpt."
        ),
        "If only 1-3 candidates are truly relevant, use only those; do not invent paths.",
        "",
        "Scenario summary:",
    ]
    lines.extend(_build_analysis_scenario_lines(scenario))
    lines.extend([
        "",
        "Previous invalid answer:",
        previous_response.strip(),
        "",
        "Repair candidates:",
        _render_concrete_hunk_bullets(candidate_hunks),
    ])
    return "\n".join(lines)



def _build_deterministic_repaired_markdown(previous_response: str, candidate_hunks: List[Dict[str, str]]) -> str:
    sections = _parse_markdown_sections(previous_response)
    diagnosis = sections.get("Diagnosis", "").strip() or "Unable to preserve the original diagnosis during evidence repair."
    supporting_evidence = sections.get("Supporting Evidence", "").strip() or "Evidence repair preserved only the strongest available excerpts."
    open_questions = sections.get("Open Questions", "").strip()
    selected_hunks = _render_concrete_hunk_bullets(candidate_hunks)
    rebuilt_sections = [
        "Diagnosis\n{}".format(diagnosis),
        "Selected Hunks\n{}".format(selected_hunks or "- (no usable evidence file was available)"),
        "Supporting Evidence\n{}".format(supporting_evidence),
        "Open Questions\n{}".format(open_questions),
    ]
    return "\n\n".join(rebuilt_sections).strip()



def _build_analysis_scenario_lines(scenario: Dict[str, object]) -> List[str]:
    lines = [
        "Scenario summary:",
        "- type: {}".format(_truncate_inline_text(scenario.get("scenario_type", "unknown"), 120)),
        "- artifact: {} ({} -> {})".format(
            _truncate_inline_text(scenario.get("artifact", "unknown"), 120),
            _truncate_inline_text(scenario.get("baseline_version", "?"), 40),
            _truncate_inline_text(scenario.get("target_version", "?"), 40),
        ),
        "- execution observations: baseline={}, target={}".format(
            _truncate_inline_text(scenario.get("baseline_execution_observation", "unknown"), 80),
            _truncate_inline_text(scenario.get("target_execution_observation", "unknown"), 80),
        ),
    ]
    keyword_seeds = _extract_seed_keywords(
        scenario.get("failure_excerpt_keywords") or scenario.get("trace_keywords")
    )
    if keyword_seeds:
        lines.append("- keyword seeds: {}".format(", ".join(keyword_seeds)))
    for key in [
        "failure_excerpt_file",
        "trace_summary_file",
        "dependency_tree_diff",
        "baseline_trace",
        "target_trace",
        "artifact_diff_root",
    ]:
        value = scenario.get(key)
        if value:
            lines.append("- {}: {}".format(key, _truncate_inline_text(value, 160)))
    return lines



def _scenario_signal_text(scenario: Dict[str, object]) -> str:
    parts: List[str] = []
    for key in [
        "scenario_type",
        "failure_excerpt_keywords",
        "trace_keywords",
        "failing_command",
        "baseline_execution_observation",
        "target_execution_observation",
        "artifact",
    ]:
        value = scenario.get(key)
        if value not in (None, ""):
            parts.append(str(value))
    return "\n".join(parts)



def _effective_tool_round_budget(scenario: Dict[str, object], configured_max_rounds: int) -> int:
    budget = max(1, configured_max_rounds)
    scenario_type = str(scenario.get("scenario_type", "")).strip().lower()
    signal_text = _scenario_signal_text(scenario)

    if scenario_type in {"compile_failure", "runtime_failure"}:
        return min(budget, 1)
    if scenario_type == "process_failure":
        return min(budget, 2)
    if CLEAR_FIX_SIGNAL_PATTERN.search(signal_text) or SIMPLE_CASE_SIGNAL_PATTERN.search(signal_text):
        return min(budget, 2)
    return budget



def build_analysis_prompt(scenario: Dict[str, object]) -> str:
    lines = [
        "You are analyzing a dependency version regression.",
        "Goal: find the smallest high-signal evidence items that explain the observed failure or trace divergence.",
        "Use tools sparingly, but for trace_diff cases prefer 2-5 selected hunks/evidence items when multiple candidates remain plausible; do not collapse the case to a single class too early.",
        "For obvious compile/runtime incompatibility or direct validator/fix-helper cases, do one focused search pass, one narrow read only if needed, then answer.",
        "Start with version-diff/llm-guide.txt, version-diff/summary.json, and trace-diff-summary.txt when present.",
        "If case context says trace_has_effective_difference=false or provides trace_invalid_reasons, treat trace-diff-summary.txt as weak background only, not as primary vulnerability evidence.",
        "Use keyword_search on version-diff and the referenced trace/failure files to narrow candidates.",
        "Do not search generic surefire boilerplate tokens such as Tests/Failures/Errors/Skipped/Please/There, bare CVE ids, or raw version strings; pivot to class/method/package tokens first.",
        "If trace keywords include InternalLoggerFactory or other initialization noise, pivot away from logger symbols and prioritize the first non-noise target-side HTTP/security class plus the changed top-level classes from version-diff/summary.json.",
        "Always inspect a cited file with read_file before citing it.",
        "Prefer version-diff/api-diffs/*.diff first; use version-diff/diffs/*.diff when API diffs are too shallow to expose method-body behavior.",
        "If an api-diff only shows class signatures, field descriptors, static initializer shape, or other declaration-only changes, do not stop there: inspect the corresponding version-diff/diffs/*.diff or load_diff_context before finalizing.",
        "When a top-level class and its helper/inner-class diffs are both changed, prefer the top-level class first, then inspect the paired bytecode diff before relying on helper-only hunks.",
        "When trace keywords or divergence mention an inner class like Foo$Bar, always also inspect the corresponding top-level Foo.diff (both api-diffs and diffs) before deciding on Selected Hunks.",
        "Deprioritize logger-only diffs, anonymous/synthetic inner-class diffs such as $1.diff, and $SwitchMap / enum-reordering diffs unless they directly alter the vulnerable path exercised by the trace.",
        "For constructor/collection/map/self-reference style vulnerabilities, expand to the complete changed method or constructor context instead of citing only the class declaration.",
        "If no concrete code diff under version-diff/api-diffs or version-diff/diffs matches the trace/failure, you may cite fallback evidence files such as trace-diff-summary.txt, *-observation-excerpt.txt, dependency-tree.diff, execution-observations.json, or version-diff/pom.diff.",
        "Fallback evidence can explain uncertainty or harness/environment breakage, but by itself it does not prove a logic fix.",
        "Use load_diff_context or search_code_context only for the top 1 candidate class or method when the first search/read is still ambiguous.",
        "Avoid broad file reads; request narrow windows when possible.",
        "Stop calling tools immediately once you have enough evidence for a concise answer.",
        "Return markdown with exactly these sections:",
        "Diagnosis",
        "Selected Hunks",
        "Supporting Evidence",
        "Open Questions",
        "In Selected Hunks, prefer concrete diff file paths under version-diff/api-diffs or version-diff/diffs, each with a minimal raw diff excerpt (--- / +++ / @@ / +/- lines).",
        "If no relevant concrete diff exists, each Selected Hunks item may instead cite one fallback evidence file path and include a short raw excerpt while explicitly saying no concrete code diff matched.",
        "For trace_diff cases, prefer multiple concrete diff-file hunks over prose-only summaries such as removed_classes lists unless the case truly has no concrete diff candidate.",
        "",
    ]
    lines.extend(_build_analysis_scenario_lines(scenario))
    return "\n".join(lines)


def search_workspace(root: pathlib.Path, keywords: str, limit: int = MAX_KEYWORD_RESULTS, path_glob: str = "**/*") -> str:
    normalized_tokens = _sanitize_search_terms(keywords, limit=24, keep_logger_terms=False)
    tokens = [token.lower() for token in normalized_tokens]
    if not tokens:
        return "No high-signal search tokens remained after sanitizing keywords: {}".format(keywords)

    results = []
    safe_limit = max(1, min(limit, MAX_KEYWORD_RESULTS))

    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file():
            continue
        relative = file_path.relative_to(root)
        relative_text = relative.as_posix()
        if path_glob and path_glob not in ("**/*", "*") and not fnmatch.fnmatch(relative_text, path_glob):
            continue
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        except OSError:
            continue

        for index, line in enumerate(lines, start=1):
            haystack = (relative_text + " " + line).lower()
            score = sum(1 for token in tokens if token in haystack) if tokens else 0
            if score <= 0:
                continue
            results.append((score, relative_text, index, line.strip()))

    results.sort(key=lambda item: (-item[0], item[1], item[2]))
    if not results:
        return "No matches for keywords: {}".format(keywords)

    rendered = []
    for score, relative, index, line in results[:safe_limit]:
        rendered.append(
            "[score={}] {}:{}: {}".format(score, relative, index, _truncate_inline_text(line, 180))
        )
    return "\n".join(rendered)


def read_workspace_file(
    root: pathlib.Path,
    path: str,
    start_line: int = 1,
    end_line: int = DEFAULT_READ_WINDOW,
) -> str:
    candidate = pathlib.Path(path)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (root / candidate).resolve()

    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ValueError("Requested path is outside the analysis workspace: {}".format(path))

    if not resolved.exists() or not resolved.is_file():
        raise ValueError("Requested file does not exist: {}".format(path))

    content = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    safe_start = max(1, start_line)
    requested_end = max(safe_start, end_line)
    safe_end = min(len(content), requested_end, safe_start + MAX_READ_LINES - 1)

    rendered = []
    for index in range(safe_start, safe_end + 1):
        rendered.append("{:05d}: {}".format(index, content[index - 1]))

    if requested_end > safe_end:
        rendered.append("...(truncated to {} lines; request a narrower window if needed)".format(MAX_READ_LINES))
    return "\n".join(rendered)



def _version_diff_root(analysis_root: pathlib.Path) -> pathlib.Path:
    return analysis_root / "version-diff"



def _format_context_preview(label: str, context: Dict[str, object]) -> List[str]:
    lines = [
        "{}: anchor_line={} lines={}-{}".format(
            label,
            context.get("anchor_line"),
            context.get("start_line"),
            context.get("end_line"),
        )
    ]
    preview = str(context.get("preview") or "").strip()
    if preview:
        lines.append(_truncate_multiline_text(preview, max_lines=22, max_chars=1200))
    return lines



def _format_diff_context_payload(payload: Dict[str, object]) -> str:
    lines = [
        "diff_path: {}".format(payload.get("diff_path")),
        "baseline_raw_path: {}".format(payload.get("baseline_raw_path")),
        "target_raw_path: {}".format(payload.get("target_raw_path")),
    ]
    anchor_terms = payload.get("matched_anchor_terms") or []
    if anchor_terms:
        lines.append(
            "matched_anchor_terms: {}".format(", ".join(str(term) for term in list(anchor_terms)[:8]))
        )
    diff_excerpt = str(payload.get("diff_excerpt") or "").strip()
    if diff_excerpt:
        lines.append(
            "diff_excerpt_lines: {}-{}".format(
                payload.get("diff_excerpt_start_line"),
                payload.get("diff_excerpt_end_line"),
            )
        )
        lines.append(_truncate_multiline_text(diff_excerpt, max_lines=24, max_chars=1400))
    lines.extend(_format_context_preview("baseline_context", payload.get("baseline_context") or {}))
    lines.extend(_format_context_preview("target_context", payload.get("target_context") or {}))
    return _truncate_multiline_text("\n".join(lines), max_lines=70, max_chars=3200)



def load_diff_context(
    analysis_root: pathlib.Path,
    diff_path: str,
    hunk_hint: str = "",
    diff_start_line: Optional[int] = None,
    diff_end_line: Optional[int] = None,
    context_lines: int = 12,
) -> str:
    payload = load_version_diff_context(
        diff_root=_version_diff_root(analysis_root),
        diff_relative_path=diff_path,
        hunk_hint=hunk_hint,
        diff_start_line=diff_start_line,
        diff_end_line=diff_end_line,
        context_lines=context_lines,
    )
    return _format_diff_context_payload(payload)



def search_code_context(
    analysis_root: pathlib.Path,
    query: str,
    limit: int = MAX_CODE_CONTEXT_RESULTS,
    scope: str = "all",
) -> str:
    safe_limit = max(1, min(limit, MAX_CODE_CONTEXT_RESULTS))
    results = search_version_diff_context(
        diff_root=_version_diff_root(analysis_root),
        query=query,
        limit=safe_limit,
        scope=scope,
    )
    if not results:
        return "No code-context matches for query={!r} in scope={!r}".format(query, scope)

    lines = [
        "query: {}".format(_truncate_inline_text(query, 160)),
        "scope: {}".format(scope),
        "result_count: {}".format(len(results)),
    ]
    for item in results:
        lines.append(
            "[score={}] [{}:{}] {}:{}: {}".format(
                item.get("score"),
                item.get("scope"),
                item.get("variant"),
                item.get("path"),
                item.get("line"),
                _truncate_inline_text(item.get("text", ""), 180),
            )
        )
    return "\n".join(lines)



def _extract_json_object(raw_text: str) -> Dict[str, Any]:
    text = raw_text.strip()
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1 :]
        if text.endswith("```"):
            text = text[:-3].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or start >= end:
            raise
        return json.loads(text[start:end + 1])



def _coalesce_description(case_payload: Dict[str, object], scenario: Dict[str, object]) -> str:
    description = scenario.get("description") or case_payload.get("description") or ""
    text = str(description).strip()
    return text or "(description unavailable)"



def _normalize_diff_path(path: object) -> str:
    raw = str(path or "").strip()
    if not raw:
        return ""
    if raw.startswith("version-diff/"):
        return raw
    if raw.startswith(("api-diffs/", "diffs/")):
        return "version-diff/{}".format(raw)
    return raw



def _render_case_context_lines(case_payload: Dict[str, object], scenario: Dict[str, object]) -> List[str]:
    lines = []
    for key in [
        "case_id",
        "cve_id",
        "artifact",
        "baseline_version",
        "target_version",
        "status",
        "failure_kind",
        "failure_subtype",
        "compare_url",
    ]:
        value = case_payload.get(key) if key in case_payload else scenario.get(key)
        if value not in (None, ""):
            lines.append("- {}: {}".format(key, _truncate_inline_text(value, 220)))
    baseline_obs = scenario.get("baseline_execution_observation") or case_payload.get("baseline_execution_observation")
    target_obs = scenario.get("target_execution_observation") or case_payload.get("target_execution_observation")
    if baseline_obs not in (None, "") or target_obs not in (None, ""):
        lines.append(
            "- current_replay_observations: baseline={}, target={}".format(
                _truncate_inline_text(baseline_obs or "unknown", 80),
                _truncate_inline_text(target_obs or "unknown", 80),
            )
        )
    if case_payload.get("trace_has_difference") not in (None, ""):
        lines.append("- trace_has_difference: {}".format(case_payload.get("trace_has_difference")))
    if case_payload.get("trace_has_effective_difference") not in (None, ""):
        lines.append(
            "- trace_has_effective_difference: {}".format(case_payload.get("trace_has_effective_difference"))
        )
    if case_payload.get("trace_evidence_valid") not in (None, ""):
        lines.append("- trace_evidence_valid: {}".format(case_payload.get("trace_evidence_valid")))
    trace_invalid_reasons = case_payload.get("trace_invalid_reasons")
    if isinstance(trace_invalid_reasons, list) and trace_invalid_reasons:
        lines.append("- trace_invalid_reasons: {}".format(", ".join(str(item) for item in trace_invalid_reasons[:6])))
    first_divergence = case_payload.get("first_divergence")
    if isinstance(first_divergence, dict) and first_divergence:
        lines.append(
            "- first_divergence: baseline={} | target={} | index={}".format(
                _truncate_inline_text(first_divergence.get("baseline") or "", 180),
                _truncate_inline_text(first_divergence.get("target") or "", 180),
                _truncate_inline_text(first_divergence.get("index") or "?", 32),
            )
        )
    baseline_enter_count = case_payload.get("baseline_enter_count")
    target_enter_count = case_payload.get("target_enter_count")
    if baseline_enter_count not in (None, "") or target_enter_count not in (None, ""):
        lines.append(
            "- trace_enter_counts: baseline={}, target={}".format(
                _truncate_inline_text(baseline_enter_count or "unknown", 32),
                _truncate_inline_text(target_enter_count or "unknown", 32),
            )
        )
    return lines



def _resolve_analysis_root(case_payload: Dict[str, object], scenario: Dict[str, object]) -> Optional[pathlib.Path]:
    analysis_dir = case_payload.get("analysis_dir") or scenario.get("analysis_dir")
    if not analysis_dir:
        return None
    try:
        return pathlib.Path(str(analysis_dir)).expanduser().resolve()
    except OSError:
        return None



def _read_prompt_supporting_file(analysis_root: pathlib.Path, relative_path: str, max_lines: int = 18, max_chars: int = 1400) -> str:
    candidate = (analysis_root / relative_path).resolve()
    if not candidate.exists() or not candidate.is_file():
        return ""
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    if not text:
        return ""
    return _truncate_multiline_text(text, max_lines=max_lines, max_chars=max_chars)



def _render_supplemental_case_evidence(case_payload: Dict[str, object], scenario: Dict[str, object]) -> List[str]:
    analysis_root = _resolve_analysis_root(case_payload, scenario)
    if analysis_root is None:
        return []

    lines: List[str] = []
    summary_path = analysis_root / "version-diff" / "summary.json"
    if summary_path.exists() and summary_path.is_file():
        try:
            summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            summary_payload = None
        if isinstance(summary_payload, dict):
            lines.extend(
                [
                    "Version diff summary:",
                    "- changed_class_count={} added_class_count={} removed_class_count={}".format(
                        summary_payload.get("changed_class_count", "?"),
                        summary_payload.get("added_class_count", "?"),
                        summary_payload.get("removed_class_count", "?"),
                    ),
                    "",
                ]
            )

    for label, relative_path in SUPPLEMENTAL_PROMPT_PATHS:
        excerpt = _read_prompt_supporting_file(analysis_root, relative_path)
        if not excerpt:
            continue
        if relative_path == "dependency-tree.diff" and excerpt.strip() == "(no dependency tree diff)":
            continue
        lines.extend([
            "{}: {}".format(label, relative_path),
            excerpt,
            "",
        ])
    return lines



def _render_diff_blocks(hunk_payloads: List[Dict[str, object]]) -> List[str]:
    blocks: List[str] = []
    for index, payload in enumerate(hunk_payloads[:MAX_JUDGMENT_HUNKS], start=1):
        path = _normalize_diff_path(payload.get("path"))
        excerpt = str(payload.get("diff_excerpt") or "").strip()
        if not path and not excerpt:
            continue
        evidence_kind = str(payload.get("evidence_kind") or "diff").strip() or "diff"
        blocks.append("Evidence Item {} [{}]: {}".format(index, evidence_kind, path or "(path unavailable)"))
        if excerpt:
            blocks.append(excerpt)
        detail_text = str(payload.get("details") or "").strip()
        if detail_text:
            blocks.append("Notes: {}".format(_truncate_inline_text(detail_text, 240)))
        blocks.append("")
    return blocks



def build_hunk_judgment_prompt(
    case_payload: Dict[str, object],
    scenario: Dict[str, object],
    hunk_payload: Dict[str, object],
) -> str:
    artifact = case_payload.get("artifact") or scenario.get("artifact") or "unknown-artifact"
    baseline_version = case_payload.get("baseline_version") or scenario.get("baseline_version") or "?"
    target_version = case_payload.get("target_version") or scenario.get("target_version") or "?"
    description = _coalesce_description(case_payload, scenario)
    normalized_path = _normalize_diff_path(hunk_payload.get("path")) or "(path unavailable)"
    diff_excerpt = str(hunk_payload.get("diff_excerpt") or "").strip() or "(evidence unavailable)"
    evidence_kind = str(hunk_payload.get("evidence_kind") or "diff").strip() or "diff"
    prompt_lines = [
        "这是{}在{}到{}之间与漏洞利用执行失效相关的一个证据项（可能是 diff hunk、trace 摘要、依赖差异或失败摘录），漏洞的描述是：".format(
            artifact,
            baseline_version,
            target_version,
        ),
        description,
        "现在漏洞利用在{}可以复现，在{}不能复现。结合这个证据项，判断它更像哪一种证据：".format(
            baseline_version,
            target_version,
        ),
        "1. 目标版本修复/阻断漏洞（fix_evidence）",
        "2. 利用因版本/API/运行时/环境变化失效（exploit_breakage_evidence）",
        "3. 中性或信息不足（neutral）",
        "",
        "特别约束：",
        "- 仅仅出现 ClassNotFoundException / NoClassDefFoundError / JAXB 缺失 / classpath 失败，更像 exploit_breakage_evidence，而不是 fix_evidence。",
        "- VerifyError、LinkageError、ASM/字节码改写失败，更像 exploit_breakage_evidence 或 uncertainty，不应压过已经命中的强 fix hunk。",
        "- 如果 case context 显示 trace_has_effective_difference=false，或 trace_invalid_reasons 包含 empty trace / InternalLoggerFactory 初始化噪声，不要把 trace summary 当主要证据。",
        "- logger-only diff、$1 这类匿名/合成内部类 diff、$SwitchMap / enum 重排，通常应视为 neutral，除非它们直接修改了基线命中的脆弱逻辑路径。",
        "- 仅有字段类型变化、descriptor/static-initializer 变化、或很小的寄存器/receiver 字节码变化时，默认更接近 neutral，而不是直接推出 fix 或 persistence。",
        "- 只有当证据显示目标版本直接移除、短路或替换了基线中命中的脆弱逻辑路径时，才能判成强 fix_evidence。",
        "- pom.diff、dependency-tree.diff、trace-only 证据可以支持不确定性或兼容性失效解释，但通常不能单独证明漏洞已修复。",
        "",
        "请只基于下面提供的证据和当前回放观测，不要依赖外部漏洞知识。返回严格 JSON，且只包含这些键：",
        "hunk_path, judgment, confidence, key_evidence, reasoning",
        "允许值：",
        "- judgment: fix_evidence | exploit_breakage_evidence | neutral",
        "- confidence: high | medium | low",
        "- key_evidence: array of short strings",
        "Keep reasoning under 80 words.",
        "",
        "Case context:",
    ]
    prompt_lines.extend(_render_case_context_lines(case_payload, scenario))
    prompt_lines.extend([
        "",
        "Evidence kind:",
        evidence_kind,
        "",
        "Evidence path:",
        normalized_path,
        "",
        "Evidence excerpt:",
        diff_excerpt,
    ])
    return "\n".join(prompt_lines)



def build_vulnerability_judgment_prompt(
    case_payload: Dict[str, object],
    scenario: Dict[str, object],
    hunk_payloads: List[Dict[str, object]],
) -> str:
    artifact = case_payload.get("artifact") or scenario.get("artifact") or "unknown-artifact"
    baseline_version = case_payload.get("baseline_version") or scenario.get("baseline_version") or "?"
    target_version = case_payload.get("target_version") or scenario.get("target_version") or "?"
    description = _coalesce_description(case_payload, scenario)
    lines = [
        "这是{}在{}到{}之间与漏洞利用执行失效相关的证据，漏洞的描述是：".format(
            artifact,
            baseline_version,
            target_version,
        ),
        description,
        "现在漏洞利用在{}可以复现，在{}不能复现。结合下面给出的 diff / trace / failure evidence，判断目标版本是否仍存在漏洞。".format(
            baseline_version,
            target_version,
        ),
        "",
        "请只基于下面给出的证据和当前回放观测，不要依赖外部漏洞知识，也不要把之前的 hunk 描述摘要当作主要输入。返回严格 JSON，且只包含这些键：",
        "vulnerability_presence_score, final_failure_reason, vulnerability_presence_verdict, judgment_confidence, fix_evidence_strength, exploit_breakage_evidence_strength, key_evidence, judgment_rationale",
        "Score definition:",
        "- vulnerability_presence_score: integer 0-100",
        "- 0 = strong evidence the vulnerability is no longer present/reachable in the target version",
        "- 50 = maximally uncertain / mixed evidence",
        "- 100 = strong evidence the vulnerability likely still exists and the PoC/replay mainly broke because of version/API/runtime changes",
        "Logic-first principle:",
        "- A vulnerability is defined by whether the vulnerable execution path is still reachable in the target version.",
        "- Treat the target version as fixed not only when it adds explicit validation/guards, but also when the evidence directly removes, short-circuits, or replaces the vulnerable path exercised by the trace.",
        "Distinguish unrelated breakage from vulnerability persistence:",
        "- Missing classes, methods, fields, compile_failure, NoClassDefFoundError, ClassNotFoundException, JAXB/classpath/environment failures mean the exploit harness may be broken; by themselves they are NOT evidence that the underlying vulnerable logic still exists.",
        "- VerifyError、LinkageError、ASM/字节码改写失败，更应视为 replay / 兼容性噪声；若没有独立证据显示脆弱逻辑仍可达，优先给 undetermined，而不是让这些失败单独推高 possibly_yes。",
        "- These environment/runtime failures are also not strong fix evidence by themselves; if logic-removal evidence is absent, prefer exploit_invalid_due_to_version_change or undetermined rather than overclaiming a fix.",
        "Trace-anchored fix rule:",
        "- If the baseline trace enters a vulnerable method/path but the target trace ends before entering it, and the target-side diff removes or replaces that exact path, treat this as fix evidence even if the target run later fails for an unrelated dependency/runtime reason.",
        "- If case context says trace_has_effective_difference=false or lists trace_invalid_reasons such as empty traces or InternalLoggerFactory divergence, do not treat trace-only evidence as meaningful proof of vulnerability persistence.",
        "Implicit persistence rule:",
        "- If the vulnerable logic from the baseline plausibly still exists in the target version under a different class or API structure and the evidence does not show removal/short-circuiting of that path, treat the vulnerability as still present.",
        "Weak-evidence rule:",
        "- If there is no concrete code diff and only shallow signals such as pom.diff, empty dependency-tree.diff, or trace-only divergence, bias toward unknown unless the trace and evidence together clearly show target-side path removal.",
        "- Logger-only diffs, anonymous/synthetic inner-class diffs such as $1.diff, and $SwitchMap / enum-reordering diffs are weak evidence and should not carry the same weight as strong vulnerability-semantic hunks such as validators or header hardening logic.",
        "- A field-type change, descriptor-only API change, static-initializer shape change, or tiny bytecode receiver/register shift near the vulnerable class is not enough by itself to conclude the vulnerability still persists; if the logic body is still unclear, bias toward unknown.",
        "Calibration guidance:",
        "- If the evidence explicitly removes the vulnerable path hit by the baseline trace, prefer final_failure_reason = vulnerability_not_present and vulnerability_presence_verdict = no, typically with score <= 25.",
        "- If the PoC fails mainly because of API mismatch, binary/runtime incompatibility, classpath breakage, or harness/environment failure while the vulnerable target-side logic still appears reachable, prefer final_failure_reason = exploit_invalid_due_to_version_change while keeping vulnerability_presence_verdict = possibly_yes.",
        "- Only prefer exploit_invalid_due_to_version_change when the evidence is dominated by compatibility breakage rather than by target-side removal of the vulnerable path.",
        "- If evidence is mixed and neither direct path removal nor direct persistence is visible, bias toward unknown rather than overclaiming a fix.",
        "Allowed values:",
        "- final_failure_reason: vulnerability_not_present | exploit_invalid_due_to_version_change | undetermined",
        "- vulnerability_presence_verdict: no | possibly_yes | unknown",
        "- judgment_confidence: high | medium | low",
        "- fix_evidence_strength: strong | medium | weak | none",
        "- exploit_breakage_evidence_strength: strong | medium | weak | none",
        "- key_evidence: array of short strings",
        "Keep judgment_rationale under 90 words.",
        "",
        "Case context:",
    ]
    lines.extend(_render_case_context_lines(case_payload, scenario))
    lines.extend(["", "Relevant evidence items:"])
    rendered_blocks = _render_diff_blocks(hunk_payloads)
    if rendered_blocks:
        lines.extend(rendered_blocks)
    else:
        lines.append("(no selected hunk/evidence item was available)")
    supplemental_lines = _render_supplemental_case_evidence(case_payload, scenario)
    if supplemental_lines:
        lines.extend(["", "Supplemental case evidence:"])
        lines.extend(supplemental_lines)
    return "\n".join(lines)



def _normalize_judgment_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    final_failure_reason = str(payload.get("final_failure_reason", "undetermined")).strip().lower()
    if final_failure_reason not in {
        "vulnerability_not_present",
        "exploit_invalid_due_to_version_change",
        "undetermined",
    }:
        final_failure_reason = "undetermined"

    vulnerability_presence_verdict = str(payload.get("vulnerability_presence_verdict", "unknown")).strip().lower()
    if vulnerability_presence_verdict not in {"no", "possibly_yes", "unknown"}:
        vulnerability_presence_verdict = "unknown"

    judgment_confidence = str(payload.get("judgment_confidence", "low")).strip().lower()
    if judgment_confidence not in {"high", "medium", "low"}:
        judgment_confidence = "low"

    fix_strength = str(payload.get("fix_evidence_strength", "none")).strip().lower()
    if fix_strength not in {"strong", "medium", "weak", "none"}:
        fix_strength = "none"

    exploit_strength = str(payload.get("exploit_breakage_evidence_strength", "none")).strip().lower()
    if exploit_strength not in {"strong", "medium", "weak", "none"}:
        exploit_strength = "none"

    key_evidence = payload.get("key_evidence")
    if not isinstance(key_evidence, list):
        key_evidence = []
    normalized_evidence = [str(item).strip() for item in key_evidence if str(item).strip()][:8]

    judgment_rationale = str(payload.get("judgment_rationale", "")).strip()
    if not judgment_rationale:
        judgment_rationale = "The model could not extract enough reliable evidence for a stronger final judgment."

    raw_score = payload.get("vulnerability_presence_score")
    evidence_text = "\n".join(normalized_evidence + [judgment_rationale])
    vulnerability_presence_score = _clamp_vulnerability_presence_score(
        raw_score,
        default=_derive_vulnerability_presence_score(
            final_failure_reason=final_failure_reason,
            vulnerability_presence_verdict=vulnerability_presence_verdict,
            judgment_confidence=judgment_confidence,
            fix_strength=fix_strength,
            exploit_strength=exploit_strength,
            evidence_text=evidence_text,
        ),
    )
    if raw_score in (None, ""):
        if vulnerability_presence_score <= 45:
            final_failure_reason = "vulnerability_not_present"
            vulnerability_presence_verdict = "no"
        elif vulnerability_presence_score >= 80:
            final_failure_reason = "exploit_invalid_due_to_version_change"
            vulnerability_presence_verdict = "possibly_yes"
        else:
            final_failure_reason = "undetermined"
            vulnerability_presence_verdict = "unknown"

    return {
        "prompt_version": DIRECT_DIFF_PROMPT_VERSION,
        "vulnerability_presence_score": vulnerability_presence_score,
        "final_failure_reason": final_failure_reason,
        "vulnerability_presence_verdict": vulnerability_presence_verdict,
        "judgment_confidence": judgment_confidence,
        "fix_evidence_strength": fix_strength,
        "exploit_breakage_evidence_strength": exploit_strength,
        "key_evidence": normalized_evidence,
        "judgment_rationale": judgment_rationale,
    }



def _normalize_hunk_judgment_payload(payload: Dict[str, Any], hunk_path: str) -> Dict[str, Any]:
    judgment = str(payload.get("judgment", "neutral")).strip().lower()
    if judgment not in {"fix_evidence", "exploit_breakage_evidence", "neutral"}:
        judgment = "neutral"

    confidence = str(payload.get("confidence", "low")).strip().lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"

    key_evidence = payload.get("key_evidence")
    if not isinstance(key_evidence, list):
        key_evidence = []
    normalized_evidence = [str(item).strip() for item in key_evidence if str(item).strip()][:MAX_HUNK_KEY_EVIDENCE]

    reasoning = str(payload.get("reasoning", "")).strip()
    if not reasoning:
        reasoning = "The model could not extract enough concrete evidence from this diff hunk."

    return {
        "prompt_version": HUNK_JUDGMENT_PROMPT_VERSION,
        "hunk_path": _normalize_diff_path(payload.get("hunk_path") or hunk_path),
        "judgment": judgment,
        "confidence": confidence,
        "key_evidence": normalized_evidence,
        "reasoning": reasoning,
    }



def _model_mismatch_warning_regex() -> str:
    return (
        r"Resolved model mismatch: .* != .*\\. "
        r"Model mapping in autogen_ext\\.models\\.openai may be incorrect\\. "
        r"Set the model to .* to enhance token/cost estimation and suppress this warning\\."
    )


async def _create_model_response(model_client, **kwargs):
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=_model_mismatch_warning_regex(),
            category=UserWarning,
        )
        return await model_client.create(**kwargs)


async def run_llm_hunk_selection(
    analysis_root: pathlib.Path,
    scenario: Dict[str, object],
    output_path: pathlib.Path,
    config: LLMAnalysisConfig,
) -> None:
    try:
        from autogen_core.models import (
            AssistantMessage,
            FunctionExecutionResult,
            FunctionExecutionResultMessage,
            SystemMessage,
            UserMessage,
        )
        from autogen_core.tools import FunctionTool
        from autogen_ext.models.openai import OpenAIChatCompletionClient
        from autogen_core.models import ModelFamily
    except ImportError as error:
        raise RuntimeError(
            "AutoGen imports failed. Ensure the active environment provides autogen_core/autogen_ext "
            "compatible with llm_hunk_selector.py. Root cause: {}: {}".format(type(error).__name__, error)
        ) from error

    def keyword_search(keywords: str, limit: int = MAX_KEYWORD_RESULTS, path_glob: str = "**/*") -> str:
        return search_workspace(analysis_root, keywords=keywords, limit=limit, path_glob=path_glob)

    def read_file(path: str, start_line: int = 1, end_line: int = DEFAULT_READ_WINDOW) -> str:
        return read_workspace_file(analysis_root, path=path, start_line=start_line, end_line=end_line)

    keyword_tool = FunctionTool(
        keyword_search,
        description="Keyword search over the generated analysis workspace. Returns matching file:line hits.",
        name="keyword_search",
    )
    read_file_tool = FunctionTool(
        read_file,
        description="Read a file from the generated analysis workspace with line numbers.",
        name="read_file",
    )
    def load_diff_context_tool_impl(
        diff_path: str,
        hunk_hint: str = "",
        diff_start_line: Optional[int] = None,
        diff_end_line: Optional[int] = None,
        context_lines: int = 8,
    ) -> str:
        return load_diff_context(
            analysis_root,
            diff_path=diff_path,
            hunk_hint=hunk_hint,
            diff_start_line=diff_start_line,
            diff_end_line=diff_end_line,
            context_lines=context_lines,
        )

    def search_code_context_tool_impl(query: str, limit: int = MAX_CODE_CONTEXT_RESULTS, scope: str = "all") -> str:
        return search_code_context(
            analysis_root,
            query=query,
            limit=limit,
            scope=scope,
        )

    load_diff_context_tool = FunctionTool(
        load_diff_context_tool_impl,
        description=(
            "Resolve a version-diff hunk to the matching baseline/target raw files and return a context preview "
            "around the best anchor lines. Use this after identifying a relevant diff."
        ),
        name="load_diff_context",
    )
    search_code_context_tool = FunctionTool(
        search_code_context_tool_impl,
        description=(
            "Search version-diff/api-raw and version-diff/raw for wider code context by class, method, or symbol name. "
            "Use scope=api, raw, or all."
        ),
        name="search_code_context",
    )

    model_client = OpenAIChatCompletionClient(
        model=config.model,
        base_url=config.base_url,
        api_key=config.api_key,
        timeout=config.request_timeout_seconds,
        max_retries=1,
        model_info={
            "vision": False,
            "function_calling": True,
            "json_output": True,
            "family": ModelFamily.ANY,
            "structured_output": True,
            "temperature": 0.5,
        },
    )

    effective_max_rounds = _effective_tool_round_budget(scenario, config.max_rounds)
    messages = [
        SystemMessage(
            content=(
                "Use tools sparingly to investigate the most relevant diff hunks before answering. "
                "Keep tool calls concise, but do not prematurely collapse trace_diff cases to a single hunk when multiple changed classes remain plausible. "
                "This case has a hard tool budget of {} round(s); if the evidence is already clear, stop earlier."
            ).format(effective_max_rounds)
        ),
        UserMessage(content=build_analysis_prompt(scenario), source="user"),
    ]
    transcript_lines: List[str] = [
        "Configured max rounds: {}".format(config.max_rounds),
        "Effective max rounds for this case: {}".format(effective_max_rounds),
        "",
    ]
    final_response = None

    try:
        for round_index in range(1, effective_max_rounds + 1):
            print(
                "[LLM] requesting round {}/{} for {}".format(round_index, effective_max_rounds, analysis_root),
                flush=True,
            )
            response = await _create_model_response(
                model_client,
                messages=messages,
                tools=[keyword_tool, read_file_tool, load_diff_context_tool, search_code_context_tool],
            )
            log_llm_usage(
                method="hunk_selection_round",
                case_id=str(scenario.get("case_id") or ""),
                model=config.model,
                usage=getattr(response, "usage", None),
                extra={"round": round_index},
            )
            if isinstance(response.content, list):
                transcript_lines.append("Round {} tool calls:".format(round_index))
                messages.append(AssistantMessage(content=response.content, source="assistant"))

                tool_results = []
                for call in response.content:
                    raw_arguments = call.arguments
                    if isinstance(raw_arguments, str):
                        arguments = json.loads(raw_arguments) if raw_arguments else {}
                    else:
                        arguments = raw_arguments

                    try:
                        if call.name == "keyword_search":
                            result_text = search_workspace(analysis_root, **arguments)
                        elif call.name == "read_file":
                            result_text = read_workspace_file(analysis_root, **arguments)
                        elif call.name == "load_diff_context":
                            result_text = load_diff_context(analysis_root, **arguments)
                        elif call.name == "search_code_context":
                            result_text = search_code_context(analysis_root, **arguments)
                        else:
                            result_text = "Unknown tool: {}".format(call.name)
                        is_error = False
                    except Exception as tool_error:
                        result_text = "{}: {}".format(type(tool_error).__name__, tool_error)
                        is_error = True

                    transcript_lines.append(
                        "- {}({})".format(call.name, json.dumps(arguments, ensure_ascii=False, sort_keys=True))
                    )
                    transcript_lines.append(result_text)
                    transcript_lines.append("")
                    tool_results.append(
                        FunctionExecutionResult(
                            content=result_text,
                            call_id=call.id,
                            is_error=is_error,
                            name=call.name,
                        )
                    )

                messages.append(FunctionExecutionResultMessage(content=tool_results))
                continue

            final_response = response.content
            transcript_lines.append("Final response:")
            transcript_lines.append(str(final_response))
            break

        if final_response is None:
            transcript_lines.append(
                "Reached the tool round limit ({}). Requesting a final answer without tools.".format(effective_max_rounds)
            )
            messages.append(
                UserMessage(
                    content=(
                        "You have already collected enough evidence. Do not call any tools. "
                        "Now return the final markdown answer immediately with exactly these sections: "
                        "Diagnosis, Selected Hunks, Supporting Evidence, Open Questions."
                    ),
                    source="user",
                )
            )
            print("[LLM] requesting forced final answer for {}".format(analysis_root), flush=True)
            forced_response = await _create_model_response(model_client, messages=messages)
            log_llm_usage(
                method="hunk_selection_forced_final",
                case_id=str(scenario.get("case_id") or ""),
                model=config.model,
                usage=getattr(forced_response, "usage", None),
                extra=None,
            )
            final_response = forced_response.content
            transcript_lines.append("Final response:")
            transcript_lines.append(str(final_response))

        final_response_text = str(final_response or "")
        if final_response_text and _final_response_needs_concrete_diff_repair(analysis_root, final_response_text):
            candidate_hunks = _find_repair_candidate_hunks(analysis_root, scenario, final_response_text)
            transcript_lines.append("")
            transcript_lines.append(
                "Evidence repair triggered: no valid concrete diff or fallback evidence path was found in Selected Hunks."
            )
            if candidate_hunks:
                transcript_lines.append("Candidate evidence paths for repair:")
                for item in candidate_hunks:
                    transcript_lines.append("- {}".format(item["path"]))
                repair_prompt = _build_concrete_diff_repair_prompt(scenario, final_response_text, candidate_hunks)
                repair_messages = [
                    SystemMessage(content="Rewrite the final markdown answer only. Do not call tools."),
                    UserMessage(content=repair_prompt, source="user"),
                ]
                print("[LLM] requesting evidence repair for {}".format(analysis_root), flush=True)
                repaired_response = await _create_model_response(model_client, messages=repair_messages)
                log_llm_usage(
                    method="hunk_selection_repair",
                    case_id=str(scenario.get("case_id") or ""),
                    model=config.model,
                    usage=getattr(repaired_response, "usage", None),
                    extra=None,
                )
                repaired_text = str(repaired_response.content)
                transcript_lines.append("")
                transcript_lines.append("Evidence repair response:")
                transcript_lines.append(repaired_text)
                if _final_response_needs_concrete_diff_repair(analysis_root, repaired_text):
                    repaired_text = _build_deterministic_repaired_markdown(final_response_text, candidate_hunks)
                    transcript_lines.append("")
                    transcript_lines.append("Evidence deterministic fallback:")
                    transcript_lines.append(repaired_text)
                final_response = repaired_text
                transcript_lines.append("")
                transcript_lines.append("Final response:")
                transcript_lines.append(str(final_response))
            else:
                transcript_lines.append("No usable evidence candidates were found for repair.")
    finally:
        close_method = getattr(model_client, "close", None)
        if callable(close_method):
            maybe_awaitable = close_method()
            if asyncio.iscoroutine(maybe_awaitable):
                await maybe_awaitable

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(transcript_lines) + "\n", encoding="utf-8")


def run_llm_hunk_selection_sync(
    analysis_root: pathlib.Path,
    scenario: Dict[str, object],
    output_path: pathlib.Path,
    config: LLMAnalysisConfig,
) -> None:
    asyncio.run(run_llm_hunk_selection(analysis_root, scenario, output_path, config))


async def run_llm_hunk_judgment(
    case_payload: Dict[str, object],
    scenario: Dict[str, object],
    hunk_payload: Dict[str, object],
    config: LLMAnalysisConfig,
) -> Dict[str, Any]:
    try:
        from autogen_core.models import SystemMessage, UserMessage
        from autogen_ext.models.openai import OpenAIChatCompletionClient
        from autogen_core.models import ModelFamily
    except ImportError as error:
        raise RuntimeError(
            "AutoGen imports failed. Ensure the active environment provides autogen_core/autogen_ext "
            "compatible with llm_hunk_selector.py. Root cause: {}: {}".format(type(error).__name__, error)
        ) from error

    model_client = OpenAIChatCompletionClient(
        model=config.model,
        base_url=config.base_url,
        api_key=config.api_key,
        timeout=config.request_timeout_seconds,
        max_retries=1,
        model_info={
            "vision": False,
            "function_calling": False,
            "json_output": True,
            "family": ModelFamily.ANY,
            "structured_output": True,
            "temperature": 0.2,
        },
    )

    messages = [
        SystemMessage(content="Return only the requested JSON judgment for this diff hunk, with concise evidence strings."),
        UserMessage(
            content=build_hunk_judgment_prompt(case_payload, scenario, hunk_payload),
            source="user",
        ),
    ]

    try:
        print(
            "[LLM] requesting per-hunk judgment for {} :: {}".format(
                case_payload.get("case_id", "unknown-case"),
                _normalize_diff_path(hunk_payload.get("path")) or "unknown-hunk",
            ),
            flush=True,
        )
        response = await _create_model_response(model_client, messages=messages)
        log_llm_usage(
            method="hunk_judgment",
            case_id=str(case_payload.get("case_id") or ""),
            model=config.model,
            usage=getattr(response, "usage", None),
            extra={"hunk_path": _normalize_diff_path(hunk_payload.get("path") or "")},
        )
        raw_text = str(response.content)
        parsed = _normalize_hunk_judgment_payload(
            _extract_json_object(raw_text),
            hunk_path=str(hunk_payload.get("path") or ""),
        )
    finally:
        close_method = getattr(model_client, "close", None)
        if callable(close_method):
            maybe_awaitable = close_method()
            if asyncio.iscoroutine(maybe_awaitable):
                await maybe_awaitable

    return parsed



def run_llm_hunk_judgment_sync(
    case_payload: Dict[str, object],
    scenario: Dict[str, object],
    hunk_payload: Dict[str, object],
    config: LLMAnalysisConfig,
) -> Dict[str, Any]:
    return asyncio.run(
        run_llm_hunk_judgment(
            case_payload=case_payload,
            scenario=scenario,
            hunk_payload=hunk_payload,
            config=config,
        )
    )



async def run_llm_vulnerability_judgment(
    case_payload: Dict[str, object],
    scenario: Dict[str, object],
    hunk_payloads: List[Dict[str, object]],
    output_path: pathlib.Path,
    config: LLMAnalysisConfig,
) -> Dict[str, Any]:
    try:
        from autogen_core.models import SystemMessage, UserMessage
        from autogen_ext.models.openai import OpenAIChatCompletionClient
        from autogen_core.models import ModelFamily
    except ImportError as error:
        raise RuntimeError(
            "AutoGen imports failed. Ensure the active environment provides autogen_core/autogen_ext "
            "compatible with llm_hunk_selector.py. Root cause: {}: {}".format(type(error).__name__, error)
        ) from error

    model_client = OpenAIChatCompletionClient(
        model=config.model,
        base_url=config.base_url,
        api_key=config.api_key,
        timeout=config.request_timeout_seconds,
        max_retries=1,
        model_info={
            "vision": False,
            "function_calling": False,
            "json_output": True,
            "family": ModelFamily.ANY,
            "structured_output": True,
            "temperature": 0.2,
        },
    )

    messages = [
        SystemMessage(
            content=(
                "Return only the requested final JSON judgment, with concise evidence strings. "
                "Apply a logic-first interpretation: explicit validation is one kind of fix evidence, but direct removal or short-circuiting of the vulnerable path exercised by the trace also counts as fix evidence. "
                "API removal or compile failure alone indicates exploit breakage, but target-side deletion of the vulnerable recursive/conversion logic indicates vulnerability_not_present."
            )
        ),
        UserMessage(
            content=build_vulnerability_judgment_prompt(case_payload, scenario, hunk_payloads),
            source="user",
        ),
    ]

    try:
        print("[LLM] requesting final vulnerability judgment for {}".format(case_payload.get("case_id", "unknown-case")), flush=True)
        response = await _create_model_response(model_client, messages=messages)
        log_llm_usage(
            method="vulnerability_judgment",
            case_id=str(case_payload.get("case_id") or ""),
            model=config.model,
            usage=getattr(response, "usage", None),
            extra={"judged_hunk_count": len(hunk_payloads[:MAX_JUDGMENT_HUNKS])},
        )
        raw_text = str(response.content)
        parsed = _normalize_judgment_payload(_extract_json_object(raw_text))
        parsed["judged_hunk_count"] = len(hunk_payloads[:MAX_JUDGMENT_HUNKS])
        parsed["judged_hunk_paths"] = [
            _normalize_diff_path(item.get("path"))
            for item in hunk_payloads[:MAX_JUDGMENT_HUNKS]
            if _normalize_diff_path(item.get("path"))
        ]
    finally:
        close_method = getattr(model_client, "close", None)
        if callable(close_method):
            maybe_awaitable = close_method()
            if asyncio.iscoroutine(maybe_awaitable):
                await maybe_awaitable

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(parsed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return parsed



def run_llm_vulnerability_judgment_sync(
    case_payload: Dict[str, object],
    scenario: Dict[str, object],
    hunk_payloads: List[Dict[str, object]],
    output_path: pathlib.Path,
    config: LLMAnalysisConfig,
) -> Dict[str, Any]:
    return asyncio.run(
        run_llm_vulnerability_judgment(
            case_payload=case_payload,
            scenario=scenario,
            hunk_payloads=hunk_payloads,
            output_path=output_path,
            config=config,
        )
    )
