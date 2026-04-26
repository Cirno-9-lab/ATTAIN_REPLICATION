#!/usr/bin/env python3

import argparse
import datetime as datetime_module
import json
import pathlib
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as element_tree
from typing import Dict, Iterable, List, Optional, Tuple

from extract_api_changes import generate_api_change_summary
from materialize_case_workspace import infer_artifact_from_pom, materialize_case_workspace
from target_paths import default_demo_target_root


ERROR_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$.]+")
CAUSE_ARTIFACT_RE = re.compile(r"(?:at|artifact)\s+([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\s]+)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one compile-false CVE case through the difftrace demo pipeline.")
    parser.add_argument("--cve-list", required=True, help="Path to dataset/list/cve_list.json")
    parser.add_argument("--cve-id", required=True, help="CVE id, for example CVE-2013-2055")
    parser.add_argument("--pair-index", required=True, type=int, help="Index in version_pair[]")
    parser.add_argument(
        "--exploit-root",
        action="append",
        default=[],
        help="Exploit 根目录，可重复传入。脚本会依次尝试 <root>/<CVE>/demo 与 <root>/<CVE>。默认自动搜索 Vision 和 Origin。",
    )
    parser.add_argument("--output-root", help="Output root. Default: <demo>/target/batch-results")
    parser.add_argument("--version-property", default="target.library.version", help="Maven version property used in generated workspaces.")
    parser.add_argument("--artifact", help="Optional explicit target artifact in groupId:artifactId form.")
    parser.add_argument("--disclosed-version-file", help="Optional path to disclosed-version.txt for artifact hints.")
    parser.add_argument("--test-file", help="Optional test file path relative to exploit demo.")
    parser.add_argument("--trace-packages", help="Optional trace package prefixes.")
    parser.add_argument("--java-version", help="Optional Java source/target override.")
    parser.add_argument("--maven-bin", default="mvn", help="Maven binary. Default: mvn")
    parser.add_argument("--allow-compile-true", action="store_true", help="Allow running pairs whose compile field is true.")
    parser.add_argument("--strict-tests", action="store_true", help="Preserve original JUnit failure semantics instead of observe-only trace capture.")
    parser.add_argument("--force", action="store_true", help="Recreate the workspace and rerun analysis.")
    return parser.parse_args()


def demo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def default_exploit_roots() -> List[pathlib.Path]:
    code_root = demo_root().parent.parent
    return [
        code_root / "PoCEmpirical" / "reproduce" / "Exploits" / "Vision",
        code_root / "PoCEmpirical" / "reproduce" / "Exploits" / "Origin",
        code_root / "PoCEmpirical" / "reproduce" / "exploits_cpy",
    ]


def resolve_exploit_roots(raw_roots: Iterable[str]) -> List[pathlib.Path]:
    explicit_roots = [pathlib.Path(value).expanduser().resolve() for value in raw_roots if value]
    defaults = default_exploit_roots()
    ordered: List[pathlib.Path] = []
    for root in explicit_roots + defaults:
        if root not in ordered:
            ordered.append(root)
    return ordered


def find_exploit_demo(exploit_roots: Iterable[pathlib.Path], cve_id: str) -> pathlib.Path:
    tried: List[pathlib.Path] = []
    existing_without_pom: List[pathlib.Path] = []
    for root in exploit_roots:
        for candidate in (root / cve_id / "demo", root / cve_id):
            tried.append(candidate)
            if not (candidate.exists() and candidate.is_dir()):
                continue
            pom_path = candidate / "pom.xml"
            if pom_path.exists():
                return candidate
            nested_poms = sorted(
                path
                for path in candidate.rglob("pom.xml")
                if "target" not in path.parts
            )
            if len(nested_poms) == 1:
                return nested_poms[0].parent
            existing_without_pom.append(candidate)
    joined = "\n".join(str(path) for path in tried)
    if existing_without_pom:
        existing_joined = "\n".join(str(path) for path in existing_without_pom)
        raise SystemExit(f"Exploit demo exists but no usable pom.xml was found for {cve_id}. Tried:\n{joined}\nExisting directories without pom:\n{existing_joined}")
    raise SystemExit(f"Exploit demo not found for {cve_id}. Tried:\n{joined}")


def default_output_root() -> pathlib.Path:
    return default_demo_target_root() / "batch-results"


def default_disclosed_version_file() -> pathlib.Path:
    return demo_root().parent.parent / "PoCEmpirical" / "reproduce" / "disclosed-version.txt"


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def read_json(path: pathlib.Path) -> object:
    return json.loads(read_text(path))


def write_json(path: pathlib.Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def slugify(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def make_case_id(cve_id: str, pair: Dict[str, object], pair_index: int) -> str:
    left = slugify(str(pair.get("appears") or pair.get("BASE_TAG") or f"pair{pair_index}"))
    right = slugify(str(pair.get("not appears") or pair.get("HEAD_TAG") or f"pair{pair_index}"))
    return f"{cve_id}__{pair_index:02d}__{left}__{right}"


def load_case_entry(cve_list_path: pathlib.Path, cve_id: str, pair_index: int) -> Tuple[Dict[str, object], Dict[str, object]]:
    dataset = read_json(cve_list_path)
    if cve_id not in dataset:
        raise SystemExit(f"CVE not found in cve_list.json: {cve_id}")
    cve_entry = dataset[cve_id]
    pairs = cve_entry.get("version_pair", [])
    if pair_index < 0 or pair_index >= len(pairs):
        raise SystemExit(f"pair-index {pair_index} is out of range for {cve_id}")
    return cve_entry, pairs[pair_index]


def parse_artifact_from_cause(cause: str) -> Optional[str]:
    match = CAUSE_ARTIFACT_RE.search(cause or "")
    if not match:
        return None
    return f"{match.group(1)}:{match.group(2)}"


def unique_preserve_order(values: List[str]) -> List[str]:
    ordered: List[str] = []
    for value in values:
        if value not in ordered:
            ordered.append(value)
    return ordered


def infer_artifact_from_disclosed_version_file(
    disclosed_version_file: pathlib.Path,
    cve_id: str,
    baseline_version: str,
    target_version: str,
) -> Optional[str]:
    if not disclosed_version_file.exists():
        return None

    by_cve: List[str] = []
    by_version: List[str] = []
    for raw_line in read_text(disclosed_version_file).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("\t")]
        if len(parts) < 2:
            continue
        artifact = parts[0]
        disclosed_cve = parts[1]
        disclosed_version = parts[2] if len(parts) > 2 else ""
        if disclosed_cve != cve_id or not artifact:
            continue
        by_cve.append(artifact)
        if disclosed_version in {baseline_version, target_version}:
            by_version.append(artifact)

    unique_by_version = unique_preserve_order(by_version)
    if len(unique_by_version) == 1:
        return unique_by_version[0]

    unique_by_cve = unique_preserve_order(by_cve)
    if len(unique_by_cve) == 1:
        return unique_by_cve[0]
    return None


def child_text(parent: element_tree.Element, namespace: str, tag: str) -> str:
    node = parent.find(f"{{{namespace}}}{tag}" if namespace else tag)
    return (node.text or "").strip() if node is not None and node.text else ""


def infer_artifact_from_repo_hint(pom_path: pathlib.Path, repo_name: str) -> Optional[str]:
    repo_name = (repo_name or "").strip().lower()
    if not repo_name or not pom_path.exists():
        return None

    root = element_tree.fromstring(read_text(pom_path))
    namespace = root.tag.split("}", 1)[0][1:] if root.tag.startswith("{") else ""
    dependencies = root.find(f"{{{namespace}}}dependencies" if namespace else "dependencies")
    if dependencies is None:
        return None

    candidates: List[str] = []
    for dependency in dependencies.findall(f"{{{namespace}}}dependency" if namespace else "dependency"):
        group_id = child_text(dependency, namespace, "groupId")
        artifact_id = child_text(dependency, namespace, "artifactId")
        scope = child_text(dependency, namespace, "scope")
        if not group_id or not artifact_id or scope in {"test", "provided"}:
            continue
        candidates.append(f"{group_id}:{artifact_id}")

    exact_matches = [candidate for candidate in candidates if candidate.split(":", 1)[1].lower() == repo_name]
    if len(exact_matches) == 1:
        return exact_matches[0]

    partial_matches = [
        candidate
        for candidate in candidates
        if repo_name in candidate.split(":", 1)[1].lower() or candidate.split(":", 1)[1].lower() in repo_name
    ]
    partial_matches = unique_preserve_order(partial_matches)
    if len(partial_matches) == 1:
        return partial_matches[0]
    return None


def run_subprocess(command: List[str], cwd: Optional[pathlib.Path] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def load_optional_json(path: pathlib.Path) -> Optional[object]:
    return read_json(path) if path.exists() else None


def collect_error_tokens(text: str) -> List[str]:
    ordered: List[str] = []
    for token in ERROR_TOKEN_RE.findall(text or ""):
        if token not in ordered:
            ordered.append(token)
    return ordered[:40]


def select_related_api_changes(api_summary: Dict[str, object], text: str) -> List[Dict[str, str]]:
    tokens = set(collect_error_tokens(text))
    related: List[Dict[str, str]] = []

    def contains_token(candidate: str) -> bool:
        simple = candidate.split(".")[-1].split("$")[-1]
        return candidate in tokens or simple in tokens or simple in text

    for class_name in api_summary.get("removed_classes", []):
        if contains_token(class_name):
            related.append({
                "class_name": class_name,
                "change_type": "removed_class",
                "symbol": class_name,
            })

    for class_name, changes in api_summary.get("changed_classes", {}).items():
        if class_name not in text and class_name.split(".")[-1] not in text:
            continue
        for change_type in (
            "removed_constructors",
            "removed_methods",
            "removed_fields",
            "added_constructors",
            "added_methods",
            "added_fields",
        ):
            for symbol in changes.get(change_type, []):
                related.append({
                    "class_name": class_name,
                    "change_type": change_type,
                    "symbol": symbol,
                })
    return related[:30]


def infer_failure_subtype(text: str, api_summary: Dict[str, object]) -> str:
    """Infer a more specific failure subtype from logs + API diff.

    设计要点：优先识别更“硬”的结构性错误（缺类/缺方法/二进制不兼容），
    然后再回落到泛化的 test_failure / unknown_failure，避免像
    "NoClassDefFoundError + there are test failures" 这类情况被误归一化成纯 test_failure。
    """
    lowered = (text or "").lower()

    # 1) 依赖下载 / 解析问题
    if "failed to collect dependencies" in lowered or "could not transfer artifact" in lowered or "could not resolve dependencies" in lowered:
        return "dependency_resolution_failure"

    # 2) 编译器 / JDK 工具链不兼容
    if "invalid target release" in lowered or "source option" in lowered or "target option" in lowered or "release version" in lowered:
        return "toolchain_incompatibility"

    # 3) trace agent / ASM 相关问题
    if "agent library failed to init" in lowered or "error opening zip file or jar manifest missing" in lowered:
        return "trace_agent_initialization_failure"
    if "arrayindexoutofboundsexception" in lowered and any(
        marker in lowered for marker in ("org.objectweb.asm", " asm", "classreader", "methodwriter", "frame", "generator")
    ):
        return "asm_instrumentation_failure"

    # 4) 明确的签名 / 链接层问题（优先级高于 test_failure）
    if "nosuchmethoderror" in lowered or ("cannot find symbol" in lowered and "method" in lowered):
        return "missing_method"
    if "noclassdeffounderror" in lowered or "classnotfoundexception" in lowered:
        return "missing_class"
    if "cannot find symbol" in lowered and "class" in lowered:
        return "missing_class"
    if "package " in lowered and " does not exist" in lowered:
        return "missing_class"
    if "nosuchfielderror" in lowered or "verifyerror" in lowered or "incompatibleclasschangeerror" in lowered or "bootstrapmethoderror" in lowered or "linkageerror" in lowered:
        return "binary_incompatibility"

    # 5) 其它结构性变化信号
    if "no suitable constructor found" in lowered:
        return "constructor_signature_change"

    # 6) 普通测试失败（在没有更具体结构性线索时才退回到这里）
    if "test timed out" in lowered or "there are test failures" in lowered or "tests in error:" in lowered or "tests run:" in lowered:
        return "test_failure"

    # 7) 用 API diff 做一个兜底归类
    if api_summary.get("removed_classes"):
        return "api_breaking_change"
    if api_summary.get("breaking_change_candidates"):
        return "signature_change"
    return "unknown_failure"


def build_result_payload(
    case_id: str,
    cve_id: str,
    cve_entry: Dict[str, object],
    pair_index: int,
    pair: Dict[str, object],
    materialized: Dict[str, object],
    analysis_dir: pathlib.Path,
    driver_command: List[str],
    driver_exit_code: int,
    driver_output_path: pathlib.Path,
) -> Dict[str, object]:
    trace_summary = load_optional_json(analysis_dir / "trace-diff-summary.json") or {}
    analysis_metadata = load_optional_json(analysis_dir / "analysis-metadata.json") or {}
    execution_observations = load_optional_json(analysis_dir / "execution-observations.json") or {}
    api_summary = load_optional_json(analysis_dir / "version-diff" / "api-change-summary.json") or {}
    llm_scenario = load_optional_json(analysis_dir / "llm-scenario.json") or {}
    failure_excerpt_path = analysis_dir / "target-failure-excerpt.txt"
    failure_excerpt = read_text(failure_excerpt_path) if failure_excerpt_path.exists() else ""
    target_prepare_generator_excerpt_path = analysis_dir / "target-prepare-generator-excerpt.txt"
    target_prepare_generator_excerpt = (
        read_text(target_prepare_generator_excerpt_path) if target_prepare_generator_excerpt_path.exists() else ""
    )
    target_prepare_classpath_excerpt_path = analysis_dir / "target-prepare-classpath-excerpt.txt"
    target_prepare_classpath_excerpt = (
        read_text(target_prepare_classpath_excerpt_path) if target_prepare_classpath_excerpt_path.exists() else ""
    )
    dataset_cause = str(pair.get("cause") or "")
    combined_error_text = "\n".join(
        part
        for part in [
            dataset_cause,
            failure_excerpt,
            target_prepare_classpath_excerpt,
            target_prepare_generator_excerpt,
        ]
        if part
    )
    target_observation = ((execution_observations.get("target") or {}).get("observation"))
    trace_has_effective_difference = bool(
        trace_summary.get("has_effective_difference", trace_summary.get("has_difference"))
    )
    trace_invalid_reasons = trace_summary.get("trace_invalid_reasons") or []

    if driver_exit_code != 0:
        status = "runner_error"
        failure_kind = "runner_error"
        failure_subtype = "runner_error"
    elif failure_excerpt and target_observation == "compile_failure":
        status = "compile_failure"
        failure_kind = llm_scenario.get("scenario_type") or "compile_failure"
        failure_subtype = infer_failure_subtype(combined_error_text, api_summary)
    elif failure_excerpt:
        status = "execution_failure"
        failure_kind = target_observation or llm_scenario.get("scenario_type") or "execution_failure"
        failure_subtype = infer_failure_subtype(combined_error_text, api_summary)
    elif trace_has_effective_difference:
        status = "trace_diff"
        failure_kind = None
        failure_subtype = "trace_difference"
    else:
        status = "no_diff"
        failure_kind = None
        failure_subtype = "invalid_trace_difference" if trace_summary.get("has_difference") else None

    return {
        "case_id": case_id,
        "cve_id": cve_id,
        "pair_index": pair_index,
        "owner": cve_entry.get("OWNER"),
        "repo": cve_entry.get("REPO"),
        "description": cve_entry.get("description"),
        "artifact": materialized.get("artifact") or analysis_metadata.get("artifact"),
        "baseline_version": materialized.get("baseline_version"),
        "target_version": materialized.get("target_version"),
        "observe_only_tests": materialized.get("observe_only_tests"),
        "compat_replay_target": True,
        "appears": pair.get("appears"),
        "not_appears": pair.get("not appears"),
        "base_tag": pair.get("BASE_TAG"),
        "head_tag": pair.get("HEAD_TAG"),
        "compare_url": pair.get("COMPARE_URL"),
        "compile": pair.get("compile"),
        "dataset_cause": dataset_cause,
        "status": status,
        "failure_kind": failure_kind,
        "failure_subtype": failure_subtype,
        "baseline_execution_observation": ((execution_observations.get("baseline") or {}).get("observation")),
        "target_execution_observation": ((execution_observations.get("target") or {}).get("observation")),
        "trace_has_difference": trace_summary.get("has_difference"),
        "trace_has_effective_difference": trace_has_effective_difference,
        "trace_evidence_valid": trace_summary.get("trace_evidence_valid"),
        "trace_invalid_reasons": trace_invalid_reasons,
        "first_divergence_is_noise": trace_summary.get("first_divergence_is_noise", False),
        "related_api_changes": select_related_api_changes(api_summary, combined_error_text),
        "analysis_dir": str(analysis_dir),
        "workspace_dir": materialized.get("workspace_dir"),
        "test_file": materialized.get("test_file"),
        "driver_command": driver_command,
        "driver_exit_code": driver_exit_code,
        "driver_output_path": str(driver_output_path),
        "trace_summary_path": str((analysis_dir / 'trace-diff-summary.json')),
        "api_change_summary_path": str((analysis_dir / 'version-diff' / 'api-change-summary.json')),
        "failure_excerpt_path": str(failure_excerpt_path) if failure_excerpt else None,
        "completed_at": datetime_module.datetime.now().isoformat(timespec="seconds"),
    }


def make_test_run_slug(workspace_dir: pathlib.Path, test_file: pathlib.Path) -> str:
    try:
        relative = test_file.resolve().relative_to(workspace_dir.resolve())
        relative_text = str(relative)
    except ValueError:
        relative_text = test_file.name
    return slugify(relative_text)


def status_priority(status: Optional[str]) -> int:
    priorities = {
        "trace_diff": 5,
        "compile_failure": 4,
        "execution_failure": 3,
        "runner_error": 2,
        "timeout": 1,
        "no_diff": 0,
    }
    return priorities.get(str(status or ""), -1)


def aggregate_case_results(result_payloads: List[Dict[str, object]], analysis_root: pathlib.Path, materialized: Dict[str, object]) -> Dict[str, object]:
    if not result_payloads:
        raise SystemExit("No test results were produced for this case.")

    primary_result = max(enumerate(result_payloads), key=lambda item: (status_priority(item[1].get("status")), -item[0]))[1]
    status_counts: Dict[str, int] = {}
    for payload in result_payloads:
        status = str(payload.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    aggregated = dict(primary_result)
    aggregated["analysis_root"] = str(analysis_root)
    aggregated["multi_test_mode"] = len(result_payloads) > 1
    aggregated["test_result_count"] = len(result_payloads)
    aggregated["test_files"] = materialized.get("test_files") or [payload.get("test_file") for payload in result_payloads]
    aggregated["selected_test_file"] = primary_result.get("test_file")
    aggregated["selected_analysis_dir"] = primary_result.get("analysis_dir")
    aggregated["status_counts"] = status_counts
    aggregated["test_results"] = result_payloads
    return aggregated


def main() -> int:
    args = parse_args()
    cve_list_path = pathlib.Path(args.cve_list).expanduser().resolve()
    cve_entry, pair = load_case_entry(cve_list_path, args.cve_id, args.pair_index)
    if pair.get("compile") is True and not args.allow_compile_true:
        raise SystemExit("This script is intended for compile:false pairs. Pass --allow-compile-true to override.")

    case_id = make_case_id(args.cve_id, pair, args.pair_index)
    exploit_roots = resolve_exploit_roots(args.exploit_root)
    exploit_demo = find_exploit_demo(exploit_roots, args.cve_id)

    output_root = pathlib.Path(args.output_root).expanduser().resolve() if args.output_root else default_output_root()
    case_root = output_root / "cases" / case_id
    workspace_root = case_root / "workspace"
    analysis_root = case_root / "analysis"
    result_path = case_root / "case-result.json"
    materialized_json_path = case_root / "materialized-case.json"
    input_snapshot_path = case_root / "case-input.json"

    if result_path.exists() and not args.force:
        print(f"Case already analyzed: {result_path}")
        return 0

    case_root.mkdir(parents=True, exist_ok=True)
    if analysis_root.exists():
        shutil.rmtree(analysis_root)
    for stale_log in case_root.glob("run-version-analysis*.log"):
        stale_log.unlink()
    if result_path.exists():
        result_path.unlink()

    write_json(
        input_snapshot_path,
        {
            "cve_id": args.cve_id,
            "pair_index": args.pair_index,
            "pair": pair,
        },
    )

    baseline_version = str(pair.get("appears") or "")
    target_version = str(pair.get("not appears") or "")
    if not baseline_version or not target_version:
        raise SystemExit("Both appears and not appears must be present in the selected version_pair entry.")

    disclosed_version_file = (
        pathlib.Path(args.disclosed_version_file).expanduser().resolve()
        if args.disclosed_version_file
        else default_disclosed_version_file()
    )
    artifact_from_pom = None
    pom_path = exploit_demo / "pom.xml"
    if pom_path.exists():
        inferred_coordinate = infer_artifact_from_pom(
            pom_path,
            baseline_version=baseline_version,
            target_version=target_version,
        )
        artifact_from_pom = inferred_coordinate.gav() if inferred_coordinate else None

    artifact = (
        args.artifact
        or artifact_from_pom
        or infer_artifact_from_disclosed_version_file(
            disclosed_version_file=disclosed_version_file,
            cve_id=args.cve_id,
            baseline_version=baseline_version,
            target_version=target_version,
        )
        or parse_artifact_from_cause(str(pair.get("cause") or ""))
        or infer_artifact_from_repo_hint(pom_path, str(cve_entry.get("REPO") or ""))
    )
    materialized = materialize_case_workspace(
        case_id=case_id,
        exploit_demo=exploit_demo,
        workspace_root=workspace_root,
        baseline_version=baseline_version,
        target_version=target_version,
        version_property=args.version_property,
        artifact=artifact,
        cause=str(pair.get("cause") or ""),
        test_file=args.test_file,
        trace_packages=args.trace_packages,
        java_version=args.java_version,
        observe_only_tests=not args.strict_tests,
        force=args.force,
        output_json=materialized_json_path,
    )
    materialized_payload = materialized.to_json()

    runner_script = pathlib.Path(__file__).resolve().parent / "run_version_regression_analysis.py"
    test_result_payloads: List[Dict[str, object]] = []
    runner_exit_codes: List[int] = []
    test_files = [pathlib.Path(test_path).resolve() for test_path in materialized_payload.get("test_files", [])]
    use_shared_analysis_dir = len(test_files) == 1

    for index, test_file in enumerate(test_files, start=1):
        test_slug = make_test_run_slug(materialized.workspace_dir, test_file)
        test_analysis_dir = analysis_root if use_shared_analysis_dir else analysis_root / test_slug
        driver_output_path = case_root / "run-version-analysis.log"
        if not use_shared_analysis_dir:
            driver_output_path = case_root / f"run-version-analysis__{test_slug}.log"

        if test_analysis_dir.exists():
            shutil.rmtree(test_analysis_dir)
        if driver_output_path.exists():
            driver_output_path.unlink()

        driver_command = [
            sys.executable,
            str(runner_script),
            baseline_version,
            target_version,
            str(test_file),
            "--analysis-dir",
            str(test_analysis_dir),
            "--version-property",
            args.version_property,
            "--artifact",
            materialized.artifact,
            "--maven-bin",
            args.maven_bin,
            "--compat-replay-target",
        ]
        if args.cve_id:
            driver_command.extend(["--cve-id", args.cve_id])
        description = str(cve_entry.get("description") or "").strip()
        if description:
            driver_command.extend(["--description", description])
        compare_url = str(pair.get("COMPARE_URL") or "").strip()
        if compare_url:
            driver_command.extend(["--compare-url", compare_url])
        if not args.strict_tests:
            driver_command.append("--observe-only")
        if args.trace_packages:
            driver_command.extend(["--trace-packages", args.trace_packages])

        print(f"[{index}/{len(test_files)}] Running test file: {test_file}", flush=True)
        completed = run_subprocess(driver_command, cwd=materialized.workspace_dir)
        driver_output_path.write_text(completed.stdout, encoding="utf-8")
        runner_exit_codes.append(completed.returncode)

        if test_analysis_dir.exists() and (test_analysis_dir / "version-diff").exists():
            generate_api_change_summary(test_analysis_dir)

        per_test_materialized = dict(materialized_payload)
        per_test_materialized["test_file"] = str(test_file)
        result_payload = build_result_payload(
            case_id=case_id,
            cve_id=args.cve_id,
            cve_entry=cve_entry,
            pair_index=args.pair_index,
            pair=pair,
            materialized=per_test_materialized,
            analysis_dir=test_analysis_dir,
            driver_command=driver_command,
            driver_exit_code=completed.returncode,
            driver_output_path=driver_output_path,
        )
        test_result_payloads.append(result_payload)

    result_payload = aggregate_case_results(test_result_payloads, analysis_root, materialized_payload)
    result_payload["runner_exit_codes"] = runner_exit_codes
    write_json(result_path, result_payload)

    print(f"Case analyzed: {case_id}")
    print(f"Result: {result_path}")
    print(f"Status: {result_payload['status']}")
    print(f"Tests analyzed: {len(test_result_payloads)}")
    return 0 if all(code == 0 for code in runner_exit_codes) else next(code for code in runner_exit_codes if code != 0)


if __name__ == "__main__":
    raise SystemExit(main())
