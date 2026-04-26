#!/usr/bin/env python3

import argparse
import pathlib
import re
import subprocess
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from materialize_case_workspace import collect_direct_dependency_candidates, infer_artifact_from_pom
from run_case_analysis import (
    default_disclosed_version_file,
    default_output_root,
    find_exploit_demo,
    infer_artifact_from_disclosed_version_file,
    infer_artifact_from_repo_hint,
    infer_failure_subtype,
    load_case_entry,
    load_optional_json,
    make_case_id,
    parse_artifact_from_cause,
    read_text,
    resolve_exploit_roots,
    write_json,
)

TRACE_PACKAGE_ERROR = "Unable to infer trace packages from imports. Please pass --trace-packages explicitly."
ARTIFACT_INFERENCE_ERROR = "Unable to infer target artifact. Pass --artifact explicitly."
ARTIFACT_FILE_MISSING_PREFIX = "Artifact file does not exist:"
WORKSPACE_EXISTS_ERROR = "Workspace already exists:"
MATERIALIZED_POM_MISSING_ERROR = "pom.xml does not exist in materialized workspace:"
BASELINE_FAILED_PATTERN = re.compile(r"Baseline version .* did not complete successfully", re.IGNORECASE)
TARGET_FAILED_PATTERN = re.compile(r"Target version .* did not complete successfully", re.IGNORECASE)
GENERIC_ARTIFACT_PARTS = {
    "core",
    "lib",
    "library",
    "plugin",
    "parent",
    "java",
    "sdk",
    "api",
    "all",
}
SIGNAL_ARTIFACT_SKIP = {
    ("junit", "junit"),
    ("org.assertj", "assertj-core"),
    ("org.junit.jupiter", "junit-jupiter"),
    ("org.mockito", "mockito-core"),
}
SIGNAL_TOKEN_SKIP = GENERIC_ARTIFACT_PARTS | {
    "org",
    "com",
    "net",
    "io",
    "edu",
    "java",
    "javax",
    "jakarta",
    "spring",
    "apache",
    "framework",
    "project",
    "projects",
    "common",
    "commons",
    "test",
    "tests",
}
ARTIFACT_HINT_OVERRIDES = {
    "CVE-2018-11039": "org.springframework:spring-web",
    "CVE-2021-40111": "org.apache.james.protocols:protocols-imap",
}
RETRY_METADATA_KEYS = ("auto_artifact", "auto_trace_packages")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Runner-error-aware wrapper for run_case_analysis.py")
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


def base_script_path() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent / "run_case_analysis.py"


def resolve_output_root(raw_output_root: Optional[str]) -> pathlib.Path:
    return pathlib.Path(raw_output_root).expanduser().resolve() if raw_output_root else default_output_root()


def resolve_case_paths(args: argparse.Namespace) -> Tuple[str, pathlib.Path, pathlib.Path, Dict[str, object], Dict[str, object]]:
    cve_list_path = pathlib.Path(args.cve_list).expanduser().resolve()
    cve_entry, pair = load_case_entry(cve_list_path, args.cve_id, args.pair_index)
    case_id = make_case_id(args.cve_id, pair, args.pair_index)
    output_root = resolve_output_root(args.output_root)
    case_root = output_root / "cases" / case_id
    result_path = case_root / "case-result.json"
    return case_id, case_root, result_path, cve_entry, pair


def find_existing_workspace_dir(case_root: pathlib.Path) -> Optional[pathlib.Path]:
    workspace_parent = case_root / "workspace"
    if not workspace_parent.exists():
        return None
    candidates = sorted(path for path in workspace_parent.iterdir() if path.is_dir())
    return candidates[0] if candidates else None


def find_existing_workspace_pom(case_root: pathlib.Path) -> Optional[pathlib.Path]:
    workspace_dir = find_existing_workspace_dir(case_root)
    if workspace_dir is None:
        return None
    pom_path = workspace_dir / "pom.xml"
    if pom_path.exists():
        return pom_path
    candidates = sorted(workspace_dir.rglob("pom.xml"))
    return candidates[0] if candidates else None


def collect_signal_test_files(case_root: pathlib.Path) -> List[pathlib.Path]:
    workspace_dir = find_existing_workspace_dir(case_root)
    if workspace_dir is None:
        return []
    return sorted(workspace_dir.glob("src/test/java/**/*.java"))


def unique_preserve_order(values: Iterable[str]) -> List[str]:
    ordered: List[str] = []
    for value in values:
        if value and value not in ordered:
            ordered.append(value)
    return ordered


def artifact_signal_tokens(group_id: str, artifact_id: str) -> List[str]:
    tokens = [
        part
        for part in list(group_id.lower().split(".")) + list(re.split(r"[-_.]+", artifact_id.lower()))
        if len(part) >= 3 and part not in SIGNAL_TOKEN_SKIP
    ]
    return unique_preserve_order(tokens)


def build_signal_text(test_files: Sequence[pathlib.Path], dataset_cause: str) -> str:
    lines: List[str] = [str(dataset_cause or "")]
    for test_file in list(test_files)[:8]:
        for raw_line in read_text(test_file).splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("import "):
                lines.append(stripped)
    return "\n".join(lines).lower()


def infer_artifact_from_signal_text(pom_path: pathlib.Path, signal_text: str) -> Optional[str]:
    if not signal_text.strip() or not pom_path.exists():
        return None

    scored: List[Tuple[int, str]] = []
    normalized_signal = normalized_token(signal_text)
    for coordinate, _version in collect_direct_dependency_candidates(pom_path):
        if (coordinate.group_id, coordinate.artifact_id) in SIGNAL_ARTIFACT_SKIP:
            continue
        score = 0
        artifact_norm = normalized_token(coordinate.artifact_id)
        if artifact_norm and artifact_norm in normalized_signal:
            score += 6
        for token in artifact_signal_tokens(coordinate.group_id, coordinate.artifact_id):
            score += signal_text.count(token)
        if score > 0:
            scored.append((score, coordinate.gav()))

    scored.sort(key=lambda item: (-item[0], item[1]))
    if not scored:
        return None
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        return None
    return scored[0][1]


def infer_artifact_for_retry(
    args: argparse.Namespace,
    case_id: str,
    case_root: pathlib.Path,
    cve_entry: Dict[str, object],
    pair: Dict[str, object],
    result_payload: Dict[str, object],
) -> Optional[str]:
    artifact = str(result_payload.get("artifact") or args.artifact or "").strip()
    if artifact:
        return artifact

    baseline_version = str(result_payload.get("baseline_version") or pair.get("appears") or "")
    target_version = str(result_payload.get("target_version") or pair.get("not appears") or "")
    dataset_cause = str(result_payload.get("dataset_cause") or pair.get("cause") or "")
    workspace_pom = find_existing_workspace_pom(case_root)
    test_files = collect_signal_test_files(case_root)
    signal_text = build_signal_text(test_files, dataset_cause)

    if workspace_pom is not None:
        inferred_coordinate = infer_artifact_from_pom(
            workspace_pom,
            baseline_version=baseline_version,
            target_version=target_version,
        )
        if inferred_coordinate is not None:
            return inferred_coordinate.gav()
        inferred_from_signal = infer_artifact_from_signal_text(workspace_pom, signal_text)
        if inferred_from_signal:
            return inferred_from_signal

    exploit_demo = None
    try:
        exploit_demo = find_exploit_demo(resolve_exploit_roots(args.exploit_root), args.cve_id)
    except SystemExit:
        exploit_demo = None

    exploit_pom = exploit_demo / "pom.xml" if exploit_demo is not None else None
    if exploit_pom is not None and exploit_pom.exists():
        inferred_coordinate = infer_artifact_from_pom(
            exploit_pom,
            baseline_version=baseline_version,
            target_version=target_version,
        )
        if inferred_coordinate is not None:
            return inferred_coordinate.gav()
        inferred_from_signal = infer_artifact_from_signal_text(exploit_pom, signal_text)
        if inferred_from_signal:
            return inferred_from_signal

    disclosed_version_file = (
        pathlib.Path(args.disclosed_version_file).expanduser().resolve()
        if args.disclosed_version_file
        else default_disclosed_version_file()
    )
    disclosed_artifact = infer_artifact_from_disclosed_version_file(
        disclosed_version_file=disclosed_version_file,
        cve_id=args.cve_id,
        baseline_version=baseline_version,
        target_version=target_version,
    )
    if disclosed_artifact:
        return disclosed_artifact

    cause_artifact = parse_artifact_from_cause(dataset_cause)
    if cause_artifact:
        return cause_artifact

    repo_name = str(cve_entry.get("REPO") or "")
    if workspace_pom is not None:
        repo_hint = infer_artifact_from_repo_hint(workspace_pom, repo_name)
        if repo_hint:
            return repo_hint
    if exploit_pom is not None and exploit_pom.exists():
        repo_hint = infer_artifact_from_repo_hint(exploit_pom, repo_name)
        if repo_hint:
            return repo_hint

    return ARTIFACT_HINT_OVERRIDES.get(case_id) or ARTIFACT_HINT_OVERRIDES.get(args.cve_id)


def build_original_command(
    args: argparse.Namespace,
    override_trace_packages: Optional[str] = None,
    override_artifact: Optional[str] = None,
) -> List[str]:
    command = [
        sys.executable,
        str(base_script_path()),
        "--cve-list",
        args.cve_list,
        "--cve-id",
        args.cve_id,
        "--pair-index",
        str(args.pair_index),
        "--version-property",
        args.version_property,
        "--maven-bin",
        args.maven_bin,
    ]
    for exploit_root in args.exploit_root:
        command.extend(["--exploit-root", exploit_root])
    if args.output_root:
        command.extend(["--output-root", args.output_root])
    selected_artifact = override_artifact or args.artifact
    if selected_artifact:
        command.extend(["--artifact", selected_artifact])
    if args.disclosed_version_file:
        command.extend(["--disclosed-version-file", args.disclosed_version_file])
    if args.test_file:
        command.extend(["--test-file", args.test_file])
    selected_trace_packages = override_trace_packages or args.trace_packages
    if selected_trace_packages:
        command.extend(["--trace-packages", selected_trace_packages])
    if args.java_version:
        command.extend(["--java-version", args.java_version])
    if args.allow_compile_true:
        command.append("--allow-compile-true")
    if args.strict_tests:
        command.append("--strict-tests")
    if args.force:
        command.append("--force")
    return command


def run_and_forward(command: List[str]) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    return completed


def load_result_payload(result_path: pathlib.Path) -> Dict[str, object]:
    if not result_path.exists():
        raise SystemExit(f"Expected result file was not produced: {result_path}")
    return load_optional_json(result_path) or {}


def synthesize_missing_result_payload(
    args: argparse.Namespace,
    case_id: str,
    case_root: pathlib.Path,
    result_path: pathlib.Path,
    cve_entry: Dict[str, object],
    pair: Dict[str, object],
    command: List[str],
    completed: subprocess.CompletedProcess,
) -> Dict[str, object]:
    case_root.mkdir(parents=True, exist_ok=True)
    bootstrap_log_path = case_root / "runner-fix-bootstrap.log"
    bootstrap_log_path.write_text(completed.stdout or "", encoding="utf-8")
    workspace_dir = find_existing_workspace_dir(case_root) or (case_root / "workspace" / case_id)
    payload = {
        "case_id": case_id,
        "cve_id": args.cve_id,
        "pair_index": args.pair_index,
        "owner": cve_entry.get("OWNER"),
        "repo": cve_entry.get("REPO"),
        "description": cve_entry.get("description"),
        "artifact": args.artifact,
        "baseline_version": str(pair.get("appears") or ""),
        "target_version": str(pair.get("not appears") or ""),
        "dataset_cause": str(pair.get("cause") or ""),
        "status": "runner_error",
        "failure_kind": "runner_error",
        "failure_subtype": "runner_error",
        "analysis_dir": str(case_root / "analysis"),
        "workspace_dir": str(workspace_dir),
        "driver_command": command,
        "driver_exit_code": completed.returncode,
        "driver_output_path": str(bootstrap_log_path),
        "failure_excerpt_path": None,
        "status_counts": {"runner_error": 1},
        "test_results": [],
    }
    write_json(result_path, payload)
    return payload


def load_or_synthesize_result_payload(
    args: argparse.Namespace,
    case_id: str,
    case_root: pathlib.Path,
    result_path: pathlib.Path,
    cve_entry: Dict[str, object],
    pair: Dict[str, object],
    command: List[str],
    completed: subprocess.CompletedProcess,
) -> Dict[str, object]:
    if result_path.exists():
        return load_result_payload(result_path)
    if completed.returncode == 0:
        raise SystemExit(f"Expected result file was not produced: {result_path}")
    return synthesize_missing_result_payload(args, case_id, case_root, result_path, cve_entry, pair, command, completed)


def load_or_synthesize_retry_payload(
    result_path: pathlib.Path,
    previous_payload: Dict[str, object],
    command: List[str],
    completed: subprocess.CompletedProcess,
    retry_label: str,
) -> Dict[str, object]:
    if result_path.exists():
        return load_result_payload(result_path)
    if completed.returncode == 0:
        raise SystemExit(f"Expected result file was not produced after {retry_label}: {result_path}")

    case_root = result_path.parent
    retry_log_path = case_root / f"runner-fix-{retry_label}.log"
    retry_log_path.write_text(completed.stdout or "", encoding="utf-8")
    payload = dict(previous_payload)
    payload["status"] = "runner_error"
    payload["failure_kind"] = "runner_error"
    payload["failure_subtype"] = "runner_error"
    payload["driver_command"] = command
    payload["driver_exit_code"] = completed.returncode
    payload["driver_output_path"] = str(retry_log_path)
    payload["failure_excerpt_path"] = None
    payload["status_counts"] = {"runner_error": 1}
    write_json(result_path, payload)
    return payload


def annotate_retry_payload(result_path: pathlib.Path, previous_payload: Dict[str, object], refreshed_payload: Dict[str, object], **metadata: str) -> Dict[str, object]:
    for key in RETRY_METADATA_KEYS:
        value = metadata.get(key) or previous_payload.get(key)
        if value:
            refreshed_payload[key] = value
    if not refreshed_payload.get("artifact"):
        inferred_artifact = metadata.get("auto_artifact") or previous_payload.get("auto_artifact")
        if inferred_artifact:
            refreshed_payload["artifact"] = inferred_artifact
    write_json(result_path, refreshed_payload)
    return refreshed_payload


def normalized_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def infer_trace_packages_from_artifact(artifact: Optional[str]) -> Optional[str]:
    if not artifact or ":" not in artifact:
        return None
    group_id, artifact_id = artifact.split(":", 1)
    group_parts = [part for part in group_id.split(".") if part]
    if not group_parts:
        return None

    artifact_parts = [part for part in re.split(r"[-_.]+", artifact_id) if part]
    artifact_norm = normalized_token(artifact_id)
    last_group_norm = normalized_token(group_parts[-1])

    candidate_parts = list(group_parts)
    if artifact_norm != last_group_norm:
        filtered_parts = [
            part
            for part in artifact_parts
            if normalized_token(part) not in GENERIC_ARTIFACT_PARTS and normalized_token(part)
        ]
        if filtered_parts:
            candidate_parts.extend(filtered_parts)
    return "/".join(candidate_parts) + "/"


def read_driver_output(result_payload: Dict[str, object]) -> str:
    driver_output_path = pathlib.Path(str(result_payload.get("driver_output_path") or ""))
    if driver_output_path.exists():
        return read_text(driver_output_path)
    return ""


def collect_analysis_dirs(result_payload: Dict[str, object]) -> List[pathlib.Path]:
    candidates: List[str] = []
    for key in ("selected_analysis_dir", "analysis_dir", "analysis_root"):
        value = str(result_payload.get(key) or "").strip()
        if value:
            candidates.append(value)
    for test_payload in result_payload.get("test_results") or []:
        value = str(test_payload.get("analysis_dir") or "").strip()
        if value:
            candidates.append(value)
    return [pathlib.Path(value) for value in unique_preserve_order(candidates)]


def first_existing_path(paths: Iterable[pathlib.Path]) -> Optional[pathlib.Path]:
    for path in paths:
        if path.exists():
            return path
    return None


def infer_observation_stage(runlog_text: str, has_baseline_artifacts: bool, has_target_artifacts: bool) -> Optional[str]:
    if BASELINE_FAILED_PATTERN.search(runlog_text):
        return "baseline"
    if TARGET_FAILED_PATTERN.search(runlog_text):
        return "target"
    if has_baseline_artifacts and not has_target_artifacts:
        return "baseline"
    if has_target_artifacts:
        return "target"
    return None


def infer_status_from_failure_text(text: str, api_summary: Dict[str, object]) -> Tuple[str, str, str]:
    lowered = (text or "").lower()
    if (
        ARTIFACT_FILE_MISSING_PREFIX.lower() in lowered
        or "failed to collect dependencies" in lowered
        or "could not resolve dependencies" in lowered
        or "could not transfer artifact" in lowered
    ):
        return "execution_failure", "dependency_resolution_failure", "dependency_resolution_failure"

    runtime_markers = (
        "there are test failures",
        "tests in error:",
        "test timed out",
        "forked vm terminated without saying properly goodbye",
        "agent library failed to init",
        "error opening zip file or jar manifest missing",
        "could not create the java virtual machine",
        "surefirebooterforkexception",
    )
    failure_subtype = infer_failure_subtype(text, api_summary)
    if any(marker in lowered for marker in runtime_markers):
        return "execution_failure", "execution_failure", failure_subtype

    compile_markers = (
        "compilation error",
        "cannot find symbol",
        "package ",
        " does not exist",
        "fatal error compiling",
        "invalid target release",
        "source option",
        "target option",
        "release version",
        "mojofailureexception",
    )
    status = "compile_failure" if any(marker in lowered for marker in compile_markers) else "execution_failure"
    failure_kind = status
    if failure_subtype == "unknown_failure" and "linkageerror" in lowered:
        failure_subtype = "binary_incompatibility"
    return status, failure_kind, failure_subtype


def prefetch_artifact_versions(artifact: str, versions: Iterable[str], maven_bin: str) -> None:
    for version in versions:
        version = str(version or "").strip()
        if not version:
            continue
        command = [maven_bin, "-q", "dependency:get", f"-Dartifact={artifact}:{version}", "-Dtransitive=false"]
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        print(f"[runner-fix] prefetch {artifact}:{version} -> exit {completed.returncode}")
        if completed.stdout:
            print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")


def apply_normalized_status(
    payload: Dict[str, object],
    status: str,
    failure_kind: str,
    failure_subtype: str,
    excerpt_path: Optional[pathlib.Path],
    reason: str,
    observation_stage: Optional[str] = None,
) -> None:
    payload["status"] = status
    payload["failure_kind"] = failure_kind
    payload["failure_subtype"] = failure_subtype
    payload["failure_excerpt_path"] = str(excerpt_path) if excerpt_path else payload.get("failure_excerpt_path")
    payload["normalized_from_runner_error"] = True
    payload["normalization_reason"] = reason
    if observation_stage in {"baseline", "target"}:
        observation_key = f"{observation_stage}_execution_observation"
        if status == "compile_failure":
            observation_value = "compile_failure"
        elif failure_kind == "dependency_resolution_failure":
            observation_value = "dependency_resolution_failure"
        else:
            observation_value = "execution_failure"
        payload[observation_key] = payload.get(observation_key) or observation_value


def normalize_runner_error_result(result_payload: Dict[str, object], result_path: pathlib.Path) -> Dict[str, object]:
    if result_payload.get("status") != "runner_error":
        return result_payload

    runlog_text = read_driver_output(result_payload)
    dataset_cause = str(result_payload.get("dataset_cause") or "")
    analysis_dirs = collect_analysis_dirs(result_payload)

    api_summary: Dict[str, object] = {}
    baseline_excerpt_path = first_existing_path(path / "baseline-observation-excerpt.txt" for path in analysis_dirs)
    target_excerpt_path = first_existing_path(
        candidate
        for path in analysis_dirs
        for candidate in (
            path / "target-failure-excerpt.txt",
            path / "target-observation-excerpt.txt",
            path / "target-prepare-classpath-excerpt.txt",
            path / "target-prepare-generator-excerpt.txt",
        )
    )
    baseline_maven_path = first_existing_path(path / "baseline-maven.log" for path in analysis_dirs)
    target_maven_path = first_existing_path(path / "target-maven.log" for path in analysis_dirs)
    for analysis_dir in analysis_dirs:
        loaded_summary = load_optional_json(analysis_dir / "version-diff" / "api-change-summary.json") or {}
        if loaded_summary:
            api_summary = loaded_summary
            break

    baseline_excerpt = read_text(baseline_excerpt_path) if baseline_excerpt_path else ""
    target_excerpt = read_text(target_excerpt_path) if target_excerpt_path else ""
    baseline_maven_text = read_text(baseline_maven_path) if baseline_maven_path else ""
    target_maven_text = read_text(target_maven_path) if target_maven_path else ""
    combined_error_text = "\n".join(
        part
        for part in [dataset_cause, runlog_text, baseline_excerpt, target_excerpt, baseline_maven_text, target_maven_text]
        if part
    )
    lowered = combined_error_text.lower()
    observation_stage = infer_observation_stage(
        runlog_text,
        has_baseline_artifacts=bool(baseline_excerpt_path or baseline_maven_path),
        has_target_artifacts=bool(target_excerpt_path or target_maven_path),
    )

    if observation_stage == "baseline" and (baseline_excerpt_path or baseline_maven_path):
        failure_text = "\n".join(part for part in [dataset_cause, runlog_text, baseline_excerpt, baseline_maven_text] if part)
        status, failure_kind, failure_subtype = infer_status_from_failure_text(failure_text, api_summary)
        apply_normalized_status(
            result_payload,
            status=status,
            failure_kind=failure_kind,
            failure_subtype=failure_subtype,
            excerpt_path=baseline_excerpt_path or baseline_maven_path,
            reason="baseline version analysis produced actionable failure logs",
            observation_stage="baseline",
        )
    elif observation_stage == "target" and (target_excerpt_path or target_maven_path):
        failure_text = "\n".join(part for part in [dataset_cause, runlog_text, target_excerpt, target_maven_text] if part)
        status, failure_kind, failure_subtype = infer_status_from_failure_text(failure_text, api_summary)
        apply_normalized_status(
            result_payload,
            status=status,
            failure_kind=failure_kind,
            failure_subtype=failure_subtype,
            excerpt_path=target_excerpt_path or target_maven_path,
            reason="target version analysis produced actionable failure logs",
            observation_stage="target",
        )
    elif ARTIFACT_FILE_MISSING_PREFIX.lower() in lowered or "failed to collect dependencies" in lowered or "could not resolve dependencies" in lowered:
        apply_normalized_status(
            result_payload,
            status="execution_failure",
            failure_kind="dependency_resolution_failure",
            failure_subtype="dependency_resolution_failure",
            excerpt_path=pathlib.Path(str(result_payload.get("driver_output_path") or "")) if result_payload.get("driver_output_path") else None,
            reason="version diff artifact lookup failed due to missing dependency artifacts",
            observation_stage="target",
        )
    elif TRACE_PACKAGE_ERROR.lower() in lowered:
        apply_normalized_status(
            result_payload,
            status="execution_failure",
            failure_kind="trace_package_inference_failure",
            failure_subtype="unknown_failure",
            excerpt_path=pathlib.Path(str(result_payload.get("driver_output_path") or "")) if result_payload.get("driver_output_path") else None,
            reason="trace package inference failed before analysis execution",
        )
    else:
        return result_payload

    test_results = result_payload.get("test_results") or []
    normalized_count = 0
    for test_payload in test_results:
        if test_payload.get("status") != "runner_error":
            continue
        apply_normalized_status(
            test_payload,
            status=str(result_payload["status"]),
            failure_kind=str(result_payload["failure_kind"]),
            failure_subtype=str(result_payload["failure_subtype"]),
            excerpt_path=pathlib.Path(str(result_payload.get("failure_excerpt_path"))) if result_payload.get("failure_excerpt_path") else None,
            reason=str(result_payload.get("normalization_reason") or "runner error normalized"),
            observation_stage=observation_stage,
        )
        normalized_count += 1
    if normalized_count:
        result_payload["status_counts"] = {str(result_payload["status"]): normalized_count}
    write_json(result_path, result_payload)
    return result_payload


def maybe_retry_existing_workspace(args: argparse.Namespace, result_path: pathlib.Path, result_payload: Dict[str, object]) -> Dict[str, object]:
    if result_payload.get("status") != "runner_error":
        return result_payload
    runlog_text = read_driver_output(result_payload)
    if WORKSPACE_EXISTS_ERROR not in runlog_text:
        return result_payload

    print("[runner-fix] retrying with --force because workspace already exists")
    retry_command = build_original_command(
        args,
        override_trace_packages=str(result_payload.get("auto_trace_packages") or args.trace_packages or "") or None,
        override_artifact=str(result_payload.get("artifact") or result_payload.get("auto_artifact") or args.artifact or "") or None,
    )
    if "--force" not in retry_command:
        retry_command.append("--force")
    retry_completed = run_and_forward(retry_command)
    refreshed = load_or_synthesize_retry_payload(
        result_path,
        result_payload,
        retry_command,
        retry_completed,
        "retry-existing-workspace",
    )
    return annotate_retry_payload(result_path, result_payload, refreshed)


def maybe_retry_infer_artifact(
    args: argparse.Namespace,
    case_id: str,
    case_root: pathlib.Path,
    result_path: pathlib.Path,
    cve_entry: Dict[str, object],
    pair: Dict[str, object],
    result_payload: Dict[str, object],
) -> Dict[str, object]:
    if result_payload.get("status") != "runner_error" or args.artifact:
        return result_payload
    runlog_text = read_driver_output(result_payload)
    if ARTIFACT_INFERENCE_ERROR not in runlog_text and MATERIALIZED_POM_MISSING_ERROR not in runlog_text:
        return result_payload

    inferred_artifact = infer_artifact_for_retry(args, case_id, case_root, cve_entry, pair, result_payload)
    if not inferred_artifact:
        return result_payload

    print(f"[runner-fix] retrying with inferred artifact: {inferred_artifact}")
    retry_command = build_original_command(args, override_artifact=inferred_artifact)
    if "--force" not in retry_command:
        retry_command.append("--force")
    retry_completed = run_and_forward(retry_command)
    refreshed = load_or_synthesize_retry_payload(
        result_path,
        result_payload,
        retry_command,
        retry_completed,
        "retry-inferred-artifact",
    )
    return annotate_retry_payload(result_path, result_payload, refreshed, auto_artifact=inferred_artifact)


def maybe_retry_trace_package_inference(args: argparse.Namespace, result_path: pathlib.Path, result_payload: Dict[str, object]) -> Dict[str, object]:
    if result_payload.get("status") != "runner_error" or args.trace_packages:
        return result_payload
    runlog_text = read_driver_output(result_payload)
    if TRACE_PACKAGE_ERROR not in runlog_text:
        return result_payload

    inferred = infer_trace_packages_from_artifact(
        str(result_payload.get("artifact") or result_payload.get("auto_artifact") or args.artifact or "")
    )
    if not inferred:
        return result_payload

    print(f"[runner-fix] retrying with inferred trace packages: {inferred}")
    retry_command = build_original_command(
        args,
        override_trace_packages=inferred,
        override_artifact=str(result_payload.get("artifact") or result_payload.get("auto_artifact") or args.artifact or "") or None,
    )
    if "--force" not in retry_command:
        retry_command.append("--force")
    retry_completed = run_and_forward(retry_command)
    refreshed = load_or_synthesize_retry_payload(
        result_path,
        result_payload,
        retry_command,
        retry_completed,
        "retry-trace-packages",
    )
    return annotate_retry_payload(result_path, result_payload, refreshed, auto_trace_packages=inferred)


def maybe_retry_missing_artifact(args: argparse.Namespace, result_path: pathlib.Path, result_payload: Dict[str, object]) -> Dict[str, object]:
    if result_payload.get("status") != "runner_error":
        return result_payload
    runlog_text = read_driver_output(result_payload)
    if ARTIFACT_FILE_MISSING_PREFIX not in runlog_text:
        return result_payload

    artifact = str(result_payload.get("artifact") or result_payload.get("auto_artifact") or args.artifact or "").strip()
    if not artifact:
        return result_payload

    prefetch_artifact_versions(
        artifact=artifact,
        versions=[result_payload.get("baseline_version"), result_payload.get("target_version")],
        maven_bin=args.maven_bin,
    )
    print("[runner-fix] retrying after artifact prefetch")
    retry_command = build_original_command(args, override_artifact=artifact)
    if "--force" not in retry_command:
        retry_command.append("--force")
    retry_completed = run_and_forward(retry_command)
    refreshed = load_or_synthesize_retry_payload(result_path, result_payload, retry_command, retry_completed, "retry-prefetch")
    return annotate_retry_payload(result_path, result_payload, refreshed)


def main() -> int:
    args = parse_args()
    case_id, case_root, result_path, cve_entry, pair = resolve_case_paths(args)
    print(f"[runner-fix] running case {case_id}")

    initial_command = build_original_command(args)
    completed = run_and_forward(initial_command)
    result_payload = load_or_synthesize_result_payload(
        args,
        case_id,
        case_root,
        result_path,
        cve_entry,
        pair,
        initial_command,
        completed,
    )

    result_payload = maybe_retry_existing_workspace(args, result_path, result_payload)
    result_payload = maybe_retry_infer_artifact(args, case_id, case_root, result_path, cve_entry, pair, result_payload)
    result_payload = maybe_retry_trace_package_inference(args, result_path, result_payload)
    result_payload = maybe_retry_missing_artifact(args, result_path, result_payload)
    result_payload = normalize_runner_error_result(result_payload, result_path)

    final_status = str(result_payload.get("status") or "unknown")
    final_subtype = str(result_payload.get("failure_subtype") or "")
    print(f"[runner-fix] final status: {final_status} {final_subtype}".rstrip())

    if final_status == "runner_error":
        return completed.returncode or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
