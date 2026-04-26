#!/usr/bin/env python3

import argparse
import os
import pathlib

from compat_replay_lib import prepare_compat_replay, run_compat_replay
from llm_hunk_selector import LLMAnalysisConfig, run_llm_hunk_selection_sync
from trace_workflow_lib import (
    annotate_trace_summary,
    classify_execution_failure,
    compare_trace_sequences,
    dataclass_to_json,
    discover_test_context,
    extract_error_excerpt,
    extract_identifiers,
    format_trace_comparison,
    infer_version_bound_dependency,
    parse_artifact_override,
    run_dependency_tree,
    run_trace,
    unified_diff_text,
    write_json,
    write_text,
)
from version_diff_lib import generate_artifact_diff

DEFAULT_LLM_MODEL = "deepseek-v3"
DEFAULT_LLM_BASE_URL = "https://api.chatanywhere.tech/v1"
MAX_TRACE_BYTES_FOR_FULL_COMPARE = int(os.environ.get("DIFFTRACE_MAX_TRACE_BYTES_FOR_FULL_COMPARE", str(1024 * 1024 * 1024)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run baseline/target dependency regression analysis with trace capture and version diffs."
    )
    parser.add_argument("baseline_version", help="Known-good dependency version.")
    parser.add_argument("target_version", help="Downgraded or changed dependency version to analyze.")
    parser.add_argument("test_file", help="Path to the exploit/test Java file to run.")
    parser.add_argument("--trace-packages", help="Optional comma-separated instrumentation package prefixes.")
    parser.add_argument(
        "--version-property",
        default="target.library.version",
        help="Maven property that controls the target dependency version. Default: target.library.version",
    )
    parser.add_argument("--artifact", help="Optional explicit artifact override in groupId:artifactId form.")
    parser.add_argument("--maven-bin", default="mvn", help="Maven executable to use. Default: mvn")
    parser.add_argument("--analysis-dir", help="Optional explicit output directory for the analysis workspace.")
    parser.add_argument("--cve-id", help="Optional CVE id metadata written into analysis outputs.")
    parser.add_argument("--description", help="Optional CVE description metadata written into analysis outputs.")
    parser.add_argument("--compare-url", help="Optional compare URL metadata written into analysis outputs.")
    parser.add_argument("--observe-only", action="store_true", help="Ignore JUnit test failures so traces can still be captured and compared.")
    parser.add_argument("--compat-replay-target", action="store_true", help="Replay baseline-compiled test bytecode directly on the target dependency classpath.")
    parser.add_argument("--run-llm", action="store_true", help="Run the LLM hunk selector when there is a failure or trace diff.")
    parser.add_argument("--llm-model", default=DEFAULT_LLM_MODEL, help="LLM model name for AutoGen.")
    parser.add_argument("--llm-base-url", default=DEFAULT_LLM_BASE_URL, help="LLM base URL.")
    parser.add_argument("--llm-api-key", default=None, help="LLM API key. Defaults to OPENAI_API_KEY.")
    parser.add_argument("--llm-max-rounds", type=int, default=8, help="Maximum LLM tool rounds. Default: 8")
    return parser.parse_args()


def default_analysis_dir(project_root: pathlib.Path, test_selector: str, baseline_version: str, target_version: str) -> pathlib.Path:
    safe_selector = test_selector.replace(".", "_")
    return project_root / "target" / "version-analysis" / "{}__{}__{}".format(
        safe_selector,
        baseline_version,
        target_version,
    )


def write_dependency_tree_diff(baseline_tree: pathlib.Path, target_tree: pathlib.Path, diff_path: pathlib.Path) -> None:
    diff_text = unified_diff_text(
        baseline_tree.read_text(encoding="utf-8", errors="replace").splitlines(True),
        target_tree.read_text(encoding="utf-8", errors="replace").splitlines(True),
        fromfile=str(baseline_tree),
        tofile=str(target_tree),
    )
    write_text(diff_path, diff_text or "(no dependency tree diff)\n")


def write_analysis_metadata(
    analysis_root: pathlib.Path,
    context,
    coordinate,
    args: argparse.Namespace,
    target_execution_mode: str,
) -> None:
    write_json(
        analysis_root / "analysis-metadata.json",
        {
            "baseline_version": args.baseline_version,
            "target_version": args.target_version,
            "test_selector": context.test_selector,
            "test_file": str(context.test_file),
            "project_root": str(context.project_root),
            "trace_packages": context.trace_packages,
            "artifact": coordinate.gav(),
            "version_property": args.version_property,
            "target_execution_mode": target_execution_mode,
            "compat_replay_target": args.compat_replay_target,
            "cve_id": args.cve_id,
            "description": args.description,
            "compare_url": args.compare_url,
        },
    )


def observe_execution(result, excerpt_path: pathlib.Path, stage: str) -> dict:
    observation = classify_execution_failure(result.output)
    if observation is None:
        observation = "process_failure" if result.returncode != 0 else "success"
    excerpt_written = None
    if observation != "success":
        excerpt = extract_error_excerpt(result.output)
        write_text(excerpt_path, excerpt + "\n")
        excerpt_written = str(excerpt_path)
    return {
        "stage": stage,
        "returncode": result.returncode,
        "observation": observation,
        "command": result.command_str(),
        "log_path": str(result.output_path) if result.output_path else None,
        "excerpt_path": excerpt_written,
    }


def serialize_command(result):
    return dataclass_to_json(result) if result is not None else None


def write_execution_artifacts(
    commands_path: pathlib.Path,
    observations_path: pathlib.Path,
    baseline_result,
    baseline_observation: dict,
    target_result,
    target_observation: dict,
    target_prepare_classpath_result=None,
    target_prepare_classpath_observation=None,
    target_prepare_generator_result=None,
    target_prepare_generator_observation=None,
) -> None:
    command_payload = {
        "baseline": serialize_command(baseline_result),
        "target": serialize_command(target_result),
    }
    observation_payload = {
        "baseline": baseline_observation,
        "target": target_observation,
    }
    if target_prepare_classpath_result is not None:
        command_payload["target_prepare_classpath"] = serialize_command(target_prepare_classpath_result)
        observation_payload["target_prepare_classpath"] = target_prepare_classpath_observation
    if target_prepare_generator_result is not None:
        command_payload["target_prepare_generator"] = serialize_command(target_prepare_generator_result)
        observation_payload["target_prepare_generator"] = target_prepare_generator_observation
    write_json(commands_path, command_payload)
    write_json(observations_path, observation_payload)


def maybe_run_llm(args: argparse.Namespace, analysis_root: pathlib.Path, scenario: dict, output_name: str) -> None:
    if not args.run_llm:
        return

    api_key = (
        args.llm_api_key
        or os.environ.get("CHATANYWHERE_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )
    if not api_key:
        raise SystemExit(
            "LLM analysis requested but neither CHATANYWHERE_API_KEY nor OPENAI_API_KEY is set, "
            "and --llm-api-key was not provided."
        )

    output_path = analysis_root / output_name
    try:
        run_llm_hunk_selection_sync(
            analysis_root=analysis_root,
            scenario=scenario,
            output_path=output_path,
            config=LLMAnalysisConfig(
                model=args.llm_model,
                base_url=args.llm_base_url,
                api_key=api_key,
                max_rounds=args.llm_max_rounds,
            ),
        )
    except Exception as error:
        error_path = analysis_root / (output_name + ".error.txt")
        write_text(
            error_path,
            "LLM analysis failed.\n{}: {}\n".format(type(error).__name__, error),
        )
        print("LLM analysis failed. Details: {}".format(error_path))


def _relative_analysis_path(analysis_root: pathlib.Path, path: pathlib.Path):
    if path is None:
        return None
    candidate = pathlib.Path(path)
    if not candidate.exists():
        return None
    return str(candidate.relative_to(analysis_root))


def build_failure_scenario(
    analysis_root: pathlib.Path,
    coordinate,
    baseline_version: str,
    target_version: str,
    scenario_type: str,
    baseline_command: str,
    target_command,
    failing_command: str,
    baseline_execution_observation: str,
    target_execution_observation,
    dependency_tree_diff: pathlib.Path,
    baseline_trace: pathlib.Path,
    target_trace: pathlib.Path,
    failure_excerpt_path: pathlib.Path,
) -> dict:
    excerpt_text = failure_excerpt_path.read_text(encoding="utf-8", errors="replace") if failure_excerpt_path.exists() else ""
    scenario = {
        "scenario_type": scenario_type or "execution_failure",
        "baseline_version": baseline_version,
        "target_version": target_version,
        "artifact": coordinate.gav(),
        "baseline_command": baseline_command,
        "target_command": target_command,
        "failing_command": failing_command,
        "baseline_execution_observation": baseline_execution_observation,
        "target_execution_observation": target_execution_observation,
        "artifact_diff_root": "version-diff",
        "dependency_tree_diff": str(dependency_tree_diff.relative_to(analysis_root)),
    }
    if baseline_trace.exists():
        scenario["baseline_trace"] = str(baseline_trace.relative_to(analysis_root))
    if target_trace.exists():
        scenario["target_trace"] = str(target_trace.relative_to(analysis_root))
    if excerpt_text:
        scenario["failure_excerpt_file"] = str(failure_excerpt_path.relative_to(analysis_root))
        scenario["failure_excerpt_keywords"] = ", ".join(extract_identifiers(excerpt_text))
    return scenario


def build_trace_scenario(
    analysis_root: pathlib.Path,
    coordinate,
    baseline_version: str,
    target_version: str,
    baseline_command,
    target_command,
    baseline_execution_observation: str,
    target_execution_observation: str,
    dependency_tree_diff: pathlib.Path,
    baseline_trace: pathlib.Path,
    target_trace: pathlib.Path,
    trace_summary_path: pathlib.Path,
    trace_summary_text: str,
    has_difference: bool,
    trace_summary=None,
    cve_id: str = None,
    description: str = None,
    compare_url: str = None,
) -> dict:
    trace_summary = trace_summary or {}
    scenario = {
        "scenario_type": "trace_diff" if has_difference else "no_diff",
        "baseline_version": baseline_version,
        "target_version": target_version,
        "artifact": coordinate.gav(),
        "baseline_command": baseline_command,
        "target_command": target_command,
        "baseline_execution_observation": baseline_execution_observation,
        "target_execution_observation": target_execution_observation,
        "trace_summary_file": str(trace_summary_path.relative_to(analysis_root)),
        "trace_keywords": ", ".join(extract_identifiers(trace_summary_text)),
        "trace_has_effective_difference": trace_summary.get("has_effective_difference", has_difference),
        "trace_evidence_valid": trace_summary.get("trace_evidence_valid"),
        "trace_invalid_reasons": trace_summary.get("trace_invalid_reasons") or [],
        "first_divergence_is_noise": trace_summary.get("first_divergence_is_noise", False),
        "artifact_diff_root": "version-diff",
        "dependency_tree_diff": str(dependency_tree_diff.relative_to(analysis_root)),
    }
    if baseline_trace.exists():
        scenario["baseline_trace"] = str(baseline_trace.relative_to(analysis_root))
    if target_trace.exists():
        scenario["target_trace"] = str(target_trace.relative_to(analysis_root))
    if cve_id:
        scenario["cve_id"] = cve_id
    if description:
        scenario["description"] = description
    if compare_url:
        scenario["compare_url"] = compare_url
    return scenario


def maybe_build_lightweight_trace_summary(
    baseline_trace: pathlib.Path,
    target_trace: pathlib.Path,
    baseline_observation: str,
    target_observation: str,
) -> dict:
    baseline_size = baseline_trace.stat().st_size if baseline_trace.exists() else 0
    target_size = target_trace.stat().st_size if target_trace.exists() else 0
    if max(baseline_size, target_size) <= MAX_TRACE_BYTES_FOR_FULL_COMPARE:
        return None

    has_difference = baseline_observation != target_observation or baseline_size != target_size
    first_divergence = None
    if has_difference:
        divergence_reasons = []
        if baseline_observation != target_observation:
            divergence_reasons.append(
                f"execution observation differs: baseline={baseline_observation}, target={target_observation}"
            )
        if baseline_size != target_size:
            divergence_reasons.append(
                f"trace size differs: baseline={baseline_size} bytes, target={target_size} bytes"
            )
        first_divergence = {
            "index": None,
            "baseline": f"<lightweight-large-trace-summary baseline_bytes={baseline_size}>",
            "target": "; ".join(divergence_reasons) or f"<lightweight-large-trace-summary target_bytes={target_size}>",
        }

    return {
        "baseline_trace": str(baseline_trace),
        "target_trace": str(target_trace),
        "baseline_enter_count": None,
        "target_enter_count": None,
        "has_difference": has_difference,
        "first_divergence": first_divergence,
        "baseline_only_unique": [],
        "target_only_unique": [],
        "baseline_meta": {},
        "target_meta": {},
        "baseline_trace_bytes": baseline_size,
        "target_trace_bytes": target_size,
        "comparison_mode": "lightweight_large_trace_fallback",
    }


def main() -> int:
    args = parse_args()

    context = discover_test_context(pathlib.Path(args.test_file), args.trace_packages, artifact=args.artifact)
    analysis_root = pathlib.Path(args.analysis_dir).expanduser().resolve() if args.analysis_dir else default_analysis_dir(
        context.project_root,
        context.test_selector,
        args.baseline_version,
        args.target_version,
    )
    analysis_root.mkdir(parents=True, exist_ok=True)

    coordinate = parse_artifact_override(args.artifact) if args.artifact else infer_version_bound_dependency(
        context.project_root,
        args.version_property,
    )

    baseline_trace = analysis_root / "baseline-trace.log"
    target_trace = analysis_root / "target-trace.log"
    baseline_log = analysis_root / "baseline-maven.log"
    target_log = analysis_root / "target-maven.log"
    baseline_tree = analysis_root / "baseline-dependency-tree.txt"
    target_tree = analysis_root / "target-dependency-tree.txt"
    dependency_tree_diff = analysis_root / "dependency-tree.diff"
    compile_excerpt_path = analysis_root / "target-failure-excerpt.txt"
    baseline_observation_excerpt_path = analysis_root / "baseline-observation-excerpt.txt"
    target_observation_excerpt_path = analysis_root / "target-observation-excerpt.txt"
    target_prepare_classpath_excerpt_path = analysis_root / "target-prepare-classpath-excerpt.txt"
    target_prepare_generator_excerpt_path = analysis_root / "target-prepare-generator-excerpt.txt"
    execution_observations_path = analysis_root / "execution-observations.json"
    trace_commands_path = analysis_root / "trace-commands.json"
    trace_summary_json = analysis_root / "trace-diff-summary.json"
    trace_summary_txt = analysis_root / "trace-diff-summary.txt"
    target_execution_mode = "compat_replay" if args.compat_replay_target else "maven_test"

    write_analysis_metadata(
        analysis_root=analysis_root,
        context=context,
        coordinate=coordinate,
        args=args,
        target_execution_mode=target_execution_mode,
    )

    baseline_tree_result = run_dependency_tree(
        project_root=context.project_root,
        version=args.baseline_version,
        version_property=args.version_property,
        maven_bin=args.maven_bin,
        output_path=baseline_tree,
    )
    target_tree_result = run_dependency_tree(
        project_root=context.project_root,
        version=args.target_version,
        version_property=args.version_property,
        maven_bin=args.maven_bin,
        output_path=target_tree,
    )
    write_dependency_tree_diff(baseline_tree, target_tree, dependency_tree_diff)
    write_json(
        analysis_root / "dependency-tree-commands.json",
        {
            "baseline": dataclass_to_json(baseline_tree_result),
            "target": dataclass_to_json(target_tree_result),
        },
    )

    artifact_diff = generate_artifact_diff(
        coordinate=coordinate,
        baseline_version=args.baseline_version,
        target_version=args.target_version,
        output_root=analysis_root / "version-diff",
    )

    baseline_result = run_trace(
        context=context,
        version=args.baseline_version,
        version_property=args.version_property,
        maven_bin=args.maven_bin,
        trace_output=baseline_trace,
        log_output=baseline_log,
        ignore_test_failures=args.observe_only,
    )
    baseline_observation = observe_execution(baseline_result, baseline_observation_excerpt_path, "baseline")
    if baseline_result.returncode != 0:
        scenario = build_failure_scenario(
            analysis_root=analysis_root,
            coordinate=coordinate,
            baseline_version=args.baseline_version,
            target_version=args.target_version,
            scenario_type=baseline_observation["observation"] or "execution_failure",
            baseline_command=baseline_result.command_str(),
            target_command=None,
            failing_command=baseline_result.command_str(),
            baseline_execution_observation=baseline_observation["observation"],
            target_execution_observation="not_run",
            dependency_tree_diff=dependency_tree_diff,
            baseline_trace=baseline_trace,
            target_trace=target_trace,
            failure_excerpt_path=baseline_observation_excerpt_path,
        )
        write_json(analysis_root / "llm-scenario.json", scenario)
        maybe_run_llm(args, analysis_root, scenario, "llm-hunk-analysis.md")
        raise SystemExit(
            "Baseline version {} did not complete successfully.\nCommand: {}\nSee {}".format(
                args.baseline_version,
                baseline_result.command_str(),
                baseline_log,
            )
        )

    target_prepare_classpath_result = None
    target_prepare_classpath_observation = None
    target_prepare_generator_result = None
    target_prepare_generator_observation = None
    target_result = None

    if args.compat_replay_target:
        preparation = prepare_compat_replay(
            context=context,
            baseline_version=args.baseline_version,
            target_version=args.target_version,
            version_property=args.version_property,
            maven_bin=args.maven_bin,
            analysis_root=analysis_root,
        )
        target_prepare_classpath_result = preparation.classpath_result
        target_prepare_classpath_observation = observe_execution(
            target_prepare_classpath_result,
            target_prepare_classpath_excerpt_path,
            "target_prepare_classpath",
        )

        compat_prepare_failed = target_prepare_classpath_result.returncode != 0
        failed_prepare_result = target_prepare_classpath_result if compat_prepare_failed else None

        if not compat_prepare_failed:
            target_prepare_generator_result = preparation.generator_result
            target_prepare_generator_observation = observe_execution(
                target_prepare_generator_result,
                target_prepare_generator_excerpt_path,
                "target_prepare_generator",
            )
            compat_prepare_failed = target_prepare_generator_result.returncode != 0
            if compat_prepare_failed:
                failed_prepare_result = target_prepare_generator_result

        if compat_prepare_failed:
            target_execution_mode = "maven_test_fallback"
            print("Target compat preparation failed; falling back to direct Maven test execution.")
            print("Compat failure command: {}".format(failed_prepare_result.command_str()))
            target_result = run_trace(
                context=context,
                version=args.target_version,
                version_property=args.version_property,
                maven_bin=args.maven_bin,
                trace_output=target_trace,
                log_output=target_log,
                ignore_test_failures=args.observe_only,
            )
        else:
            target_result = run_compat_replay(
                context=context,
                layout=preparation.layout,
                version=args.target_version,
                version_property=args.version_property,
                trace_output=target_trace,
                log_output=target_log,
                ignore_test_failures=args.observe_only,
            )
    else:
        target_result = run_trace(
            context=context,
            version=args.target_version,
            version_property=args.version_property,
            maven_bin=args.maven_bin,
            trace_output=target_trace,
            log_output=target_log,
            ignore_test_failures=args.observe_only,
        )

    write_analysis_metadata(
        analysis_root=analysis_root,
        context=context,
        coordinate=coordinate,
        args=args,
        target_execution_mode=target_execution_mode,
    )

    target_observation = observe_execution(target_result, target_observation_excerpt_path, "target")
    write_execution_artifacts(
        trace_commands_path,
        execution_observations_path,
        baseline_result,
        baseline_observation,
        target_result,
        target_observation,
        target_prepare_classpath_result=target_prepare_classpath_result,
        target_prepare_classpath_observation=target_prepare_classpath_observation,
        target_prepare_generator_result=target_prepare_generator_result,
        target_prepare_generator_observation=target_prepare_generator_observation,
    )

    failure_kind = target_observation["observation"] if target_result.returncode != 0 else None
    if target_result.returncode != 0:
        excerpt = extract_error_excerpt(target_result.output)
        write_text(compile_excerpt_path, excerpt + "\n")

        scenario = build_failure_scenario(
            analysis_root=analysis_root,
            coordinate=coordinate,
            baseline_version=args.baseline_version,
            target_version=args.target_version,
            scenario_type=failure_kind or "execution_failure",
            baseline_command=baseline_result.command_str(),
            target_command=target_result.command_str(),
            failing_command=target_result.command_str(),
            baseline_execution_observation=baseline_observation["observation"],
            target_execution_observation=target_observation["observation"],
            dependency_tree_diff=dependency_tree_diff,
            baseline_trace=baseline_trace,
            target_trace=target_trace,
            failure_excerpt_path=compile_excerpt_path,
        )
        write_json(analysis_root / "llm-scenario.json", scenario)
        maybe_run_llm(args, analysis_root, scenario, "llm-hunk-analysis.md")

        print("Target version failed: {}".format(failure_kind or "execution_failure"))
        print("Failing command: {}".format(target_result.command_str()))
        print("Failure excerpt: {}".format(compile_excerpt_path))
        print("Artifact diff: {}".format(artifact_diff.root))
        print("Dependency tree diff: {}".format(dependency_tree_diff))
        return 0

    raw_trace_summary = (
        maybe_build_lightweight_trace_summary(
            baseline_trace,
            target_trace,
            baseline_observation["observation"],
            target_observation["observation"],
        )
        or compare_trace_sequences(baseline_trace, target_trace)
    )
    # Attach artifact so trace heuristics can treat some divergences as library-specific noise.
    raw_trace_summary["artifact"] = coordinate.gav()
    trace_summary = annotate_trace_summary(raw_trace_summary)
    trace_summary["baseline_execution_observation"] = baseline_observation["observation"]
    trace_summary["target_execution_observation"] = target_observation["observation"]
    trace_summary["target_execution_mode"] = target_execution_mode
    write_json(trace_summary_json, trace_summary)
    formatted_trace_summary = format_trace_comparison(trace_summary)
    if baseline_observation["observation"] != "success" or target_observation["observation"] != "success":
        formatted_trace_summary += "\n\nExecution observations:\n"
        formatted_trace_summary += "  baseline: {}\n".format(baseline_observation["observation"])
        formatted_trace_summary += "  target: {}\n".format(target_observation["observation"])
    formatted_trace_summary += "\nTarget execution mode: {}\n".format(target_execution_mode)
    write_text(trace_summary_txt, formatted_trace_summary)

    if trace_summary.get("has_effective_difference"):
        scenario = build_trace_scenario(
            analysis_root=analysis_root,
            coordinate=coordinate,
            baseline_version=args.baseline_version,
            target_version=args.target_version,
            baseline_command=baseline_result.command_str(),
            target_command=target_result.command_str(),
            baseline_execution_observation=baseline_observation["observation"],
            target_execution_observation=target_observation["observation"],
            dependency_tree_diff=dependency_tree_diff,
            baseline_trace=baseline_trace,
            target_trace=target_trace,
            trace_summary_path=trace_summary_txt,
            trace_summary_text=formatted_trace_summary,
            has_difference=True,
            trace_summary=trace_summary,
            cve_id=args.cve_id,
            description=args.description,
            compare_url=args.compare_url,
        )
        write_json(analysis_root / "llm-scenario.json", scenario)
        maybe_run_llm(args, analysis_root, scenario, "llm-hunk-analysis.md")
        print("Effective trace difference detected.")
        print("Trace summary: {}".format(trace_summary_txt))
        print("Artifact diff: {}".format(artifact_diff.root))
        return 0

    scenario = build_trace_scenario(
        analysis_root=analysis_root,
        coordinate=coordinate,
        baseline_version=args.baseline_version,
        target_version=args.target_version,
        baseline_command=baseline_result.command_str(),
        target_command=target_result.command_str(),
        baseline_execution_observation=baseline_observation["observation"],
        target_execution_observation=target_observation["observation"],
        dependency_tree_diff=dependency_tree_diff,
        baseline_trace=baseline_trace,
        target_trace=target_trace,
        trace_summary_path=trace_summary_txt,
        trace_summary_text=formatted_trace_summary,
        has_difference=False,
        trace_summary=trace_summary,
        cve_id=args.cve_id,
        description=args.description,
        compare_url=args.compare_url,
    )
    write_json(analysis_root / "llm-scenario.json", scenario)

    if trace_summary.get("has_difference") and not trace_summary.get("has_effective_difference"):
        invalid_reasons = ", ".join(trace_summary.get("trace_invalid_reasons") or []) or "unknown_invalid_trace_reason"
        print("Raw trace difference was filtered as invalid evidence: {}".format(invalid_reasons))

    if baseline_observation["observation"] != "success" or target_observation["observation"] != "success":
        print("Trace capture completed in observe-only mode without sequence differences.")
        print("Baseline observation: {}".format(baseline_observation["observation"]))
        print("Target observation: {}".format(target_observation["observation"]))
    elif args.compat_replay_target:
        print("Target version replayed successfully on the target dependency classpath, and no trace difference was detected.")
    else:
        print("Target version compiled and ran successfully, and no trace difference was detected.")
    print("Trace summary: {}".format(trace_summary_txt))
    print("Artifact diff: {}".format(artifact_diff.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
