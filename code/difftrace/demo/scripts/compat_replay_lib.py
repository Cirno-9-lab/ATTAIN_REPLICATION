#!/usr/bin/env python3

import os
import pathlib
import shutil
from dataclasses import dataclass
from typing import Optional, Tuple

from target_paths import default_demo_target_root
from trace_workflow_lib import CommandResult, TestContext, build_maven_command, read_text, run_command


@dataclass
class CompatReplayLayout:
    root: pathlib.Path
    baseline_build_root: pathlib.Path
    baseline_classes_dir: pathlib.Path
    baseline_test_classes_dir: pathlib.Path
    compat_test_classes_dir: pathlib.Path
    target_classpath_file: pathlib.Path
    compat_plan_file: pathlib.Path
    classpath_log: pathlib.Path
    generator_log: pathlib.Path
    trace_agent_jar: pathlib.Path
    target_classpath: str


@dataclass
class CompatReplayPreparation:
    layout: CompatReplayLayout
    classpath_result: CommandResult
    generator_result: Optional[CommandResult]


def _copy_tree(source: pathlib.Path, destination: pathlib.Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def _copy_file(source: pathlib.Path, destination: pathlib.Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _find_trace_agent_jar(project_root: pathlib.Path, target_root: pathlib.Path) -> pathlib.Path:
    candidates = sorted(target_root.glob("*-trace-agent.jar"))
    if not candidates:
        difftrace_root = project_root / ".difftrace"
        candidates = sorted(difftrace_root.glob("*-trace-agent*.jar"))
    if not candidates:
        raise SystemExit(
            "Unable to locate the trace-agent jar under {} or {}".format(target_root, project_root / ".difftrace")
        )
    return candidates[0]


def snapshot_baseline_build_outputs(project_root: pathlib.Path, snapshot_root: pathlib.Path) -> Tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    target_root = project_root / "target"
    classes_dir = target_root / "classes"
    test_classes_dir = target_root / "test-classes"
    trace_agent_jar = _find_trace_agent_jar(project_root, target_root)

    if not test_classes_dir.is_dir():
        raise SystemExit("Baseline build did not produce target/test-classes: {}".format(test_classes_dir))

    snapshot_root.mkdir(parents=True, exist_ok=True)
    snapshot_classes_dir = snapshot_root / "classes"
    snapshot_test_classes_dir = snapshot_root / "test-classes"
    snapshot_trace_agent_jar = snapshot_root / trace_agent_jar.name

    if classes_dir.is_dir():
        _copy_tree(classes_dir, snapshot_classes_dir)
    else:
        snapshot_classes_dir.mkdir(parents=True, exist_ok=True)
    _copy_tree(test_classes_dir, snapshot_test_classes_dir)
    _copy_file(trace_agent_jar, snapshot_trace_agent_jar)
    return snapshot_classes_dir, snapshot_test_classes_dir, snapshot_trace_agent_jar


def resolve_tooling_classpath_entry() -> pathlib.Path:
    target_root = default_demo_target_root()
    fat_jar = target_root / "demo-1.0-SNAPSHOT-trace-agent-all.jar"
    if fat_jar.is_file():
        return fat_jar

    project_jar = target_root / "demo-1.0-SNAPSHOT.jar"
    if project_jar.is_file():
        return project_jar

    classes_dir = target_root / "classes"
    if not classes_dir.is_dir():
        raise SystemExit(
            "Compat replay tooling classes not found: {}. Run 'mvn -DskipTests package' in code/difftrace/demo first.".format(
                target_root
            )
        )
    return classes_dir


def build_target_test_classpath(
    project_root: pathlib.Path,
    version: str,
    version_property: str,
    maven_bin: str,
    classpath_output: pathlib.Path,
    log_output: pathlib.Path,
) -> CommandResult:
    classpath_output.parent.mkdir(parents=True, exist_ok=True)
    command = build_maven_command(
        project_root,
        maven_bin,
        [
            "-q",
            "-D{}={}".format(version_property, version),
            "-DskipTests",
            "-Dmdep.includeScope=test",
            "-Dmdep.pathSeparator={}".format(os.pathsep),
            "-Dmdep.outputFile={}".format(str(classpath_output)),
            "dependency:build-classpath",
        ],
    )
    return run_command(command, cwd=project_root, output_path=log_output)


def _join_classpath(*entries: str) -> str:
    return os.pathsep.join(entry for entry in entries if entry)


def prepare_compat_replay(
    context: TestContext,
    baseline_version: str,
    target_version: str,
    version_property: str,
    maven_bin: str,
    analysis_root: pathlib.Path,
) -> CompatReplayPreparation:
    compat_root = analysis_root / "compat-replay"
    if compat_root.exists():
        shutil.rmtree(compat_root)
    compat_root.mkdir(parents=True, exist_ok=True)

    baseline_build_root = compat_root / "baseline-build"
    baseline_classes_dir, baseline_test_classes_dir, trace_agent_jar = snapshot_baseline_build_outputs(
        context.project_root,
        baseline_build_root,
    )

    target_classpath_file = compat_root / "target-test-classpath.txt"
    classpath_log = compat_root / "target-classpath-maven.log"
    classpath_result = build_target_test_classpath(
        project_root=context.project_root,
        version=target_version,
        version_property=version_property,
        maven_bin=maven_bin,
        classpath_output=target_classpath_file,
        log_output=classpath_log,
    )
    target_classpath = read_text(target_classpath_file).strip() if target_classpath_file.exists() else ""
    layout = CompatReplayLayout(
        root=compat_root,
        baseline_build_root=baseline_build_root,
        baseline_classes_dir=baseline_classes_dir,
        baseline_test_classes_dir=baseline_test_classes_dir,
        compat_test_classes_dir=compat_root / "rewritten-test-classes",
        target_classpath_file=target_classpath_file,
        compat_plan_file=compat_root / "compat-plan.json",
        classpath_log=classpath_log,
        generator_log=compat_root / "compat-generator.log",
        trace_agent_jar=trace_agent_jar,
        target_classpath=target_classpath,
    )

    if classpath_result.returncode != 0:
        return CompatReplayPreparation(layout=layout, classpath_result=classpath_result, generator_result=None)

    baseline_classpath_file = compat_root / "baseline-test-classpath.txt"
    baseline_classpath_log = compat_root / "baseline-classpath-maven.log"
    baseline_classpath_result = build_target_test_classpath(
        project_root=context.project_root,
        version=baseline_version,
        version_property=version_property,
        maven_bin=maven_bin,
        classpath_output=baseline_classpath_file,
        log_output=baseline_classpath_log,
    )
    baseline_classpath = read_text(baseline_classpath_file).strip() if baseline_classpath_result.returncode == 0 and baseline_classpath_file.exists() else ""

    tooling_classpath_entry = resolve_tooling_classpath_entry()
    layout.compat_test_classes_dir.mkdir(parents=True, exist_ok=True)
    generator_classpath = _join_classpath(
        str(tooling_classpath_entry),
        str(layout.baseline_classes_dir),
        baseline_classpath,
        layout.target_classpath,
    )
    generator_command = [
        "java",
        "-cp",
        generator_classpath,
        "com.example.trace.compat.CompatReplayGenerator",
        "--baseline-main-root",
        str(layout.baseline_classes_dir),
        "--baseline-test-root",
        str(layout.baseline_test_classes_dir),
        "--compat-test-root",
        str(layout.compat_test_classes_dir),
        "--classpath-file",
        str(layout.target_classpath_file),
        "--test-selector",
        context.test_selector,
        "--plan-output",
        str(layout.compat_plan_file),
    ]
    generator_result = run_command(generator_command, cwd=context.project_root, output_path=layout.generator_log)
    return CompatReplayPreparation(layout=layout, classpath_result=classpath_result, generator_result=generator_result)


def run_compat_replay(
    context: TestContext,
    layout: CompatReplayLayout,
    version: str,
    version_property: str,
    trace_output: pathlib.Path,
    log_output: Optional[pathlib.Path] = None,
    ignore_test_failures: bool = False,
) -> CommandResult:
    trace_output.parent.mkdir(parents=True, exist_ok=True)
    tooling_classpath_entry = resolve_tooling_classpath_entry()
    runtime_classpath = _join_classpath(
        str(tooling_classpath_entry),
        str(layout.compat_test_classes_dir),
        str(layout.baseline_test_classes_dir),
        str(layout.baseline_classes_dir),
        layout.target_classpath,
    )
    command = [
        "java",
        "-Ddependency.trace.output={}".format(str(trace_output)),
        "-Ddependency.trace.packages={}".format(context.trace_packages),
        "-Ddifftrace.observe.only={}".format("true" if ignore_test_failures else "false"),
        "-D{}={}".format(version_property, version),
        "-javaagent:{}=output={};packages={}".format(
            str(layout.trace_agent_jar),
            str(trace_output),
            context.trace_packages,
        ),
        "-cp",
        runtime_classpath,
        "com.example.trace.compat.CompatJUnitRunner",
        context.test_selector,
    ]
    return run_command(command, cwd=context.project_root, output_path=log_output)
