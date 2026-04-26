#!/usr/bin/env python3

import argparse
import concurrent.futures
import datetime as datetime_module
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional

from target_paths import default_demo_target_root


SELECTION_MODES = ("compile-false", "seek-patch-false", "seek-patch-true")
TIMEOUT_EXIT_CODE = 124


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch-run difftrace demo cases selected from cve_list.json.")
    parser.add_argument("--cve-list", required=True, help="Path to dataset/list/cve_list.json")
    parser.add_argument(
        "--exploit-root",
        action="append",
        default=[],
        help="Exploit 根目录，可重复传入。默认自动搜索 Vision 和 Origin。",
    )
    parser.add_argument("--output-root", help="Output root. Default depends on --selection-mode under the shared demo target root")
    parser.add_argument("--result-json", help="Aggregated result JSON path. Default: <dataset>/trace_diff.json for seek-patch-false, otherwise <output-root>/batch-summary.json")
    parser.add_argument("--version-property", default="target.library.version", help="Maven version property used in generated workspaces.")
    parser.add_argument("--trace-packages", help="Optional trace package prefixes passed to all cases.")
    parser.add_argument("--java-version", help="Optional Java source/target override.")
    parser.add_argument("--maven-bin", default="mvn", help="Maven binary. Default: mvn")
    parser.add_argument("--max-workers", type=int, default=16, help="Number of concurrent CVE worker partitions. Default: 16")
    parser.add_argument("--timeout-seconds", type=int, default=3600, help="Maximum wall-clock time for each case. Default: 3600")
    parser.add_argument("--selection-mode", choices=SELECTION_MODES, default="compile-false", help="Case selection rule. Default: compile-false")
    parser.add_argument("--limit", type=int, help="Optional maximum number of cases to schedule.")
    parser.add_argument("--only-cve", action="append", default=[], help="Only run the specified CVE id. Can be repeated.")
    parser.add_argument("--resume", action="store_true", help="Skip cases whose result JSON already exists.")
    parser.add_argument("--force", action="store_true", help="Force rerun existing cases.")
    parser.add_argument(
        "--continue-latest-run",
        action="store_true",
        help="从 batch-status.jsonl 推断最新一次中断运行，只补跑尚未完成的 case，并沿用其进度计数。",
    )
    return parser.parse_args()


def demo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def default_exploit_roots() -> List[pathlib.Path]:
    code_root = demo_root().parent.parent
    return [
        code_root / "PoCEmpirical" / "reproduce" / "Exploits" / "Vision",
        code_root / "PoCEmpirical" / "reproduce" / "Exploits" / "Origin",
    ]


def resolve_exploit_roots(raw_roots: Iterable[str]) -> List[pathlib.Path]:
    roots = [pathlib.Path(value).expanduser().resolve() for value in raw_roots if value]
    return roots or default_exploit_roots()


def default_output_root(selection_mode: str) -> pathlib.Path:
    base_target_root = default_demo_target_root()
    if selection_mode == "seek-patch-false":
        return base_target_root / "seek-patch-false-results"
    return base_target_root / "batch-results"


def default_result_json(cve_list_path: pathlib.Path, output_root: pathlib.Path, selection_mode: str) -> pathlib.Path:
    if selection_mode == "seek-patch-false":
        return cve_list_path.parent.parent / "trace_diff.json"
    return output_root / "batch-summary.json"


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


def coerce_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def load_latest_run_state(status_jsonl_path: pathlib.Path) -> Optional[Dict[str, object]]:
    if not status_jsonl_path.exists():
        return None

    latest_run: List[Dict[str, object]] = []
    current_run: List[Dict[str, object]] = []
    for raw_line in read_text(status_jsonl_path).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        try:
            progress_index = int(entry.get("progress_index") or 0)
        except (TypeError, ValueError):
            progress_index = 0

        if progress_index == 1:
            current_run = [entry]
            latest_run = current_run
            continue

        if not current_run:
            continue

        current_run.append(entry)
        latest_run = current_run

    if not latest_run:
        return None

    completed_case_ids: List[str] = []
    seen_case_ids = set()
    progress_total = 0
    for entry in latest_run:
        case_id = str(entry.get("case_id") or "").strip()
        if case_id and case_id not in seen_case_ids:
            completed_case_ids.append(case_id)
            seen_case_ids.add(case_id)
        try:
            progress_total = max(progress_total, int(entry.get("progress_total") or 0))
        except (TypeError, ValueError):
            continue

    return {
        "completed_case_ids": completed_case_ids,
        "completed_count": len(completed_case_ids),
        "progress_total": progress_total or len(completed_case_ids),
    }


def slugify(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def make_case_id(cve_id: str, pair: Dict[str, object], pair_index: int) -> str:
    left = slugify(str(pair.get("appears") or pair.get("BASE_TAG") or f"pair{pair_index}"))
    right = slugify(str(pair.get("not appears") or pair.get("HEAD_TAG") or f"pair{pair_index}"))
    return f"{cve_id}__{pair_index:02d}__{left}__{right}"


def pair_matches_selection(pair: Dict[str, object], selection_mode: str) -> bool:
    if selection_mode == "compile-false":
        return pair.get("compile") is False
    if selection_mode == "seek-patch-false":
        return pair.get("seek_patch") is False
    if selection_mode == "seek-patch-true":
        return pair.get("seek_patch") is True
    raise ValueError(f"Unsupported selection mode: {selection_mode}")


def enumerate_selected_cases(cve_list_path: pathlib.Path, only_cves: Iterable[str], selection_mode: str) -> List[Dict[str, object]]:
    dataset = read_json(cve_list_path)
    allowed = set(only_cves)
    cases: List[Dict[str, object]] = []
    for cve_id, cve_entry in sorted(dataset.items()):
        if allowed and cve_id not in allowed:
            continue
        for pair_index, pair in enumerate(cve_entry.get("version_pair", [])):
            if not pair_matches_selection(pair, selection_mode):
                continue
            cases.append({
                "cve_id": cve_id,
                "pair_index": pair_index,
                "pair": pair,
                "case_id": make_case_id(cve_id, pair, pair_index),
                "owner": cve_entry.get("OWNER"),
                "repo": cve_entry.get("REPO"),
                "description": cve_entry.get("description"),
            })
    return cases


def case_root_for_case(output_root: pathlib.Path, case_id: str) -> pathlib.Path:
    return output_root / "cases" / case_id


def result_path_for_case(output_root: pathlib.Path, case_id: str) -> pathlib.Path:
    return case_root_for_case(output_root, case_id) / "case-result.json"


def driver_meta_path_for_case(output_root: pathlib.Path, case_id: str) -> pathlib.Path:
    return case_root_for_case(output_root, case_id) / "driver-run.json"


def analysis_dir_for_case(output_root: pathlib.Path, case_id: str) -> pathlib.Path:
    return case_root_for_case(output_root, case_id) / "analysis"


def partition_work_items_by_cve(work_items: List[Dict[str, object]], max_workers: int) -> List[List[Dict[str, object]]]:
    if not work_items:
        return []

    cve_groups: Dict[str, List[Dict[str, object]]] = {}
    for item in work_items:
        case = item["case"]
        cve_id = str(case["cve_id"])
        cve_groups.setdefault(cve_id, []).append(item)

    worker_count = min(max(1, max_workers), len(cve_groups))
    partitions: List[List[Dict[str, object]]] = [[] for _ in range(worker_count)]
    partition_sizes = [0] * worker_count

    for _cve_id, group in sorted(cve_groups.items(), key=lambda entry: (-len(entry[1]), entry[0])):
        target_index = min(range(worker_count), key=lambda index: (partition_sizes[index], index))
        partitions[target_index].extend(group)
        partition_sizes[target_index] += len(group)

    return [partition for partition in partitions if partition]


def run_partition(work_items: List[Dict[str, object]], timeout_seconds: int, worker_label: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for item in work_items:
        case = item["case"]
        print(f"[{worker_label}] start CVE={case['cve_id']} case={case['case_id']}", flush=True)
        results.append({
            "case": case,
            "run_result": run_case(item["command"], timeout_seconds),
        })
    return results


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        return
    process.wait(timeout=5)


def run_case(command: List[str], timeout_seconds: int) -> Dict[str, object]:
    started_at = datetime_module.datetime.now().isoformat(timespec="seconds")
    start_monotonic = time.monotonic()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=(os.name != "nt"),
    )

    timed_out = False
    output = ""
    try:
        stdout, _ = process.communicate(timeout=timeout_seconds)
        output = coerce_text(stdout)
        returncode = process.returncode
    except subprocess.TimeoutExpired as error:
        timed_out = True
        output = coerce_text(error.stdout)
        terminate_process(process)
        try:
            remaining_stdout, _ = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            remaining_stdout = ""
        output += coerce_text(remaining_stdout)
        returncode = TIMEOUT_EXIT_CODE

    duration_seconds = round(time.monotonic() - start_monotonic, 3)
    finished_at = datetime_module.datetime.now().isoformat(timespec="seconds")
    return {
        "returncode": returncode,
        "output": output,
        "command": command,
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "duration_seconds": duration_seconds,
        "started_at": started_at,
        "finished_at": finished_at,
    }


def build_placeholder_result(case: Dict[str, object], output_root: pathlib.Path, run_result: Dict[str, object], driver_output_path: pathlib.Path) -> Dict[str, object]:
    pair = case["pair"]
    timed_out = bool(run_result.get("timed_out"))
    status = "timeout" if timed_out else "runner_error"
    return {
        "case_id": case["case_id"],
        "cve_id": case["cve_id"],
        "pair_index": case["pair_index"],
        "owner": case.get("owner"),
        "repo": case.get("repo"),
        "description": case.get("description"),
        "artifact": None,
        "baseline_version": pair.get("appears"),
        "target_version": pair.get("not appears"),
        "observe_only_tests": True,
        "compat_replay_target": True,
        "appears": pair.get("appears"),
        "not_appears": pair.get("not appears"),
        "base_tag": pair.get("BASE_TAG"),
        "head_tag": pair.get("HEAD_TAG"),
        "compare_url": pair.get("COMPARE_URL"),
        "compile": pair.get("compile"),
        "seek_patch": pair.get("seek_patch"),
        "dataset_cause": str(pair.get("cause") or ""),
        "status": status,
        "failure_kind": status,
        "failure_subtype": status,
        "baseline_execution_observation": None,
        "target_execution_observation": None,
        "related_api_changes": [],
        "analysis_dir": str(analysis_dir_for_case(output_root, case["case_id"])),
        "workspace_dir": str(case_root_for_case(output_root, case["case_id"]) / "workspace" / case["case_id"]),
        "test_file": None,
        "driver_command": run_result.get("command"),
        "driver_exit_code": run_result.get("returncode"),
        "driver_output_path": str(driver_output_path),
        "trace_summary_path": str(analysis_dir_for_case(output_root, case["case_id"]) / "trace-diff-summary.json"),
        "api_change_summary_path": str(analysis_dir_for_case(output_root, case["case_id"]) / "version-diff" / "api-change-summary.json"),
        "failure_excerpt_path": None,
        "timed_out": timed_out,
        "timeout_seconds": run_result.get("timeout_seconds"),
        "duration_seconds": run_result.get("duration_seconds"),
        "started_at": run_result.get("started_at"),
        "completed_at": run_result.get("finished_at"),
    }


def ensure_case_result_exists(output_root: pathlib.Path, case: Dict[str, object], run_result: Dict[str, object], driver_output_path: pathlib.Path) -> pathlib.Path:
    result_path = result_path_for_case(output_root, case["case_id"])
    if result_path.exists():
        return result_path
    placeholder = build_placeholder_result(case, output_root, run_result, driver_output_path)
    write_json(result_path, placeholder)
    return result_path


def summarize_results(
    output_root: pathlib.Path,
    scheduled_cases: List[Dict[str, object]],
    selection_mode: str,
    cve_list_path: pathlib.Path,
    result_json_path: pathlib.Path,
    timeout_seconds: int,
) -> Dict[str, object]:
    summary = {
        "generated_at": datetime_module.datetime.now().isoformat(timespec="seconds"),
        "selection_mode": selection_mode,
        "cve_list_path": str(cve_list_path),
        "output_root": str(output_root),
        "result_json": str(result_json_path),
        "timeout_seconds": timeout_seconds,
        "total_cases": len(scheduled_cases),
        "completed_cases": 0,
        "timed_out_cases": 0,
        "trace_diff_cases": 0,
        "effective_trace_diff_cases": 0,
        "invalid_trace_diff_cases": 0,
        "by_status": {},
        "by_failure_subtype": {},
        "cases": [],
    }
    for case in scheduled_cases:
        result_path = result_path_for_case(output_root, case["case_id"])
        if not result_path.exists():
            continue

        result = read_json(result_path)
        status = result.get("status") or "unknown"
        subtype = result.get("failure_subtype") or "none"
        timed_out = bool(result.get("timed_out")) or status == "timeout"
        driver_meta_path = driver_meta_path_for_case(output_root, case["case_id"])
        driver_meta = read_json(driver_meta_path) if driver_meta_path.exists() else {}

        trace_summary = None
        trace_summary_path_value = result.get("trace_summary_path")
        if trace_summary_path_value:
            trace_summary_path = pathlib.Path(str(trace_summary_path_value))
            if trace_summary_path.exists():
                trace_summary = read_json(trace_summary_path)

        if timed_out:
            summary["timed_out_cases"] += 1
        if trace_summary and trace_summary.get("has_difference"):
            summary["trace_diff_cases"] += 1
            if trace_summary.get("has_effective_difference", trace_summary.get("has_difference")):
                summary["effective_trace_diff_cases"] += 1
            else:
                summary["invalid_trace_diff_cases"] += 1

        summary["completed_cases"] += 1
        summary["by_status"][status] = summary["by_status"].get(status, 0) + 1
        summary["by_failure_subtype"][subtype] = summary["by_failure_subtype"].get(subtype, 0) + 1
        summary["cases"].append({
            "case_id": result.get("case_id") or case["case_id"],
            "cve_id": result.get("cve_id") or case["cve_id"],
            "pair_index": result.get("pair_index", case["pair_index"]),
            "artifact": result.get("artifact"),
            "baseline_version": result.get("baseline_version") or case["pair"].get("appears"),
            "target_version": result.get("target_version") or case["pair"].get("not appears"),
            "compile": result.get("compile", case["pair"].get("compile")),
            "seek_patch": case["pair"].get("seek_patch"),
            "compare_url": result.get("compare_url") or case["pair"].get("COMPARE_URL"),
            "status": status,
            "failure_kind": result.get("failure_kind"),
            "failure_subtype": result.get("failure_subtype"),
            "baseline_execution_observation": result.get("baseline_execution_observation"),
            "target_execution_observation": result.get("target_execution_observation"),
            "driver_exit_code": result.get("driver_exit_code"),
            "timed_out": timed_out,
            "timeout_seconds": result.get("timeout_seconds") or driver_meta.get("timeout_seconds"),
            "duration_seconds": result.get("duration_seconds") or driver_meta.get("duration_seconds"),
            "started_at": result.get("started_at") or driver_meta.get("started_at"),
            "completed_at": result.get("completed_at") or driver_meta.get("finished_at"),
            "trace_has_difference": trace_summary.get("has_difference") if trace_summary else None,
            "trace_has_effective_difference": (
                trace_summary.get("has_effective_difference", trace_summary.get("has_difference")) if trace_summary else None
            ),
            "trace_evidence_valid": trace_summary.get("trace_evidence_valid") if trace_summary else None,
            "trace_invalid_reasons": trace_summary.get("trace_invalid_reasons") if trace_summary else None,
            "first_divergence_is_noise": trace_summary.get("first_divergence_is_noise") if trace_summary else None,
            "first_divergence": trace_summary.get("first_divergence") if trace_summary else None,
            "baseline_enter_count": trace_summary.get("baseline_enter_count") if trace_summary else None,
            "target_enter_count": trace_summary.get("target_enter_count") if trace_summary else None,
            "trace_summary_path": trace_summary_path_value,
            "analysis_dir": result.get("analysis_dir"),
            "result_path": str(result_path),
        })
    return summary


def main() -> int:
    args = parse_args()
    cve_list_path = pathlib.Path(args.cve_list).expanduser().resolve()
    exploit_roots = resolve_exploit_roots(args.exploit_root)
    output_root = pathlib.Path(args.output_root).expanduser().resolve() if args.output_root else default_output_root(args.selection_mode)
    result_json_path = pathlib.Path(args.result_json).expanduser().resolve() if args.result_json else default_result_json(cve_list_path, output_root, args.selection_mode)
    output_root.mkdir(parents=True, exist_ok=True)

    cases = enumerate_selected_cases(cve_list_path, args.only_cve, args.selection_mode)
    if args.limit is not None:
        cases = cases[: args.limit]

    run_case_script = pathlib.Path(__file__).resolve().parent / "run_case_analysis_runner_fix.py"
    status_jsonl_path = output_root / "batch-status.jsonl"
    run_logs_dir = output_root / "batch-driver-logs"
    run_logs_dir.mkdir(parents=True, exist_ok=True)

    continue_state = load_latest_run_state(status_jsonl_path) if args.continue_latest_run else None
    continue_mode_active = args.continue_latest_run and continue_state is not None
    continue_completed_case_ids = set()
    resumed_count = 0
    progress_base = 0
    progress_total = 0
    if args.continue_latest_run:
        if continue_state is None:
            print(
                f"Continue requested but no existing batch status found at {status_jsonl_path}; scheduling the full selection.",
                flush=True,
            )
        else:
            recorded_total = int(continue_state["progress_total"])
            if recorded_total and recorded_total != len(cases):
                raise SystemExit(
                    f"Latest recorded run total {recorded_total} does not match current selection {len(cases)}. "
                    f"Please rerun with matching filters or clear {status_jsonl_path}."
                )
            continue_completed_case_ids = {str(case_id) for case_id in continue_state["completed_case_ids"]}
            progress_base = int(continue_state["completed_count"])
            progress_total = recorded_total or len(cases)

    scheduled_cases: List[Dict[str, object]] = []
    work_items: List[Dict[str, object]] = []
    for case in cases:
        if continue_mode_active:
            if case["case_id"] in continue_completed_case_ids:
                scheduled_cases.append(case)
                resumed_count += 1
                continue
        else:
            existing_result = result_path_for_case(output_root, case["case_id"])
            if args.resume and existing_result.exists() and not args.force:
                scheduled_cases.append(case)
                resumed_count += 1
                continue

        command = [
            sys.executable,
            str(run_case_script),
            "--cve-list",
            str(cve_list_path),
            "--cve-id",
            case["cve_id"],
            "--pair-index",
            str(case["pair_index"]),
            "--output-root",
            str(output_root),
            "--version-property",
            args.version_property,
            "--maven-bin",
            args.maven_bin,
        ]
        for exploit_root in exploit_roots:
            command.extend(["--exploit-root", str(exploit_root)])
        if args.selection_mode != "compile-false":
            command.append("--allow-compile-true")
        if args.trace_packages:
            command.extend(["--trace-packages", args.trace_packages])
        if args.java_version:
            command.extend(["--java-version", args.java_version])
        if args.force or continue_mode_active:
            command.append("--force")

        work_items.append({
            "case": case,
            "command": command,
        })
        scheduled_cases.append(case)

    partitions = partition_work_items_by_cve(work_items, args.max_workers)
    worker_count = max(1, min(args.max_workers, len(partitions) or 1))
    total_scheduled = len(work_items)
    progress_total = progress_total if continue_mode_active else total_scheduled
    completed_count = progress_base if continue_mode_active else 0
    print(
        f"Batch start: total_selected={len(cases)} scheduled={total_scheduled} resumed={resumed_count} workers={worker_count} selection_mode={args.selection_mode}",
        flush=True,
    )
    if continue_mode_active:
        print(
            f"Continue mode: latest_completed={progress_base} remaining={total_scheduled} status_file={status_jsonl_path}",
            flush=True,
        )
    for index, partition in enumerate(partitions, start=1):
        cve_ids = sorted({str(item["case"]["cve_id"]) for item in partition})
        print(
            f"[worker-{index}] assigned_cases={len(partition)} assigned_cves={','.join(cve_ids)}",
            flush=True,
        )
    submitted: List[concurrent.futures.Future] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        for index, partition in enumerate(partitions, start=1):
            submitted.append(executor.submit(run_partition, partition, args.timeout_seconds, f"worker-{index}"))

        with status_jsonl_path.open("a", encoding="utf-8") as status_file:
            for future in concurrent.futures.as_completed(submitted):
                for partition_result in future.result():
                    case = partition_result["case"]
                    run_result = partition_result["run_result"]
                    completed_count += 1
                    log_path = run_logs_dir / f"{case['case_id']}.log"
                    log_path.write_text(run_result["output"], encoding="utf-8")
                    write_json(
                        driver_meta_path_for_case(output_root, case["case_id"]),
                        {
                            "case_id": case["case_id"],
                            "cve_id": case["cve_id"],
                            "pair_index": case["pair_index"],
                            "returncode": run_result["returncode"],
                            "timed_out": run_result["timed_out"],
                            "timeout_seconds": run_result["timeout_seconds"],
                            "duration_seconds": run_result["duration_seconds"],
                            "started_at": run_result["started_at"],
                            "finished_at": run_result["finished_at"],
                            "command": run_result["command"],
                            "driver_log": str(log_path),
                        },
                    )
                    ensure_case_result_exists(output_root, case, run_result, log_path)
                    status_entry = {
                        "case_id": case["case_id"],
                        "cve_id": case["cve_id"],
                        "pair_index": case["pair_index"],
                        "returncode": run_result["returncode"],
                        "timed_out": run_result["timed_out"],
                        "timeout_seconds": run_result["timeout_seconds"],
                        "duration_seconds": run_result["duration_seconds"],
                        "command": run_result["command"],
                        "driver_log": str(log_path),
                        "progress_index": completed_count,
                        "progress_total": progress_total,
                    }
                    status_file.write(json.dumps(status_entry, ensure_ascii=False) + "\n")
                    status_file.flush()
                    print(
                        f"[{completed_count}/{progress_total}] CVE={case['cve_id']} case={case['case_id']} "
                        f"returncode={run_result['returncode']} timed_out={run_result['timed_out']} "
                        f"duration={run_result['duration_seconds']}s log={log_path}",
                        flush=True,
                    )

    summary = summarize_results(
        output_root=output_root,
        scheduled_cases=scheduled_cases,
        selection_mode=args.selection_mode,
        cve_list_path=cve_list_path,
        result_json_path=result_json_path,
        timeout_seconds=args.timeout_seconds,
    )
    batch_summary_path = output_root / "batch-summary.json"
    write_json(batch_summary_path, summary)
    if result_json_path != batch_summary_path:
        write_json(result_json_path, summary)
    print(f"Batch summary: {batch_summary_path}", flush=True)
    if result_json_path != batch_summary_path:
        print(f"Result JSON: {result_json_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
