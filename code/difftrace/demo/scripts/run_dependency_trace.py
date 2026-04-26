#!/usr/bin/env python3

import sys

from trace_workflow_lib import build_trace_output, discover_test_context, run_trace


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        description="Run a Maven test PoC with the trace agent enabled."
    )
    parser.add_argument("version", help="Target dependency version to inject into the Maven property.")
    parser.add_argument("test_file", help="Path to the exploit/test Java file to run.")
    parser.add_argument(
        "--trace-packages",
        help="Comma-separated internal package prefixes to instrument, like io/socket/,org/apache/commons/collections/."
    )
    parser.add_argument(
        "--version-property",
        default="target.library.version",
        help="Maven property name that controls the target dependency version. Default: target.library.version"
    )
    parser.add_argument(
        "--maven-bin",
        default="mvn",
        help="Maven executable to use. Default: mvn"
    )
    parser.add_argument(
        "--trace-output",
        help="Optional explicit output path for the trace log."
    )
    return parser.parse_args()


def main() -> int:
    import pathlib

    args = parse_args()

    context = discover_test_context(pathlib.Path(args.test_file), args.trace_packages)
    trace_output = build_trace_output(context.project_root, context.test_selector, args.version, args.trace_output)

    print("Project root:", context.project_root)
    print("Exploit file:", context.test_file)
    print("Test selector:", context.test_selector)
    print("Version property:", args.version_property)
    print("Target version:", args.version)
    print("Trace packages:", context.trace_packages)
    print("Trace output:", trace_output)

    completed = run_trace(
        context=context,
        version=args.version,
        version_property=args.version_property,
        maven_bin=args.maven_bin,
        trace_output=trace_output,
    )
    if completed.returncode != 0:
        print(completed.output, end="")
        return completed.returncode

    print("Trace completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
