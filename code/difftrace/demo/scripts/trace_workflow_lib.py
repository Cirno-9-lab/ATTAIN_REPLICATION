#!/usr/bin/env python3

import difflib
import json
import pathlib
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as element_tree
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional


PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)\s*;", re.MULTILINE)
CLASS_RE = re.compile(r"\bpublic\s+(?:class|interface|enum)\s+([A-Za-z_]\w*)")
FALLBACK_CLASS_RE = re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_]\w*)")
IMPORT_RE = re.compile(r"^\s*import\s+(static\s+)?([A-Za-z_][\w.*]*)\s*;", re.MULTILINE)
TRACE_ENTER_RE = re.compile(r"^\d+\s+ENTER\s+\[[^\]]+\]\s+depth=\d+\s+(.+)$")
TRACE_META_RE = re.compile(r"^\d+\s+META\s+\[[^\]]+\]\s+([^=]+)=(.*)$")

EXCLUDED_IMPORT_PREFIXES = (
    "java.",
    "javax.",
    "jdk.",
    "sun.",
    "org.junit.",
    "junit.",
    "org.hamcrest.",
    "com.example.trace.",
)

TRACE_PACKAGE_ARTIFACT_FALLBACKS = {
    "org.springframework:spring-web": ["org.springframework.web"],
    "net.lingala.zip4j:zip4j": ["net.lingala.zip4j"],
    "com.fasterxml.jackson.datatype:jackson-datatype-jsr310": [
        "com.fasterxml.jackson.databind",
        "com.fasterxml.jackson.datatype.jsr310",
    ],
    "org.xwiki.commons:xwiki-commons-velocity": ["org.xwiki.velocity"],
    "org.jodd:jodd-http": ["jodd.http"],
    "com.nimbusds:nimbus-jose-jwt": ["com.nimbusds.jose"],
}

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


@dataclass
class TestContext:
    project_root: pathlib.Path
    test_file: pathlib.Path
    source: str
    test_selector: str
    trace_packages: str


@dataclass
class ArtifactCoordinate:
    group_id: str
    artifact_id: str
    packaging: str = "jar"

    def gav(self) -> str:
        return "{}:{}".format(self.group_id, self.artifact_id)


@dataclass
class CommandResult:
    command: List[str]
    cwd: pathlib.Path
    returncode: int
    output: str
    output_path: Optional[pathlib.Path]

    def command_str(self) -> str:
        return " ".join(shlex.quote(part) for part in self.command)


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def write_text(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: pathlib.Path, payload: object) -> None:
    write_text(path, json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


ISOLATED_MAVEN_USER_SETTINGS = """<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\"
          xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
          xsi:schemaLocation=\"http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd\">
  <profiles>
    <profile>
      <id>difftrace-central</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo.maven.apache.org/maven2</url>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>central</id>
          <url>https://repo.maven.apache.org/maven2</url>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>difftrace-central</activeProfile>
  </activeProfiles>
</settings>
"""

ISOLATED_MAVEN_GLOBAL_SETTINGS = """<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\"
          xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
          xsi:schemaLocation=\"http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd\">
</settings>
"""


def ensure_isolated_maven_settings(project_root: pathlib.Path) -> Dict[str, pathlib.Path]:
    settings_root = project_root / "target" / "difftrace-maven"
    user_settings = settings_root / "user-settings.xml"
    global_settings = settings_root / "global-settings.xml"

    if not user_settings.exists() or read_text(user_settings) != ISOLATED_MAVEN_USER_SETTINGS:
        write_text(user_settings, ISOLATED_MAVEN_USER_SETTINGS)
    if not global_settings.exists() or read_text(global_settings) != ISOLATED_MAVEN_GLOBAL_SETTINGS:
        write_text(global_settings, ISOLATED_MAVEN_GLOBAL_SETTINGS)

    return {
        "user": user_settings,
        "global": global_settings,
    }


def build_maven_command(
    project_root: pathlib.Path,
    maven_bin: str,
    arguments: List[str],
    force_update: bool = True,
) -> List[str]:
    settings = ensure_isolated_maven_settings(project_root)
    command = [maven_bin]
    if force_update:
        command.append("-U")
    command.extend([
        "-s",
        str(settings["user"]),
        "-gs",
        str(settings["global"]),
    ])
    command.extend(arguments)
    return command


def find_project_root(start: pathlib.Path) -> pathlib.Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pom.xml").exists():
            return candidate
    raise SystemExit("Unable to locate pom.xml from test path: {}".format(start))


def parse_test_selector(source: str, fallback_name: str) -> str:
    package_match = PACKAGE_RE.search(source)
    package_name = package_match.group(1) if package_match else ""

    class_match = CLASS_RE.search(source) or FALLBACK_CLASS_RE.search(source)
    if not class_match:
        raise SystemExit("Unable to determine the test class name from the exploit file.")

    class_name = class_match.group(1)
    if package_name:
        return package_name + "." + class_name
    return class_name or fallback_name


def normalize_import_to_package(import_name: str) -> str:
    normalized = import_name.strip()
    if normalized.endswith(".*"):
        normalized = normalized[:-2]

    parts = normalized.split(".")
    if len(parts) >= 2 and parts[-1] and parts[-1][0].isupper():
        parts = parts[:-1]
    elif len(parts) >= 3 and parts[-2] and parts[-2][0].isupper():
        parts = parts[:-2]

    return ".".join(parts)


def normalized_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def collapse_trace_packages(package_names: Iterable[str]) -> List[str]:
    collapsed: List[str] = []
    for package_name in sorted(set(package_names), key=lambda item: (item.count("."), len(item))):
        if any(package_name == existing or package_name.startswith(existing + ".") for existing in collapsed):
            continue
        collapsed = [existing for existing in collapsed if not existing.startswith(package_name + ".")]
        collapsed.append(package_name)
    return collapsed


def infer_trace_packages_from_artifact(artifact: Optional[str]) -> List[str]:
    if not artifact:
        return []

    normalized_artifact = artifact.strip()
    explicit = TRACE_PACKAGE_ARTIFACT_FALLBACKS.get(normalized_artifact)
    if explicit:
        return explicit

    if ":" not in normalized_artifact:
        return []

    group_id, artifact_id = normalized_artifact.split(":", 1)
    group_parts = [part for part in group_id.split(".") if part]
    if not group_parts:
        return []

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

    return [".".join(candidate_parts)] if candidate_parts else []


def infer_trace_packages(source: str, test_selector: str, artifact: Optional[str] = None) -> str:
    inferred = []
    test_package = test_selector.rsplit(".", 1)[0] if "." in test_selector else ""

    for _, import_name in IMPORT_RE.findall(source):
        if any(import_name.startswith(prefix) for prefix in EXCLUDED_IMPORT_PREFIXES):
            continue

        package_name = normalize_import_to_package(import_name)
        if not package_name:
            continue
        if test_package and (package_name == test_package or package_name.startswith(test_package + ".")):
            continue

        inferred.append(package_name)

    collapsed = collapse_trace_packages(inferred)
    if not collapsed:
        collapsed = collapse_trace_packages(infer_trace_packages_from_artifact(artifact))

    if not collapsed:
        raise SystemExit(
            "Unable to infer trace packages from imports. Please pass --trace-packages explicitly."
        )

    return ",".join(package_name.replace(".", "/") + "/" for package_name in collapsed)


def discover_test_context(test_file: pathlib.Path, trace_packages: Optional[str], artifact: Optional[str] = None) -> TestContext:
    resolved_test_file = test_file.expanduser().resolve()
    if not resolved_test_file.exists():
        raise SystemExit("Exploit/test file does not exist: {}".format(resolved_test_file))

    project_root = find_project_root(resolved_test_file.parent)
    source = read_text(resolved_test_file)
    test_selector = parse_test_selector(source, resolved_test_file.stem)
    selected_trace_packages = trace_packages or infer_trace_packages(source, test_selector, artifact=artifact)

    return TestContext(
        project_root=project_root,
        test_file=resolved_test_file,
        source=source,
        test_selector=test_selector,
        trace_packages=selected_trace_packages,
    )


def build_trace_output(project_root: pathlib.Path, test_selector: str, version: str, requested: Optional[str]) -> pathlib.Path:
    if requested:
        return pathlib.Path(requested).expanduser().resolve()

    safe_test_name = test_selector.replace(".", "_")
    return project_root / "target" / "dependency-trace" / "{}-{}.log".format(safe_test_name, version)


def run_command(command: List[str], cwd: pathlib.Path, output_path: Optional[pathlib.Path] = None) -> CommandResult:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    output = completed.stdout
    if output_path is not None:
        write_text(output_path, output)
    return CommandResult(
        command=command,
        cwd=cwd,
        returncode=completed.returncode,
        output=output,
        output_path=output_path,
    )


def reset_maven_build_outputs(project_root: pathlib.Path) -> None:
    target_root = project_root / "target"
    cleanup_paths = [
        target_root / "classes",
        target_root / "test-classes",
        target_root / "maven-status",
        target_root / "surefire-reports",
        target_root / "dependency-trace",
    ]

    for path in cleanup_paths:
        if path.is_dir():
            shutil.rmtree(str(path))
        elif path.exists():
            path.unlink()

    for jar_file in target_root.glob("*.jar"):
        if jar_file.is_file():
            jar_file.unlink()


def run_trace(
    context: TestContext,
    version: str,
    version_property: str,
    maven_bin: str,
    trace_output: pathlib.Path,
    log_output: Optional[pathlib.Path] = None,
    force_rebuild: bool = True,
    ignore_test_failures: bool = False,
) -> CommandResult:
    if force_rebuild:
        reset_maven_build_outputs(context.project_root)

    trace_output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        maven_bin,
        "-q",
        "-D{}={}".format(version_property, version),
        "-Ddependency.trace.output={}".format(str(trace_output)),
        "-Ddependency.trace.packages={}".format(context.trace_packages),
    ]
    if ignore_test_failures:
        command.append("-Dmaven.test.failure.ignore=true")
    command.extend([
        "-Dtest={}".format(context.test_selector),
        "test",
    ])
    return run_command(command, cwd=context.project_root, output_path=log_output)


def run_dependency_tree(
    project_root: pathlib.Path,
    version: str,
    version_property: str,
    maven_bin: str,
    output_path: pathlib.Path,
) -> CommandResult:
    command = build_maven_command(
        project_root,
        maven_bin,
        [
            "-q",
            "-D{}={}".format(version_property, version),
            "-DskipTests",
            "dependency:tree",
        ],
    )
    return run_command(command, cwd=project_root, output_path=output_path)


def classify_execution_failure(output: str) -> Optional[str]:
    lowered = output.lower()
    if "compilation error" in lowered:
        return "compile_failure"
    if "failed to execute goal" in lowered and (":compile" in lowered or ":testcompile" in lowered):
        return "compile_failure"
    if (
        "could not resolve dependencies" in lowered
        or "failed to collect dependencies" in lowered
        or "could not transfer artifact" in lowered
        or "could not find artifact" in lowered
    ):
        return "dependency_resolution_failure"
    if "there are test failures." in lowered or "failures!!!" in lowered or "tests run:" in lowered:
        return "test_failure"
    if "exception in thread \"main\"" in output or "caused by:" in lowered:
        return "runtime_failure"
    if "build failure" in lowered:
        return "build_failure"
    return None


def classify_maven_failure(output: str) -> Optional[str]:
    return classify_execution_failure(output)


def extract_error_excerpt(output: str, max_lines: int = 80) -> str:
    lines = output.splitlines()
    marker_indexes = []
    for index, line in enumerate(lines):
        if "COMPILATION ERROR" in line or line.startswith("[ERROR]") or "BUILD FAILURE" in line:
            marker_indexes.append(index)

    if not marker_indexes:
        return "\n".join(lines[-max_lines:])

    start = max(0, marker_indexes[0] - 3)
    end = min(len(lines), start + max_lines)
    return "\n".join(lines[start:end])


def extract_identifiers(text: str, limit: int = 12) -> List[str]:
    candidates = re.findall(r"[A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)+", text)
    simple = re.findall(r"\b[A-Z][A-Za-z0-9_$]{2,}\b", text)
    ordered = []
    for token in candidates + simple:
        if token not in ordered:
            ordered.append(token)
    return ordered[:limit]


def parse_trace_file(path: pathlib.Path) -> Dict[str, object]:
    enters = []
    meta: Dict[str, List[str]] = {}
    for raw_line in read_text(path).splitlines():
        enter_match = TRACE_ENTER_RE.match(raw_line)
        if enter_match:
            enters.append(enter_match.group(1))
            continue

        meta_match = TRACE_META_RE.match(raw_line)
        if meta_match:
            meta.setdefault(meta_match.group(1), []).append(meta_match.group(2))

    return {
        "path": str(path),
        "enters": enters,
        "unique_enters": list(dict.fromkeys(enters)),
        "meta": meta,
    }


TRACE_NOISE_MARKERS = ("internalloggerfactory",)


def _normalize_trace_symbol(value: object) -> str:
    return str(value or "").strip().replace("/", ".").replace("$", ".").lower()


def trace_invalid_reasons_from_summary(summary: Dict[str, object]) -> List[str]:
    reasons: List[str] = []
    baseline_enter_count = summary.get("baseline_enter_count")
    target_enter_count = summary.get("target_enter_count")
    try:
        baseline_enter_value = int(baseline_enter_count)
        target_enter_value = int(target_enter_count)
    except (TypeError, ValueError):
        baseline_enter_value = None
        target_enter_value = None

    if baseline_enter_value == 0 and target_enter_value == 0:
        reasons.append("empty_baseline_and_target_trace")

    first_divergence = summary.get("first_divergence") or {}
    if isinstance(first_divergence, dict):
        divergence_symbols = [
            _normalize_trace_symbol(first_divergence.get("baseline")),
            _normalize_trace_symbol(first_divergence.get("target")),
        ]
        if any(marker in symbol for symbol in divergence_symbols for marker in TRACE_NOISE_MARKERS):
            reasons.append("initialization_noise_internalloggerfactory")

        # Library-specific noise handling: for Netty HTTP codec, treat pure ByteBuf / EmbeddedChannel
        # divergences as compatibility noise rather than effective vulnerability evidence.
        artifact = str(summary.get("artifact") or "")
        if artifact == "io.netty:netty-codec-http":
            if all(
                symbol.startswith("io.netty.buffer.")
                or symbol.startswith("io.netty.channel.embedded.")
                for symbol in divergence_symbols
                if symbol
            ):
                reasons.append("netty_http_header_bytebuf_compat_noise")

    return reasons


def annotate_trace_summary(summary: Dict[str, object]) -> Dict[str, object]:
    annotated = dict(summary)
    invalid_reasons = trace_invalid_reasons_from_summary(annotated)
    raw_has_difference = bool(annotated.get("has_difference"))
    annotated["trace_invalid_reasons"] = invalid_reasons
    annotated["first_divergence_is_noise"] = "initialization_noise_internalloggerfactory" in invalid_reasons
    annotated["trace_evidence_valid"] = raw_has_difference and not invalid_reasons
    annotated["has_effective_difference"] = raw_has_difference and not invalid_reasons
    return annotated


def compare_trace_sequences(baseline_trace: pathlib.Path, target_trace: pathlib.Path) -> Dict[str, object]:
    baseline = parse_trace_file(baseline_trace)
    target = parse_trace_file(target_trace)

    baseline_enters = baseline["enters"]
    target_enters = target["enters"]
    first_divergence = None

    limit = min(len(baseline_enters), len(target_enters))
    for index in range(limit):
        if baseline_enters[index] != target_enters[index]:
            first_divergence = {
                "index": index,
                "baseline": baseline_enters[index],
                "target": target_enters[index],
            }
            break

    if first_divergence is None and len(baseline_enters) != len(target_enters):
        if len(baseline_enters) > len(target_enters):
            first_divergence = {
                "index": limit,
                "baseline": baseline_enters[limit],
                "target": "<trace ended>",
            }
        else:
            first_divergence = {
                "index": limit,
                "baseline": "<trace ended>",
                "target": target_enters[limit],
            }

    baseline_unique = baseline["unique_enters"]
    target_unique = target["unique_enters"]
    baseline_only = [entry for entry in baseline_unique if entry not in target_unique]
    target_only = [entry for entry in target_unique if entry not in baseline_unique]

    raw_summary = {
        "baseline_trace": str(baseline_trace),
        "target_trace": str(target_trace),
        "baseline_enter_count": len(baseline_enters),
        "target_enter_count": len(target_enters),
        "has_difference": first_divergence is not None or bool(baseline_only or target_only),
        "first_divergence": first_divergence,
        "baseline_only_unique": baseline_only[:50],
        "target_only_unique": target_only[:50],
        "baseline_meta": {key: values[-1] for key, values in baseline["meta"].items()},
        "target_meta": {key: values[-1] for key, values in target["meta"].items()},
    }
    return annotate_trace_summary(raw_summary)


def format_trace_comparison(summary: Dict[str, object]) -> str:
    lines = [
        "Baseline trace: {}".format(summary["baseline_trace"]),
        "Target trace: {}".format(summary["target_trace"]),
        "Baseline ENTER count: {}".format(summary["baseline_enter_count"]),
        "Target ENTER count: {}".format(summary["target_enter_count"]),
        "Has difference: {}".format(summary["has_difference"]),
        "Has effective difference: {}".format(summary.get("has_effective_difference", summary["has_difference"])),
        "Trace evidence valid: {}".format(summary.get("trace_evidence_valid", False)),
        "",
    ]
    invalid_reasons = summary.get("trace_invalid_reasons") or []
    if invalid_reasons:
        lines.append("Trace invalid reasons:")
        for reason in invalid_reasons:
            lines.append("  - {}".format(reason))
        lines.append("")
    divergence = summary["first_divergence"]
    if divergence:
        lines.extend([
            "First divergence:",
            "  index: {}".format(divergence["index"]),
            "  baseline: {}".format(divergence["baseline"]),
            "  target: {}".format(divergence["target"]),
            "",
        ])
    else:
        lines.append("First divergence: none")
        lines.append("")

    lines.append("Baseline-only unique calls:")
    for entry in summary["baseline_only_unique"]:
        lines.append("  - {}".format(entry))
    if not summary["baseline_only_unique"]:
        lines.append("  - none")
    lines.append("")

    lines.append("Target-only unique calls:")
    for entry in summary["target_only_unique"]:
        lines.append("  - {}".format(entry))
    if not summary["target_only_unique"]:
        lines.append("  - none")
    lines.append("")

    return "\n".join(lines)


def unified_diff_text(
    before_lines: Iterable[str],
    after_lines: Iterable[str],
    fromfile: str,
    tofile: str,
) -> str:
    before = [line.rstrip("\n") for line in before_lines]
    after = [line.rstrip("\n") for line in after_lines]
    diff_lines = list(
        difflib.unified_diff(
            before,
            after,
            fromfile=fromfile,
            tofile=tofile,
            lineterm="",
        )
    )
    if not diff_lines:
        return ""
    return "\n".join(diff_lines) + "\n"


def _pom_namespace(root: element_tree.Element) -> Dict[str, str]:
    if root.tag.startswith("{"):
        namespace = root.tag.split("}", 1)[0][1:]
        return {"m": namespace}
    return {}


def infer_version_bound_dependency(project_root: pathlib.Path, version_property: str) -> ArtifactCoordinate:
    pom_path = project_root / "pom.xml"
    root = element_tree.fromstring(read_text(pom_path))
    namespace = _pom_namespace(root)
    version_expression = "${" + version_property + "}"

    if namespace:
        dependencies = root.findall(".//m:dependencies/m:dependency", namespace)
        group_id_key = "m:groupId"
        artifact_id_key = "m:artifactId"
        version_key = "m:version"
    else:
        dependencies = root.findall(".//dependencies/dependency")
        group_id_key = "groupId"
        artifact_id_key = "artifactId"
        version_key = "version"

    matches = []
    for dependency in dependencies:
        version_node = dependency.find(version_key, namespace) if namespace else dependency.find(version_key)
        if version_node is None or (version_node.text or "").strip() != version_expression:
            continue

        group_node = dependency.find(group_id_key, namespace) if namespace else dependency.find(group_id_key)
        artifact_node = dependency.find(artifact_id_key, namespace) if namespace else dependency.find(artifact_id_key)
        if group_node is None or artifact_node is None:
            continue
        matches.append(
            ArtifactCoordinate(
                group_id=(group_node.text or "").strip(),
                artifact_id=(artifact_node.text or "").strip(),
            )
        )

    if not matches:
        raise SystemExit(
            "Unable to infer a dependency bound to property {} in pom.xml. Pass an explicit artifact override.".format(
                version_property
            )
        )
    if len(matches) > 1:
        raise SystemExit(
            "Multiple dependencies use property {} in pom.xml. Pass an explicit artifact override.".format(
                version_property
            )
        )
    return matches[0]


def parse_artifact_override(raw_value: str) -> ArtifactCoordinate:
    parts = raw_value.split(":")
    if len(parts) < 2:
        raise SystemExit("Artifact override must look like groupId:artifactId")
    return ArtifactCoordinate(group_id=parts[0], artifact_id=parts[1])


def dataclass_to_json(payload: object) -> Dict[str, object]:
    if hasattr(payload, "__dataclass_fields__"):
        result = asdict(payload)
        for key, value in list(result.items()):
            if isinstance(value, pathlib.Path):
                result[key] = str(value)
        return result
    raise TypeError("Expected dataclass payload")
