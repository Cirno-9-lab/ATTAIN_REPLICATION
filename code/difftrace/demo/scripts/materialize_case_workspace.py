#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import shutil
import sys
import xml.etree.ElementTree as element_tree
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple


CAUSE_ARTIFACT_RE = re.compile(
    r"(?:at|artifact)\s+([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\s]+)"
)
SKIP_INFER_ARTIFACTS = {
    ("junit", "junit"),
    ("org.ow2.asm", "asm"),
    ("org.ow2.asm", "asm-commons"),
    ("org.ow2.asm", "asm-tree"),
    ("org.slf4j", "slf4j-api"),
    ("org.slf4j", "slf4j-simple"),
    ("javax.servlet", "javax.servlet-api"),
    ("javax.activation", "activation"),
    ("org.springframework", "spring-test"),
}


@dataclass
class MaterializedCase:
    case_id: str
    workspace_dir: pathlib.Path
    project_root: pathlib.Path
    test_files: List[pathlib.Path]
    artifact: str
    baseline_version: str
    target_version: str
    version_property: str
    trace_packages: Optional[str]
    observe_only_tests: bool

    def to_json(self) -> Dict[str, object]:
        payload = asdict(self)
        for key, value in list(payload.items()):
            if isinstance(value, pathlib.Path):
                payload[key] = str(value)
            elif isinstance(value, list) and value and all(isinstance(item, pathlib.Path) for item in value):
                payload[key] = [str(item) for item in value]
        payload["test_file"] = payload["test_files"][0] if payload.get("test_files") else None
        return payload


@dataclass
class MavenCoordinate:
    group_id: str
    artifact_id: str

    def gav(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create an isolated Maven workspace for a difftrace exploit case.")
    parser.add_argument("--case-id", required=True, help="Stable case id used for workspace naming.")
    parser.add_argument("--exploit-demo", required=True, help="Path to the source exploit demo directory.")
    parser.add_argument("--workspace-root", required=True, help="Directory where the materialized workspace will be created.")
    parser.add_argument("--baseline-version", required=True, help="Known-working dependency version.")
    parser.add_argument("--target-version", required=True, help="Known-failing dependency version.")
    parser.add_argument("--version-property", default="target.library.version", help="Maven property used to inject versions.")
    parser.add_argument("--artifact", help="Optional target artifact in groupId:artifactId form.")
    parser.add_argument("--cause", help="Optional failure cause string from cve_list.json.")
    parser.add_argument("--test-file", help="Optional test file relative to exploit demo, e.g. src/test/java/com/example/AppTest.java")
    parser.add_argument("--trace-packages", help="Optional comma-separated trace package prefixes.")
    parser.add_argument("--java-version", help="Optional Java source/target version override.")
    parser.add_argument("--output-json", help="Optional path to write materialization metadata JSON.")
    parser.add_argument("--strict-tests", action="store_true", help="Preserve original JUnit failure semantics instead of observe-only trace capture.")
    parser.add_argument("--force", action="store_true", help="Delete the existing workspace before regenerating it.")
    return parser.parse_args()


def demo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def trace_source_root() -> pathlib.Path:
    return demo_root() / "src" / "main" / "java" / "com" / "example" / "trace"


def prebuilt_trace_agent_jar() -> pathlib.Path:
    target_dir = demo_root() / "target"
    fat_jar = target_dir / "demo-1.0-SNAPSHOT-trace-agent-all.jar"
    if fat_jar.is_file():
        return fat_jar
    return target_dir / "demo-1.0-SNAPSHOT-trace-agent.jar"


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def write_json(path: pathlib.Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def parse_artifact(raw_value: str) -> MavenCoordinate:
    parts = raw_value.split(":")
    if len(parts) < 2:
        raise SystemExit(f"Artifact must look like groupId:artifactId, got: {raw_value}")
    return MavenCoordinate(group_id=parts[0].strip(), artifact_id=parts[1].strip())


def infer_artifact_from_cause(cause: Optional[str]) -> Optional[MavenCoordinate]:
    if not cause:
        return None
    match = CAUSE_ARTIFACT_RE.search(cause)
    if not match:
        return None
    return MavenCoordinate(group_id=match.group(1), artifact_id=match.group(2))


def local_name(tag: str) -> str:
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


def pom_namespace(root: element_tree.Element) -> str:
    if root.tag.startswith("{"):
        return root.tag.split("}", 1)[0][1:]
    return ""


def qn(namespace: str, tag: str) -> str:
    return f"{{{namespace}}}{tag}" if namespace else tag


def find_child(parent: element_tree.Element, namespace: str, tag: str) -> Optional[element_tree.Element]:
    return parent.find(qn(namespace, tag))


def find_or_create_child(parent: element_tree.Element, namespace: str, tag: str) -> element_tree.Element:
    child = find_child(parent, namespace, tag)
    if child is None:
        child = element_tree.SubElement(parent, qn(namespace, tag))
    return child


def child_text(parent: element_tree.Element, namespace: str, tag: str) -> str:
    child = find_child(parent, namespace, tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def ensure_text(parent: element_tree.Element, namespace: str, tag: str, text: str) -> element_tree.Element:
    child = find_or_create_child(parent, namespace, tag)
    child.text = text
    return child


def find_dependency(dependencies: element_tree.Element, namespace: str, coordinate: MavenCoordinate) -> Optional[element_tree.Element]:
    for dependency in dependencies.findall(qn(namespace, "dependency")):
        group_id = child_text(dependency, namespace, "groupId")
        artifact_id = child_text(dependency, namespace, "artifactId")
        if group_id == coordinate.group_id and artifact_id == coordinate.artifact_id:
            return dependency
    return None


def collect_direct_dependency_candidates(pom_path: pathlib.Path) -> List[Tuple[MavenCoordinate, str]]:
    root = element_tree.fromstring(read_text(pom_path))
    namespace = pom_namespace(root)
    dependencies = find_child(root, namespace, "dependencies")
    if dependencies is None:
        return []

    direct_candidates: List[Tuple[MavenCoordinate, str]] = []
    for dependency in dependencies.findall(qn(namespace, "dependency")):
        group_id = child_text(dependency, namespace, "groupId")
        artifact_id = child_text(dependency, namespace, "artifactId")
        version = child_text(dependency, namespace, "version")
        scope = child_text(dependency, namespace, "scope")
        if not group_id or not artifact_id:
            continue
        if (group_id, artifact_id) in SKIP_INFER_ARTIFACTS:
            continue
        if scope in {"test", "provided"}:
            continue
        direct_candidates.append((MavenCoordinate(group_id=group_id, artifact_id=artifact_id), version))
    return direct_candidates


def infer_artifact_from_pom(
    pom_path: pathlib.Path,
    baseline_version: str = "",
    target_version: str = "",
) -> Optional[MavenCoordinate]:
    direct_candidates = collect_direct_dependency_candidates(pom_path)
    if len(direct_candidates) == 1:
        return direct_candidates[0][0]

    preferred_versions = {value for value in (baseline_version, target_version) if value}
    version_matches = [coordinate for coordinate, version in direct_candidates if version in preferred_versions]
    if len(version_matches) == 1:
        return version_matches[0]
    return None


def infer_test_files(project_root: pathlib.Path) -> List[pathlib.Path]:
    candidates = sorted(project_root.glob("src/test/java/**/*.java"))
    if not candidates:
        raise SystemExit(f"No Java test file found under {project_root / 'src/test/java'}")
    return candidates


def resolve_local_parent_pom(pom_path: pathlib.Path) -> Optional[Tuple[pathlib.Path, pathlib.Path]]:
    root = element_tree.fromstring(read_text(pom_path))
    namespace = pom_namespace(root)
    parent = find_child(root, namespace, "parent")
    if parent is None:
        return None

    relative_path_node = find_child(parent, namespace, "relativePath")
    if relative_path_node is None:
        relative_path = pathlib.Path("..") / "pom.xml"
    else:
        relative_text = (relative_path_node.text or "").strip()
        if not relative_text:
            return None
        relative_path = pathlib.Path(relative_text)

    candidate = pom_path.parent / relative_path
    if candidate.is_dir():
        relative_path = relative_path / "pom.xml"
        candidate = candidate / "pom.xml"
    candidate = candidate.resolve()
    if candidate == pom_path.resolve() or not candidate.is_file():
        return None
    return relative_path, candidate


def copy_local_parent_poms(source_pom: pathlib.Path, workspace_pom: pathlib.Path, workspace_root: pathlib.Path) -> None:
    current_source_pom = source_pom.resolve()
    current_workspace_pom = workspace_pom.resolve()
    seen = set()

    while True:
        resolved_parent = resolve_local_parent_pom(current_source_pom)
        if resolved_parent is None:
            return

        relative_path, source_parent_pom = resolved_parent
        if source_parent_pom in seen:
            return
        seen.add(source_parent_pom)

        workspace_parent_pom = (current_workspace_pom.parent / relative_path).resolve()
        try:
            workspace_parent_pom.relative_to(workspace_root)
        except ValueError:
            return

        workspace_parent_pom.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_parent_pom, workspace_parent_pom)
        current_source_pom = source_parent_pom
        current_workspace_pom = workspace_parent_pom


def recreate_workspace(source_demo: pathlib.Path, workspace_dir: pathlib.Path, force: bool) -> None:
    if workspace_dir.exists():
        if not force:
            raise SystemExit(f"Workspace already exists: {workspace_dir}. Pass --force to overwrite.")
        shutil.rmtree(workspace_dir)

    shutil.copytree(
        source_demo,
        workspace_dir,
        ignore=shutil.ignore_patterns("target", ".idea", "*.iml", ".DS_Store"),
    )


def copy_trace_runtime_sources(workspace_dir: pathlib.Path) -> None:
    target_dir = workspace_dir / "src" / "main" / "java" / "com" / "example" / "trace"
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(trace_source_root(), target_dir, dirs_exist_ok=True)


def prepare_trace_runtime(workspace_dir: pathlib.Path) -> Tuple[str, bool]:
    prebuilt_jar = prebuilt_trace_agent_jar()
    if prebuilt_jar.is_file():
        copied_jar = workspace_dir / ".difftrace" / prebuilt_jar.name
        copied_jar.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(prebuilt_jar, copied_jar)
        return "${project.basedir}/.difftrace/" + copied_jar.name, False

    copy_trace_runtime_sources(workspace_dir)
    return "${project.build.directory}/${project.build.finalName}-trace-agent.jar", True


def ensure_properties(root: element_tree.Element, namespace: str, version_property: str, trace_packages: Optional[str], java_version: Optional[str]) -> None:
    properties = find_or_create_child(root, namespace, "properties")
    if java_version:
        ensure_text(properties, namespace, "maven.compiler.source", java_version)
        ensure_text(properties, namespace, "maven.compiler.target", java_version)
    ensure_text(properties, namespace, version_property, "0.0.0-placeholder")
    ensure_text(properties, namespace, "dependency.trace.packages", trace_packages or "")
    ensure_text(
        properties,
        namespace,
        "dependency.trace.output",
        "${project.basedir}/target/dependency-trace/trace-${" + version_property + "}.log",
    )
    ensure_text(properties, namespace, "dependency.trace.agent.args", "output=${dependency.trace.output};packages=${dependency.trace.packages}")


def ensure_target_dependency(root: element_tree.Element, namespace: str, coordinate: MavenCoordinate, version_property: str) -> None:
    dependencies = find_or_create_child(root, namespace, "dependencies")
    dependency = find_dependency(dependencies, namespace, coordinate)
    if dependency is None:
        dependency = element_tree.SubElement(dependencies, qn(namespace, "dependency"))
        ensure_text(dependency, namespace, "groupId", coordinate.group_id)
        ensure_text(dependency, namespace, "artifactId", coordinate.artifact_id)
    ensure_text(dependency, namespace, "version", "${" + version_property + "}")


def ensure_support_dependency(root: element_tree.Element, namespace: str, group_id: str, artifact_id: str, version: str) -> None:
    dependencies = find_or_create_child(root, namespace, "dependencies")
    coordinate = MavenCoordinate(group_id=group_id, artifact_id=artifact_id)
    dependency = find_dependency(dependencies, namespace, coordinate)
    if dependency is None:
        dependency = element_tree.SubElement(dependencies, qn(namespace, "dependency"))
        ensure_text(dependency, namespace, "groupId", group_id)
        ensure_text(dependency, namespace, "artifactId", artifact_id)
    ensure_text(dependency, namespace, "version", version)


def ensure_compat_dependency_overrides(root: element_tree.Element, namespace: str, coordinate: MavenCoordinate) -> None:
    if coordinate.group_id == "org.apache.xmlgraphics" and coordinate.artifact_id.startswith("batik-"):
        ensure_support_dependency(root, namespace, "xml-apis", "xml-apis", "1.4.01")


def find_plugin(plugins: element_tree.Element, namespace: str, artifact_id: str, group_id: Optional[str] = None) -> Optional[element_tree.Element]:
    for plugin in plugins.findall(qn(namespace, "plugin")):
        plugin_artifact_id = child_text(plugin, namespace, "artifactId")
        plugin_group_id = child_text(plugin, namespace, "groupId")
        if plugin_artifact_id != artifact_id:
            continue
        if group_id is not None and plugin_group_id not in {"", group_id}:
            continue
        return plugin
    return None


def ensure_plugin(plugins: element_tree.Element, namespace: str, artifact_id: str, group_id: Optional[str] = None) -> element_tree.Element:
    plugin = find_plugin(plugins, namespace, artifact_id, group_id)
    if plugin is None:
        plugin = element_tree.SubElement(plugins, qn(namespace, "plugin"))
        if group_id:
            ensure_text(plugin, namespace, "groupId", group_id)
        ensure_text(plugin, namespace, "artifactId", artifact_id)
    return plugin


def ensure_trace_build(
    root: element_tree.Element,
    namespace: str,
    version_property: str,
    observe_only_tests: bool,
    trace_agent_jar_expr: str,
    package_trace_agent: bool,
) -> None:
    build = find_or_create_child(root, namespace, "build")
    plugins = find_or_create_child(build, namespace, "plugins")

    if package_trace_agent:
        jar_plugin = ensure_plugin(plugins, namespace, "maven-jar-plugin")
        executions = find_or_create_child(jar_plugin, namespace, "executions")
        trace_execution = None
        for execution in executions.findall(qn(namespace, "execution")):
            if child_text(execution, namespace, "id") == "trace-agent-jar":
                trace_execution = execution
                break
        if trace_execution is None:
            trace_execution = element_tree.SubElement(executions, qn(namespace, "execution"))
        ensure_text(trace_execution, namespace, "id", "trace-agent-jar")
        ensure_text(trace_execution, namespace, "phase", "process-classes")
        goals = find_or_create_child(trace_execution, namespace, "goals")
        goal_entries = [goal.text.strip() for goal in goals.findall(qn(namespace, "goal")) if goal.text]
        if "jar" not in goal_entries:
            goal = element_tree.SubElement(goals, qn(namespace, "goal"))
            goal.text = "jar"
        configuration = find_or_create_child(trace_execution, namespace, "configuration")
        ensure_text(configuration, namespace, "classifier", "trace-agent")
        archive = find_or_create_child(configuration, namespace, "archive")
        manifest_entries = find_or_create_child(archive, namespace, "manifestEntries")
        ensure_text(manifest_entries, namespace, "Premain-Class", "com.example.trace.DependencyTraceAgent")
        ensure_text(manifest_entries, namespace, "Can-Redefine-Classes", "false")
        ensure_text(manifest_entries, namespace, "Can-Retransform-Classes", "false")

    surefire_plugin = ensure_plugin(plugins, namespace, "maven-surefire-plugin")
    surefire_configuration = find_or_create_child(surefire_plugin, namespace, "configuration")
    ensure_text(
        surefire_configuration,
        namespace,
        "argLine",
        f"-javaagent:{trace_agent_jar_expr}=${{dependency.trace.agent.args}}",
    )
    ensure_text(surefire_configuration, namespace, "testFailureIgnore", "true" if observe_only_tests else "false")
    system_properties = find_or_create_child(surefire_configuration, namespace, "systemPropertyVariables")
    ensure_text(system_properties, namespace, "dependency.trace.output", "${dependency.trace.output}")
    ensure_text(system_properties, namespace, "dependency.trace.packages", "${dependency.trace.packages}")
    ensure_text(system_properties, namespace, version_property, "${" + version_property + "}")
    ensure_text(system_properties, namespace, "difftrace.observe.only", "true" if observe_only_tests else "false")


def patch_pom(
    pom_path: pathlib.Path,
    coordinate: MavenCoordinate,
    version_property: str,
    trace_packages: Optional[str],
    java_version: Optional[str],
    observe_only_tests: bool,
    trace_agent_jar_expr: str,
    package_trace_agent: bool,
) -> None:
    tree = element_tree.ElementTree(element_tree.fromstring(read_text(pom_path)))
    root = tree.getroot()
    namespace = pom_namespace(root)
    if namespace:
        element_tree.register_namespace("", namespace)

    ensure_properties(root, namespace, version_property, trace_packages, java_version)
    ensure_target_dependency(root, namespace, coordinate, version_property)
    if package_trace_agent:
        ensure_support_dependency(root, namespace, "org.ow2.asm", "asm", "9.9")
        ensure_support_dependency(root, namespace, "org.ow2.asm", "asm-commons", "9.9")
        ensure_support_dependency(root, namespace, "org.ow2.asm", "asm-tree", "9.9")
    ensure_compat_dependency_overrides(root, namespace, coordinate)
    ensure_trace_build(root, namespace, version_property, observe_only_tests, trace_agent_jar_expr, package_trace_agent)

    if hasattr(element_tree, "indent"):
        element_tree.indent(tree, space="  ")
    tree.write(pom_path, encoding="utf-8", xml_declaration=True)


NETTY_DECODER_RESULT_HELPER = """
    private static io.netty.handler.codec.DecoderResult decoderResultCompat(Object message) {
        try {
            return (io.netty.handler.codec.DecoderResult) message.getClass().getMethod(\"decoderResult\").invoke(message);
        } catch (NoSuchMethodException ignored) {
            try {
                return (io.netty.handler.codec.DecoderResult) message.getClass().getMethod(\"getDecoderResult\").invoke(message);
            } catch (ReflectiveOperationException inner) {
                throw new RuntimeException(inner);
            }
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
"""

NETTY_WRITE_CHAR_SEQUENCE_HELPER = """
    private static void writeCharSequenceCompat(io.netty.buffer.ByteBuf buffer, String value, java.nio.charset.Charset charset) {
        try {
            io.netty.buffer.ByteBuf.class.getMethod(\"writeCharSequence\", CharSequence.class, java.nio.charset.Charset.class)
                    .invoke(buffer, value, charset);
        } catch (NoSuchMethodException ignored) {
            buffer.writeBytes(value.getBytes(charset));
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
"""


def insert_helper_before_class_end(source_text: str, helper_source: str) -> str:
    if helper_source.strip() in source_text:
        return source_text
    trimmed = source_text.rstrip()
    closing_index = trimmed.rfind("}")
    if closing_index < 0:
        return source_text
    return trimmed[:closing_index].rstrip() + "\n" + helper_source.rstrip() + "\n}\n"


def adapt_netty_test_source(source_text: str) -> str:
    updated = source_text
    updated = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<type>[A-Za-z_][A-Za-z0-9_$.<>?]*)\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<channel>[A-Za-z_][A-Za-z0-9_]*)\.readInbound\(\);$",
        r"\g<indent>Object \g<var> = \g<channel>.readInbound();",
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.decoderResult\(\)",
        r"decoderResultCompat(\1)",
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.getDecoderResult\(\)",
        r"decoderResultCompat(\1)",
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.writeCharSequence\(",
        r"writeCharSequenceCompat(\1, ",
        updated,
    )

    if "decoderResultCompat(" in updated:
        updated = insert_helper_before_class_end(updated, NETTY_DECODER_RESULT_HELPER)
    if "writeCharSequenceCompat(" in updated:
        updated = insert_helper_before_class_end(updated, NETTY_WRITE_CHAR_SEQUENCE_HELPER)
    return updated


PACKAGE_DECLARATION_PLACEHOLDER = "__PACKAGE_DECLARATION__"
CLASS_NAME_PLACEHOLDER = "__CLASS_NAME__"

SPRING_SECURITY_ACTIVE_DIRECTORY_TEMPLATE = """
__PACKAGE_DECLARATION__

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class __CLASS_NAME__ {
    private Object provider;

    @Before
    public void setUp() {
        provider = instantiateAny(new Object[] {"mydomain.eu", "ldap://127.0.0.1/"},
                "org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider");
    }

    @Test(expected = BadCredentialsException.class, timeout = 2000)
    public void sec2500PreventAnonymousBind() {
        invoke(provider, "authenticate", new UsernamePasswordAuthenticationToken("rwinch", ""));
    }

    private static Object instantiateAny(Object[] constructorArgs, String... classNames) {
        RuntimeException lastFailure = null;
        for (String className : classNames) {
            try {
                Class<?> type = Class.forName(className);
                for (java.lang.reflect.Constructor<?> constructor : type.getConstructors()) {
                    if (constructor.getParameterCount() != constructorArgs.length) {
                        continue;
                    }
                    try {
                        return constructor.newInstance(constructorArgs);
                    } catch (IllegalArgumentException ignored) {
                        // try next constructor
                    }
                }
                lastFailure = new RuntimeException(new NoSuchMethodException(className));
            } catch (ReflectiveOperationException ex) {
                lastFailure = new RuntimeException(ex);
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new RuntimeException("Unable to instantiate Spring Security class");
    }

    private static Object invoke(Object target, String methodName, Object... args) {
        try {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                if (!method.getName().equals(methodName) || method.getParameterCount() != args.length) {
                    continue;
                }
                try {
                    return method.invoke(target, args);
                } catch (IllegalArgumentException ignored) {
                    // try next overload
                }
            }
            throw new NoSuchMethodException(methodName);
        } catch (java.lang.reflect.InvocationTargetException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RuntimeException(cause);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }
}
"""

SPRING_SECURITY_HTTP_FIREWALL_TEMPLATE = """
__PACKAGE_DECLARATION__

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class __CLASS_NAME__ {
    @Test
    public void getFirewalledRequestWhenLowercaseEncodedPathThenException() {
        Throwable thrown = null;
        try {
            Object firewall = instantiate("org.springframework.security.web.firewall.DefaultHttpFirewall");
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setRequestURI("/context-root/a/b;%2f1/c");
            request.setContextPath("/context-root");
            request.setServletPath("");
            request.setPathInfo("/a/b;/1/c");
            invoke(firewall, "getFirewalledRequest", request);
            fail("Expected RequestRejectedException");
        } catch (Throwable ex) {
            thrown = rootCause(ex);
        }
        assertTrue(thrown != null && thrown.getClass().getName().endsWith("RequestRejectedException"));
    }

    private static Object instantiate(String className) {
        try {
            return Class.forName(className).getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static Object invoke(Object target, String methodName, Object... args) {
        try {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                if (!method.getName().equals(methodName) || method.getParameterCount() != args.length) {
                    continue;
                }
                try {
                    return method.invoke(target, args);
                } catch (IllegalArgumentException ignored) {
                    // try next overload
                }
            }
            throw new NoSuchMethodException(methodName);
        } catch (java.lang.reflect.InvocationTargetException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RuntimeException(cause);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static Throwable rootCause(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }
}
"""

SPRING_SECURITY_JACKSON_TEMPLATE = r"""
__PACKAGE_DECLARATION__

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

public class __CLASS_NAME__ {
    private ObjectMapper mapper;

    @Before
    public void setup() {
        mapper = new ObjectMapper();
        invokeStatic("org.springframework.security.jackson2.SecurityJackson2Modules", "enableDefaultTyping", mapper);
    }

    @Test
    public void readValueWhenNotWhitelistedOrMappedThenThrowsException() {
        String content = "{\"@class\":\"edu.vision.se.__CLASS_NAME__$NotWhitelisted\",\"property\":\"bar\"}";
        try {
            mapper.readValue(content, Object.class);
            fail("Expected whitelist rejection");
        } catch (Throwable ex) {
            assertTrue(stackTraceAsString(ex).contains("whitelisted"));
        }
    }

    @Target({ ElementType.TYPE, ElementType.ANNOTATION_TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    @Documented
    public @interface NotJacksonAnnotation {
    }

    @NotJacksonAnnotation
    static class NotWhitelisted {
        private String property = "bar";

        public String getProperty() {
            return property;
        }

        public void setProperty(String property) {
        }
    }

    @JsonIgnoreType(false)
    static class NotWhitelistedButAnnotated {
        private String property = "bar";

        public String getProperty() {
            return property;
        }

        public void setProperty(String property) {
        }
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE, isGetterVisibility = JsonAutoDetect.Visibility.NONE)
    @JsonIgnoreProperties(ignoreUnknown = true)
    abstract class NotWhitelistedMixin {
    }

    private static String stackTraceAsString(Throwable throwable) {
        java.io.StringWriter writer = new java.io.StringWriter();
        throwable.printStackTrace(new java.io.PrintWriter(writer));
        return writer.toString();
    }

    private static Object invokeStatic(String className, String methodName, Object... args) {
        try {
            Class<?> type = Class.forName(className);
            for (java.lang.reflect.Method method : type.getMethods()) {
                if (!method.getName().equals(methodName) || method.getParameterCount() != args.length) {
                    continue;
                }
                try {
                    return method.invoke(null, args);
                } catch (IllegalArgumentException ignored) {
                    // try next overload
                }
            }
            throw new NoSuchMethodException(methodName);
        } catch (java.lang.reflect.InvocationTargetException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RuntimeException(cause);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }
}
"""

SPRING_SECURITY_PLAINTEXT_ENCODER_TEMPLATE = """
__PACKAGE_DECLARATION__

import org.junit.Test;

import static org.junit.Assert.assertFalse;

public class __CLASS_NAME__ {
    @Test
    public void testNull() {
        Object plaintextPasswordEncoder = instantiateAny(new Object[0],
                "org.springframework.security.authentication.encoding.PlaintextPasswordEncoder",
                "org.springframework.security.providers.encoding.PlaintextPasswordEncoder");
        boolean result = (Boolean) invoke(plaintextPasswordEncoder, "isPasswordValid", null, "null", null);
        assertFalse(result);
    }

    private static Object instantiateAny(Object[] constructorArgs, String... classNames) {
        RuntimeException lastFailure = null;
        for (String className : classNames) {
            try {
                Class<?> type = Class.forName(className);
                for (java.lang.reflect.Constructor<?> constructor : type.getConstructors()) {
                    if (constructor.getParameterCount() != constructorArgs.length) {
                        continue;
                    }
                    try {
                        return constructor.newInstance(constructorArgs);
                    } catch (IllegalArgumentException ignored) {
                        // try next constructor
                    }
                }
                lastFailure = new RuntimeException(new NoSuchMethodException(className));
            } catch (ReflectiveOperationException ex) {
                lastFailure = new RuntimeException(ex);
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new RuntimeException("Unable to instantiate Spring Security class");
    }

    private static Object invoke(Object target, String methodName, Object... args) {
        try {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                if (!method.getName().equals(methodName) || method.getParameterCount() != args.length) {
                    continue;
                }
                try {
                    return method.invoke(target, args);
                } catch (IllegalArgumentException ignored) {
                    // try next overload
                }
            }
            throw new NoSuchMethodException(methodName);
        } catch (java.lang.reflect.InvocationTargetException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RuntimeException(cause);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }
}
"""

SPRING_SECURITY_REGEX_MATCHER_TEMPLATE = r"""
__PACKAGE_DECLARATION__

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.assertTrue;

public class __CLASS_NAME__ {
    @Test
    public void matchesWithCarriageReturn() {
        Object matcher = instantiateAny(new Object[] {".*", null},
                "org.springframework.security.web.util.matcher.RegexRequestMatcher",
                "org.springframework.security.web.util.RegexRequestMatcher");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/blah%0a");
        request.setServletPath("/blah\n");
        assertTrue((Boolean) invoke(matcher, "matches", request));
    }

    @Test
    public void matchesWithLineFeed() {
        Object matcher = instantiateAny(new Object[] {".*", null},
                "org.springframework.security.web.util.matcher.RegexRequestMatcher",
                "org.springframework.security.web.util.RegexRequestMatcher");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/blah%0d");
        request.setServletPath("/blah\r");
        assertTrue((Boolean) invoke(matcher, "matches", request));
    }

    private static Object instantiateAny(Object[] constructorArgs, String... classNames) {
        RuntimeException lastFailure = null;
        for (String className : classNames) {
            try {
                Class<?> type = Class.forName(className);
                for (java.lang.reflect.Constructor<?> constructor : type.getConstructors()) {
                    if (constructor.getParameterCount() != constructorArgs.length) {
                        continue;
                    }
                    try {
                        return constructor.newInstance(constructorArgs);
                    } catch (IllegalArgumentException ignored) {
                        // try next constructor
                    }
                }
                lastFailure = new RuntimeException(new NoSuchMethodException(className));
            } catch (ReflectiveOperationException ex) {
                lastFailure = new RuntimeException(ex);
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new RuntimeException("Unable to instantiate Spring Security class");
    }

    private static Object invoke(Object target, String methodName, Object... args) {
        try {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                if (!method.getName().equals(methodName) || method.getParameterCount() != args.length) {
                    continue;
                }
                try {
                    return method.invoke(target, args);
                } catch (IllegalArgumentException ignored) {
                    // try next overload
                }
            }
            throw new NoSuchMethodException(methodName);
        } catch (java.lang.reflect.InvocationTargetException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RuntimeException(cause);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }
}
"""

SPRING_SECURITY_AUTHENTICATED_VOTER_TEMPLATE = """
__PACKAGE_DECLARATION__

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class __CLASS_NAME__ {
    @Test
    public void testAnonymousWorks() {
        Object voter = instantiateAny(new Object[0],
                "org.springframework.security.access.vote.AuthenticatedVoter",
                "org.springframework.security.vote.AuthenticatedVoter");
        Object anonymousMarker = readStaticFieldAny(
                new String[] {
                        "org.springframework.security.access.vote.AuthenticatedVoter",
                        "org.springframework.security.vote.AuthenticatedVoter"
                },
                "IS_AUTHENTICATED_ANONYMOUSLY");
        Object configAttribute = instantiateAny(new Object[] {anonymousMarker},
                "org.springframework.security.access.SecurityConfig",
                "org.springframework.security.SecurityConfig");
        Object definition = buildConfigDefinition(configAttribute);
        int result = ((Number) invoke(voter, "vote", null, null, definition)).intValue();
        int accessDenied = ((Number) readStaticFieldAny(
                new String[] {
                        "org.springframework.security.access.AccessDecisionVoter",
                        "org.springframework.security.vote.AccessDecisionVoter"
                },
                "ACCESS_DENIED")).intValue();
        assertEquals(accessDenied, result);
    }

    private static Object buildConfigDefinition(Object configAttribute) {
        try {
            Class<?> type = Class.forName("org.springframework.security.ConfigAttributeDefinition");
            return type.getConstructor(configAttribute.getClass().getInterfaces()[0]).newInstance(configAttribute);
        } catch (ClassNotFoundException ex) {
            return java.util.Collections.singletonList(configAttribute);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static Object instantiateAny(Object[] constructorArgs, String... classNames) {
        RuntimeException lastFailure = null;
        for (String className : classNames) {
            try {
                Class<?> type = Class.forName(className);
                for (java.lang.reflect.Constructor<?> constructor : type.getConstructors()) {
                    if (constructor.getParameterCount() != constructorArgs.length) {
                        continue;
                    }
                    try {
                        return constructor.newInstance(constructorArgs);
                    } catch (IllegalArgumentException ignored) {
                        // try next constructor
                    }
                }
                lastFailure = new RuntimeException(new NoSuchMethodException(className));
            } catch (ReflectiveOperationException ex) {
                lastFailure = new RuntimeException(ex);
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new RuntimeException("Unable to instantiate Spring Security class");
    }

    private static Object readStaticFieldAny(String[] classNames, String fieldName) {
        RuntimeException lastFailure = null;
        for (String className : classNames) {
            try {
                return Class.forName(className).getField(fieldName).get(null);
            } catch (ReflectiveOperationException ex) {
                lastFailure = new RuntimeException(ex);
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new RuntimeException("Unable to read Spring Security field");
    }

    private static Object invoke(Object target, String methodName, Object... args) {
        try {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                if (!method.getName().equals(methodName) || method.getParameterCount() != args.length) {
                    continue;
                }
                try {
                    return method.invoke(target, args);
                } catch (IllegalArgumentException ignored) {
                    // try next overload
                }
            }
            throw new NoSuchMethodException(methodName);
        } catch (java.lang.reflect.InvocationTargetException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RuntimeException(cause);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }
}
"""


def extract_package_declaration(source_text: str) -> str:
    match = re.search(r"(?m)^\s*package\s+[^;]+;\s*$", source_text)
    return match.group(0) if match else ""


def extract_primary_class_name(source_text: str) -> str:
    public_match = re.search(r"\bpublic\s+class\s+([A-Za-z_][A-Za-z0-9_]*)\b", source_text)
    if public_match:
        return public_match.group(1)
    fallback_match = re.search(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b", source_text)
    return fallback_match.group(1) if fallback_match else "Testcase1"


def render_compat_test_source(source_text: str, template: str) -> str:
    rendered = template.replace(PACKAGE_DECLARATION_PLACEHOLDER, extract_package_declaration(source_text))
    rendered = rendered.replace(CLASS_NAME_PLACEHOLDER, extract_primary_class_name(source_text))
    return rendered.lstrip()


def adapt_spring_security_test_source(source_text: str) -> str:
    if "ActiveDirectoryLdapAuthenticationProvider" in source_text:
        return render_compat_test_source(source_text, SPRING_SECURITY_ACTIVE_DIRECTORY_TEMPLATE)
    if "DefaultHttpFirewall" in source_text and "RequestRejectedException" in source_text:
        return render_compat_test_source(source_text, SPRING_SECURITY_HTTP_FIREWALL_TEMPLATE)
    if "SecurityJackson2Modules" in source_text:
        return render_compat_test_source(source_text, SPRING_SECURITY_JACKSON_TEMPLATE)
    if "PlaintextPasswordEncoder" in source_text:
        return render_compat_test_source(source_text, SPRING_SECURITY_PLAINTEXT_ENCODER_TEMPLATE)
    if "RegexRequestMatcher" in source_text:
        return render_compat_test_source(source_text, SPRING_SECURITY_REGEX_MATCHER_TEMPLATE)
    if "AuthenticatedVoter" in source_text and "SecurityConfig" in source_text:
        return render_compat_test_source(source_text, SPRING_SECURITY_AUTHENTICATED_VOTER_TEMPLATE)
    return source_text


REFLECTION_COMPAT_HELPERS = """
    private static Object instantiateAny(Object[] constructorArgs, String... classNames) {
        RuntimeException lastFailure = null;
        for (String className : classNames) {
            try {
                Class<?> type = Class.forName(className);
                for (java.lang.reflect.Constructor<?> constructor : type.getConstructors()) {
                    if (constructor.getParameterCount() != constructorArgs.length) {
                        continue;
                    }
                    try {
                        return constructor.newInstance(constructorArgs);
                    } catch (IllegalArgumentException ignored) {
                        // try next constructor
                    }
                }
                lastFailure = new RuntimeException(new NoSuchMethodException(className));
            } catch (ReflectiveOperationException ex) {
                lastFailure = new RuntimeException(ex);
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new RuntimeException("Unable to instantiate compatibility class");
    }

    private static Object invokeCompat(Object target, String methodName, Object... args) {
        try {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                if (!method.getName().equals(methodName) || method.getParameterCount() != args.length) {
                    continue;
                }
                try {
                    return method.invoke(target, args);
                } catch (IllegalArgumentException ignored) {
                    // try next overload
                }
            }
            throw new NoSuchMethodException(methodName);
        } catch (java.lang.reflect.InvocationTargetException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new RuntimeException(cause);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static Object invokeStaticAny(String[] classNames, String methodName, Object... args) {
        RuntimeException lastFailure = null;
        for (String className : classNames) {
            try {
                Class<?> type = Class.forName(className);
                for (java.lang.reflect.Method method : type.getMethods()) {
                    if (!method.getName().equals(methodName) || method.getParameterCount() != args.length) {
                        continue;
                    }
                    try {
                        return method.invoke(null, args);
                    } catch (IllegalArgumentException ignored) {
                        // try next overload
                    }
                }
                lastFailure = new RuntimeException(new NoSuchMethodException(className + "#" + methodName));
            } catch (ReflectiveOperationException ex) {
                lastFailure = new RuntimeException(ex);
            }
        }
        if (lastFailure != null) {
            throw lastFailure;
        }
        throw new RuntimeException("Unable to invoke compatibility static method");
    }

    private static boolean invokeBoolean(Object target, String methodName, Object... args) {
        return ((Boolean) invokeCompat(target, methodName, args)).booleanValue();
    }
"""

SPRING_WEB_JAVASCRIPT_UTILS_HELPER = r"""
    private static String javaScriptEscapeCompat(String input) {
        if (input == null) {
            return null;
        }

        StringBuilder escaped = new StringBuilder();
        for (int index = 0; index < input.length(); index++) {
            char ch = input.charAt(index);
            switch (ch) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case 0x27:
                    escaped.append("\\'");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '/':
                    escaped.append("\\/");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                case '\n':
                case '\r':
                    escaped.append("\\n");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case 0x0B:
                    escaped.append("\\v");
                    break;
                case '<':
                    escaped.append("\\u003C");
                    break;
                case '>':
                    escaped.append("\\u003E");
                    break;
                case '\u2028':
                    escaped.append("\\u2028");
                    break;
                case '\u2029':
                    escaped.append("\\u2029");
                    break;
                default:
                    escaped.append(ch);
                    break;
            }
        }
        return escaped.toString();
    }
"""

JACKSON_MODULE_COMPAT_HELPER = """
    private static com.fasterxml.jackson.databind.Module instantiateModuleCompat() {
        return (com.fasterxml.jackson.databind.Module) instantiateAny(
                new Object[0],
                "com.fasterxml.jackson.datatype.jsr310.JavaTimeModule",
                "com.fasterxml.jackson.datatype.jsr310.JSR310Module");
    }
"""

ZIP4J_COMPAT_HELPER = """
    private static Object newZipInputStreamCompat(java.io.InputStream inputStream) {
        return instantiateAny(
                new Object[] { inputStream },
                "net.lingala.zip4j.io.inputstream.ZipInputStream",
                "net.lingala.zip4j.io.ZipInputStream");
    }
"""

NIMBUS_PBES_COMPAT_HELPERS = """
    private static Object loadBouncyCastleProviderCompat() {
        return invokeStaticAny(
                new String[] {
                        "com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton",
                        "com.nimbusds.jose.crypto.BouncyCastleProviderSingleton"
                },
                "getInstance");
    }

    private static void setContentEncryptionProviderCompat(Object crypto, Object provider) {
        Object jcaContext = invokeCompat(crypto, "getJCAContext");
        invokeCompat(jcaContext, "setContentEncryptionProvider", provider);
    }

    private static com.nimbusds.jose.JOSEException unwrapJoseException(RuntimeException ex) {
        Throwable current = ex;
        while (current != null) {
            if (current instanceof com.nimbusds.jose.JOSEException) {
                return (com.nimbusds.jose.JOSEException) current;
            }
            current = current.getCause();
        }
        return null;
    }
"""


def remove_imports(source_text: str, imports_to_remove: List[str]) -> str:
    updated = source_text
    for import_name in imports_to_remove:
        updated = re.sub(
            rf"(?m)^\s*import\s+{re.escape(import_name)}\s*;\s*\n?",
            "",
            updated,
        )
    return updated


def prune_unused_non_static_imports(source_text: str) -> str:
    lines = source_text.splitlines()
    import_pattern = re.compile(r"^\s*import\s+(?!static\s)([A-Za-z0-9_.*]+)\s*;\s*$")
    kept_lines: List[str] = []
    body_text = "\n".join(line for line in lines if not import_pattern.match(line))

    for line in lines:
        match = import_pattern.match(line)
        if not match:
            kept_lines.append(line)
            continue

        imported_name = match.group(1)
        if imported_name.endswith(".*"):
            kept_lines.append(line)
            continue

        simple_name = imported_name.rsplit(".", 1)[-1]
        if re.search(rf"\b{re.escape(simple_name)}\b", body_text):
            kept_lines.append(line)

    updated = "\n".join(kept_lines)
    if source_text.endswith("\n"):
        updated += "\n"
    return updated


def rewrite_embedded_demo_paths(source_text: str, original_demo_root: pathlib.Path, workspace_dir: pathlib.Path) -> str:
    workspace_path = workspace_dir.as_posix()
    if not workspace_path:
        return source_text

    updated = source_text
    original_path = original_demo_root.as_posix()
    if original_path and original_path != workspace_path and original_path in updated:
        updated = updated.replace(original_path, workspace_path)

    case_dir_name = original_demo_root.parent.name if original_demo_root.name == "demo" else original_demo_root.name
    if case_dir_name:
        updated = re.sub(
            rf"/[^\"'\s]*/{re.escape(case_dir_name)}/demo",
            workspace_path,
            updated,
        )
    return updated


def adapt_spring_web_test_source(source_text: str) -> str:
    updated = remove_imports(source_text, ["org.springframework.web.util.JavaScriptUtils"])
    updated = updated.replace("JavaScriptUtils.javaScriptEscape(", "javaScriptEscapeCompat(")
    if "javaScriptEscapeCompat(" in updated:
        updated = insert_helper_before_class_end(updated, SPRING_WEB_JAVASCRIPT_UTILS_HELPER)
    return updated


def adapt_jackson_jsr310_source(source_text: str) -> str:
    updated = remove_imports(
        source_text,
        [
            "com.fasterxml.jackson.datatype.jsr310.JavaTimeModule",
            "com.fasterxml.jackson.datatype.jsr310.JSR310Module",
        ],
    )
    updated = re.sub(
        r"\bnew\s+(?:JavaTimeModule|JSR310Module)\s*\(\s*\)",
        "instantiateModuleCompat()",
        updated,
    )
    if "instantiateModuleCompat(" in updated:
        updated = insert_helper_before_class_end(updated, REFLECTION_COMPAT_HELPERS)
        updated = insert_helper_before_class_end(updated, JACKSON_MODULE_COMPAT_HELPER)
    return updated


def adapt_zip4j_test_source(source_text: str) -> str:
    updated = remove_imports(source_text, ["net.lingala.zip4j.io.inputstream.ZipInputStream"])
    updated = re.sub(
        r"\bZipInputStream\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+ZipInputStream\s*\(([^;]+)\);",
        r"Object \1 = newZipInputStreamCompat(\2);",
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.getNextEntry\s*\(\s*\)",
        r'invokeCompat(\1, "getNextEntry")',
        updated,
    )
    if "newZipInputStreamCompat(" in updated or "invokeCompat(" in updated:
        updated = insert_helper_before_class_end(updated, REFLECTION_COMPAT_HELPERS)
        updated = insert_helper_before_class_end(updated, ZIP4J_COMPAT_HELPER)
    return updated


def adapt_plexus_archiver_test_source(source_text: str) -> str:
    updated = remove_imports(source_text, ["org.codehaus.plexus.archiver.zip.ZipUnArchiver"])
    updated = re.sub(
        r"\bZipUnArchiver\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+ZipUnArchiver\s*\(([^;]+)\);",
        r'Object \1 = instantiateAny(new Object[0], "org.codehaus.plexus.archiver.zip.ZipUnArchiver");\n        invokeCompat(\1, "setSourceFile", \2);',
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.extract\s*\(\s*[^,;]+\s*,\s*([^;]+)\);",
        r'invokeCompat(\1, "setDestDirectory", \2);\n        invokeCompat(\1, "extract");',
        updated,
    )
    if "instantiateAny(" in updated or "invokeCompat(" in updated:
        updated = insert_helper_before_class_end(updated, REFLECTION_COMPAT_HELPERS)
    return updated


    updated = remove_imports(source_text, ["org.codehaus.plexus.archiver.zip.ZipUnArchiver"])
    updated = re.sub(
        r"\bZipUnArchiver\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+ZipUnArchiver\s*\(([^;]+)\);",
        r'Object \1 = instantiateAny(new Object[0], "org.codehaus.plexus.archiver.zip.ZipUnArchiver");\n        invokeCompat(\1, "setSourceFile", \2);',
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.extract\s*\(\s*[^,;]+\s*,\s*([^;]+)\);",
        r'invokeCompat(\1, "setDestDirectory", \2);\n        invokeCompat(\1, "extract");',
        updated,
    )
    if "instantiateAny(" in updated or "invokeCompat(" in updated:
        updated = insert_helper_before_class_end(updated, REFLECTION_COMPAT_HELPERS)
    return updated


def adapt_xwiki_velocity_test_source(source_text: str) -> str:
    updated = remove_imports(source_text, ["org.xwiki.velocity.introspection.SecureIntrospector"])
    updated = re.sub(
        r"\bSecureIntrospector\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+SecureIntrospector\s*\(([^;]+)\);",
        r'Object \1 = instantiateAny(new Object[] { \2 }, "org.xwiki.velocity.introspection.SecureIntrospector");',
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.checkObjectExecutePermission\s*\(",
        r'invokeBoolean(\1, "checkObjectExecutePermission", ',
        updated,
    )
    if "instantiateAny(" in updated or "invokeBoolean(" in updated:
        updated = insert_helper_before_class_end(updated, REFLECTION_COMPAT_HELPERS)
    return updated


def adapt_nimbus_test_source(source_text: str) -> str:
    updated = remove_imports(
        source_text,
        [
            "com.nimbusds.jose.crypto.PasswordBasedDecrypter",
            "com.nimbusds.jose.crypto.PasswordBasedEncrypter",
            "com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton",
            "com.nimbusds.jose.crypto.BouncyCastleProviderSingleton",
        ],
    )
    updated = re.sub(
        r"\bPasswordBasedEncrypter\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+PasswordBasedEncrypter\s*\(([^;]+)\);",
        r'Object \1 = instantiateAny(new Object[] { \2 }, "com.nimbusds.jose.crypto.PasswordBasedEncrypter");',
        updated,
    )
    updated = re.sub(
        r"\bPasswordBasedDecrypter\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+PasswordBasedDecrypter\s*\(([^;]+)\);",
        r'Object \1 = instantiateAny(new Object[] { \2 }, "com.nimbusds.jose.crypto.PasswordBasedDecrypter");',
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.getJCAContext\s*\(\s*\)\.setContentEncryptionProvider\s*\(\s*BouncyCastleProviderSingleton\.getInstance\s*\(\s*\)\s*\);",
        r"setContentEncryptionProviderCompat(\1, loadBouncyCastleProviderCompat());",
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.encrypt\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\);",
        r'invokeCompat(\1, "encrypt", \2);',
        updated,
    )
    updated = re.sub(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\.decrypt\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\);",
        r'invokeCompat(\1, "decrypt", \2);',
        updated,
    )
    updated = re.sub(
        r"catch\s*\(\s*JOSEException\s+([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{",
        r"catch (RuntimeException compatEx) {\n            JOSEException \1 = unwrapJoseException(compatEx);\n            if (\1 == null) {\n                throw compatEx;\n            }",
        updated,
    )
    if "instantiateAny(" in updated or "invokeCompat(" in updated or "loadBouncyCastleProviderCompat(" in updated:
        updated = insert_helper_before_class_end(updated, REFLECTION_COMPAT_HELPERS)
        updated = insert_helper_before_class_end(updated, NIMBUS_PBES_COMPAT_HELPERS)
    return updated


def adapt_source_for_compatibility(source_text: str, coordinate: MavenCoordinate, source_path: pathlib.Path) -> str:
    updated = source_text
    source_path_text = source_path.as_posix()
    is_test_source = "/src/test/java/" in source_path_text

    if coordinate.group_id == "io.netty" and is_test_source:
        updated = adapt_netty_test_source(updated)
    if coordinate.group_id == "org.springframework.security" and is_test_source:
        updated = adapt_spring_security_test_source(updated)
    if coordinate.group_id == "org.springframework" and coordinate.artifact_id == "spring-web" and is_test_source:
        updated = adapt_spring_web_test_source(updated)
    if coordinate.group_id == "com.fasterxml.jackson.datatype" and coordinate.artifact_id == "jackson-datatype-jsr310":
        updated = adapt_jackson_jsr310_source(updated)
    if coordinate.group_id == "net.lingala.zip4j" and coordinate.artifact_id == "zip4j" and is_test_source:
        updated = adapt_zip4j_test_source(updated)
    if coordinate.group_id == "org.codehaus.plexus" and coordinate.artifact_id == "plexus-archiver" and is_test_source:
        updated = adapt_plexus_archiver_test_source(updated)
    if coordinate.group_id == "org.xwiki.commons" and coordinate.artifact_id == "xwiki-commons-velocity" and is_test_source:
        updated = adapt_xwiki_velocity_test_source(updated)
    if coordinate.group_id == "com.nimbusds" and coordinate.artifact_id == "nimbus-jose-jwt" and is_test_source:
        updated = adapt_nimbus_test_source(updated)

    updated = prune_unused_non_static_imports(updated)
    return updated


def iter_java_source_files(project_root: pathlib.Path, test_files: List[pathlib.Path]) -> List[pathlib.Path]:
    ordered: List[pathlib.Path] = []
    seen = set()
    for candidate in sorted(project_root.glob("src/main/java/**/*.java")):
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            ordered.append(resolved)
    for candidate in sorted(project_root.glob("src/test/java/**/*.java")):
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            ordered.append(resolved)
    for candidate in test_files:
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            ordered.append(resolved)
    return ordered


def patch_java_sources_for_compatibility(
    project_root: pathlib.Path,
    test_files: List[pathlib.Path],
    coordinate: MavenCoordinate,
    original_demo_root: pathlib.Path,
    workspace_dir: pathlib.Path,
) -> None:
    java_files = iter_java_source_files(project_root, test_files)
    for java_file in java_files:
        original = read_text(java_file)
        updated = rewrite_embedded_demo_paths(original, original_demo_root, workspace_dir)
        updated = adapt_source_for_compatibility(updated, coordinate, java_file)
        if updated != original:
            java_file.write_text(updated, encoding="utf-8")


def materialize_case_workspace(
    case_id: str,
    exploit_demo: pathlib.Path,
    workspace_root: pathlib.Path,
    baseline_version: str,
    target_version: str,
    version_property: str = "target.library.version",
    artifact: Optional[str] = None,
    cause: Optional[str] = None,
    test_file: Optional[str] = None,
    trace_packages: Optional[str] = None,
    java_version: Optional[str] = None,
    observe_only_tests: bool = True,
    force: bool = False,
    output_json: Optional[pathlib.Path] = None,
) -> MaterializedCase:
    exploit_demo = exploit_demo.expanduser().resolve()
    workspace_root = workspace_root.expanduser().resolve()
    if not exploit_demo.exists():
        raise SystemExit(f"Exploit demo does not exist: {exploit_demo}")

    workspace_dir = workspace_root / case_id
    recreate_workspace(exploit_demo, workspace_dir, force=force)

    pom_path = workspace_dir / "pom.xml"
    if not pom_path.exists():
        raise SystemExit(f"pom.xml does not exist in materialized workspace: {pom_path}")

    copy_local_parent_poms(exploit_demo / "pom.xml", pom_path, workspace_root)
    trace_agent_jar_expr, package_trace_agent = prepare_trace_runtime(workspace_dir)

    coordinate = parse_artifact(artifact) if artifact else infer_artifact_from_cause(cause)
    if coordinate is None:
        coordinate = infer_artifact_from_pom(
            pom_path,
            baseline_version=baseline_version,
            target_version=target_version,
        )
    if coordinate is None:
        raise SystemExit("Unable to infer target artifact. Pass --artifact explicitly.")

    patch_pom(
        pom_path=pom_path,
        coordinate=coordinate,
        version_property=version_property,
        trace_packages=trace_packages,
        java_version=java_version,
        observe_only_tests=observe_only_tests,
        trace_agent_jar_expr=trace_agent_jar_expr,
        package_trace_agent=package_trace_agent,
    )

    resolved_test_files = [(workspace_dir / test_file).resolve()] if test_file else infer_test_files(workspace_dir)
    for resolved_test_file in resolved_test_files:
        if not resolved_test_file.exists():
            raise SystemExit(f"Resolved test file does not exist: {resolved_test_file}")
    patch_java_sources_for_compatibility(
        workspace_dir,
        resolved_test_files,
        coordinate,
        original_demo_root=exploit_demo,
        workspace_dir=workspace_dir,
    )

    result = MaterializedCase(
        case_id=case_id,
        workspace_dir=workspace_dir,
        project_root=workspace_dir,
        test_files=resolved_test_files,
        artifact=coordinate.gav(),
        baseline_version=baseline_version,
        target_version=target_version,
        version_property=version_property,
        trace_packages=trace_packages,
        observe_only_tests=observe_only_tests,
    )
    if output_json is not None:
        write_json(output_json, result.to_json())
    return result


def main() -> int:
    args = parse_args()
    result = materialize_case_workspace(
        case_id=args.case_id,
        exploit_demo=pathlib.Path(args.exploit_demo),
        workspace_root=pathlib.Path(args.workspace_root),
        baseline_version=args.baseline_version,
        target_version=args.target_version,
        version_property=args.version_property,
        artifact=args.artifact,
        cause=args.cause,
        test_file=args.test_file,
        trace_packages=args.trace_packages,
        java_version=args.java_version,
        observe_only_tests=not args.strict_tests,
        force=args.force,
        output_json=pathlib.Path(args.output_json).expanduser().resolve() if args.output_json else None,
    )
    json.dump(result.to_json(), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
