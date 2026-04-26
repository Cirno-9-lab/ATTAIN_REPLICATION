#!/usr/bin/env python3

import asyncio
import json
import pathlib
from typing import Any, Dict, List, Optional

from llm_hunk_selector import (  # type: ignore
    LLMAnalysisConfig,
    MAX_CODE_CONTEXT_RESULTS,
    MAX_KEYWORD_RESULTS,
    DEFAULT_READ_WINDOW,
    _effective_tool_round_budget,
    _truncate_inline_text,
    _truncate_multiline_text,
    _create_model_response,
    search_workspace,
    read_workspace_file,
    load_diff_context,
    search_code_context,
)


def _read_failure_excerpt(analysis_root: pathlib.Path, scenario: Dict[str, object]) -> str:
    """Load the failure excerpt text for this case.

    We first honor scenario["failure_excerpt_file"] when present; otherwise fall back to
    common filenames under the analysis root. The caller is responsible for truncation.
    """

    candidate = str(scenario.get("failure_excerpt_file") or "").strip()
    search_paths: List[pathlib.Path] = []
    if candidate:
        search_paths.append(analysis_root / candidate)
    # Fallbacks commonly used by the existing pipeline
    search_paths.append(analysis_root / "target-observation-excerpt.txt")
    search_paths.append(analysis_root / "baseline-observation-excerpt.txt")

    for path in search_paths:
        if path.exists() and path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            return _truncate_multiline_text(text, max_lines=40, max_chars=2000)
    return "(no failure excerpt was available for this case)"


def build_analysis_prompt_ab1(analysis_root: pathlib.Path, scenario: Dict[str, object]) -> str:
    """Build a failure-only analysis prompt for the ab1 pipeline.

    The prompt intentionally omits any trace-diff summary, version-diff overview, or
    dependency tree information. The only rich context provided is the failure excerpt,
    plus minimal high-level metadata so the model knows which artifact/version pair it
    is looking at.
    """

    failure_excerpt = _read_failure_excerpt(analysis_root, scenario)

    lines: List[str] = [
        "You are analyzing a single dependency version regression case.",
        "You only have access to the PoC's failure symptoms on this target version.",
        "No pre-computed trace-diff summary or version-diff overview is provided in this prompt.",
        "When you need code or diff context, you MUST call the provided tools (keyword_search, read_file, load_diff_context, search_code_context) yourself.",
        "",
        "Scenario (minimal metadata):",
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
        "",
        "Failure excerpt (target run):",
        _truncate_multiline_text(failure_excerpt, max_lines=40, max_chars=2000),
        "",
        "Your task:",
        "- Use the failure excerpt to infer which components are likely involved (e.g., classes, methods, configuration).",
        "- When you need details, call keyword_search/read_file/load_diff_context/search_code_context to inspect diff files or code.",
        "- Select a small set of high-signal diff hunks or fallback evidence items that best explain the failure.",
        "- Do not assume you know the patch location unless you have inspected the relevant diff or code via tools.",
        "",
        "Return markdown with exactly these sections:",
        "Diagnosis",
        "Selected Hunks",
        "Supporting Evidence",
        "Open Questions",
        "In Selected Hunks, prefer concrete diff file paths under version-diff/api-diffs or version-diff/diffs, each with a minimal raw diff excerpt.",
        "If no relevant concrete diff exists, you may instead cite a fallback evidence file (e.g., failure excerpt, dependency-tree.diff, execution-observations.json) and explain the limitation.",
        "",
    ]
    return "\n".join(lines)


async def run_llm_hunk_selection_ab1(
    analysis_root: pathlib.Path,
    scenario: Dict[str, object],
    output_path: pathlib.Path,
    config: LLMAnalysisConfig,
) -> None:
    """Failure-only variant of run_llm_hunk_selection.

    The tool set and round budget logic are identical to the baseline implementation,
    but the user prompt is restricted to the failure excerpt and minimal metadata.
    """

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
            "AutoGen imports failed for ab1 selector. Ensure the active environment provides autogen_core/autogen_ext "
            "compatible with llm_hunk_selector.py. Root cause: {}: {}".format(type(error).__name__, error)
        ) from error

    def keyword_search(keywords: str, limit: int = MAX_KEYWORD_RESULTS, path_glob: str = "**/*") -> str:
        return search_workspace(analysis_root, keywords=keywords, limit=limit, path_glob=path_glob)

    def read_file(path: str, start_line: int = 1, end_line: int = DEFAULT_READ_WINDOW) -> str:
        return read_workspace_file(analysis_root, path=path, start_line=start_line, end_line=end_line)

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
                "This is the ab1 failure-only setting: you should rely primarily on the failure excerpt "
                "and only call tools when you genuinely need code or diff context. "
                "This case has a hard tool budget of {} round(s); if the evidence is already clear, stop earlier.".format(
                    effective_max_rounds
                )
            )
        ),
        UserMessage(content=build_analysis_prompt_ab1(analysis_root, scenario), source="user"),
    ]

    transcript_lines: List[str] = [
        "[ab1] Configured max rounds: {}".format(config.max_rounds),
        "[ab1] Effective max rounds for this case: {}".format(effective_max_rounds),
        "",
    ]
    final_response: Optional[Any] = None

    try:
        for round_index in range(1, effective_max_rounds + 1):
            print(
                "[ab1][LLM] requesting round {}/{} for {}".format(round_index, effective_max_rounds, analysis_root),
                flush=True,
            )
            response = await _create_model_response(
                model_client,
                messages=messages,
                tools=[keyword_tool, read_file_tool, load_diff_context_tool, search_code_context_tool],
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
                    except Exception as tool_error:  # pragma: no cover - defensive
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
                "Reached the tool round limit ({}). Requesting a final answer without tools.".format(
                    effective_max_rounds
                )
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
            print("[ab1][LLM] requesting forced final answer for {}".format(analysis_root), flush=True)
            forced_response = await _create_model_response(model_client, messages=messages)
            final_response = forced_response.content
            transcript_lines.append("Final response:")
            transcript_lines.append(str(final_response))

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
    asyncio.run(run_llm_hunk_selection_ab1(analysis_root, scenario, output_path, config))
