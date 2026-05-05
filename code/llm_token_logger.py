import json
import time
from pathlib import Path
from typing import Any, Dict, Optional
from collections.abc import Mapping





def log_llm_usage(
    *,
    method: str,
    case_id: Optional[str],
    model: str,
    usage: Optional[Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Append a single LLM usage record to the JSONL log.

    - method: logical stage or script, e.g. "hunk_selection_round", "hunk_judgment", "vulnerability_judgment", "excel_refine".
    - case_id: best-effort identifier (may be empty string if unavailable).
    - model: model name used for this call.
    - usage: dict-like object with token information, typically containing
      prompt_tokens / completion_tokens / total_tokens or input_tokens / output_tokens.
    - extra: any additional metadata for later filtering, must be JSON-serializable.
    """
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If directory cannot be created, silently skip logging to avoid breaking main logic.
        return

    record: Dict[str, Any] = {
        "ts": time.time(),
        "method": method,
        "case_id": case_id or "",
        "model": model,
    }

    if usage:
        # Normalize usage to a dict-like object; autogen may return a RequestUsage object.
        if isinstance(usage, Mapping):
            u = usage
        else:
            u = {}
            for key in ("prompt_tokens", "input_tokens", "prompt_tokens_total"):
                val = getattr(usage, key, None)
                if val is not None:
                    u["prompt_tokens"] = val
                    break
            for key in ("completion_tokens", "output_tokens", "completion_tokens_total"):
                val = getattr(usage, key, None)
                if val is not None:
                    u["completion_tokens"] = val
                    break
            total_val = getattr(usage, "total_tokens", None)
            if total_val is not None:
                u["total_tokens"] = total_val

        # Be tolerant to different naming conventions.
        prompt_tokens = (
            u.get("prompt_tokens")
            or u.get("input_tokens")
            or u.get("prompt_tokens_total")
        )
        completion_tokens = (
            u.get("completion_tokens")
            or u.get("output_tokens")
            or u.get("completion_tokens_total")
        )
        total_tokens = u.get("total_tokens")
        if total_tokens is None and prompt_tokens is not None and completion_tokens is not None:
            try:
                total_tokens = int(prompt_tokens) + int(completion_tokens)
            except Exception:
                total_tokens = None

        record.update(
            {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            }
        )

    if extra:
        record["extra"] = extra

    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        # Logging must never crash the main program.
        return
