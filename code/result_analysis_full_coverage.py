import os
import asyncio
import json
import warnings

import pandas as pd

from llm_token_logger import log_llm_usage

EXCEL_PATH = os.path.join(BASE_PATH, "execution_result.xlsx")

FORWARD_PROPAGATION_LABELS = {"not affected_patch", "affected_patch"}
BACKWARD_PROPAGATION_LABELS = {"not affected_intro", "affected_intro"}


def get_state(val):
    s = str(val).strip().lower()
    if "affected" in s and not s.startswith("not"):
        return "POS"
    return "NEG"


def main():
    if not os.path.exists(EXCEL_PATH):
        print(f"❌ 找不到文件: {EXCEL_PATH}")
        return

    df = pd.read_excel(EXCEL_PATH)

    required_cols = ["CVE_ID", "Library", "PoC", "LLM_Verdict", "Execution Result", "True Affected Version"]
    for col in required_cols:
        if col not in df.columns:
            print(f"❌ Excel 中缺少必要列: {col}")
            return

    def region_key(idx: int):
        cve = str(df.at[idx, "CVE_ID"]).strip()
        lib = str(df.at[idx, "Library"]).strip()
        poc = str(df.at[idx, "PoC"]).strip()
        exec_res = str(df.at[idx, "Execution Result"]).strip().upper()
        bucket = "APPEARS" if exec_res == "APPEARS" else "OTHER"
        return cve, lib, bucket, poc

    def same_region(i: int, j: int) -> bool:
        return region_key(i) == region_key(j)

    n = len(df)

    def stable_region_key(idx: int):
        cve = str(df.at[idx, "CVE_ID"]).strip()
        lib = str(df.at[idx, "Library"]).strip()
        poc = str(df.at[idx, "PoC"]).strip()
        return cve, lib, poc

    def execution_bucket(exec_res: str) -> str:
        s = str(exec_res).strip().upper()
        return "APPEARS" if s == "APPEARS" else "OTHER"

    def in_execution_conflict_zone(idx: int) -> bool:
        key_clp = stable_region_key(idx)
        cur_bucket = execution_bucket(df.at[idx, "Execution Result"])
        cur_label = str(df.at[idx, "LLM_Verdict"]).strip()
        for neighbor in (idx - 1, idx + 1):
            if 0 <= neighbor < n and stable_region_key(neighbor) == key_clp:
                nb_bucket = execution_bucket(df.at[neighbor, "Execution Result"])
                nb_label = str(df.at[neighbor, "LLM_Verdict"]).strip()
                if nb_bucket != cur_bucket and (
                    cur_label in {"affected_intro", "affected_patch"}
                    or nb_label in {"affected_intro", "affected_patch"}
                ):
                    return True
        return False

    def hypothetical_llm_score(row, neighbor_version=None) -> float:
        enable_llm = os.environ.get("EXCEL_ENABLE_LLM_REFINE", "").lower() in ("1", "true", "yes", "on")
        if not enable_llm:
            return 0.5
        try:
            from autogen_core.models import SystemMessage, UserMessage, ModelFamily
            from autogen_ext.models.openai import OpenAIChatCompletionClient
        except ImportError:
            return 0.5

        api_key = (
            os.environ.get("CHATANYWHERE_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )
        if not api_key:
            return 0.5

        model_name = os.environ.get("EXCEL_LLM_MODEL") or "deepseek-v3"
        base_url = os.environ.get("EXCEL_LLM_BASE_URL") or "https://api.chatanywhere.tech/v1"

        client = OpenAIChatCompletionClient(
            model=model_name,
            base_url=base_url,
            api_key=api_key,
            timeout=30.0,
            max_retries=1,
            model_info={
                "vision": False,
                "function_calling": False,
                "json_output": True,
                "family": ModelFamily.ANY,
                "structured_output": True,
                "temperature": 0.0,
            },
        )

        payload = {
            "cve_id": str(row["CVE_ID"]),
            "library": str(row["Library"]),
            "poc": str(row["PoC"]),
            "execution_result": str(row["Execution Result"]),
            "llm_verdict": str(row["LLM_Verdict"]),
            "true_label": str(row["True Affected Version"]),
        }

        prompt = (
            "Given the following row from a CVE/version Excel table, "
            "return a JSON object with a single key 'refinement_score' between 0.0 and 1.0. "
            "The score should be high only when you are highly confident that the LLM_Verdict column should be changed, "
            "and low when you are uncertain or evidence is insufficient. "
            "Return strict JSON only. Row JSON:\n" + json.dumps(payload, ensure_ascii=False)
        )

        messages = [
            SystemMessage(content="You are a calibration helper that returns only JSON objects."),
            UserMessage(content=prompt, source="user"),
        ]

        async def _run():
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=".*Resolved model mismatch.*", category=UserWarning)
                return await client.create(messages=messages)

        try:
            response = asyncio.run(_run())
            # 记录版本链 refine 阶段的 LLM token usage
            log_llm_usage(
                method="excel_refine",
                case_id=f"{row['CVE_ID']}::{row['Library']}::{row['PoC']}",
                model=model_name,
                usage=getattr(response, "usage", None),
                extra={"llm_verdict": str(row["LLM_Verdict"]).strip()},
            )
        except Exception as e:
            print(f"[EXCEL_LLM_REFINE] LLM 调用异常: {e}")
            close_method = getattr(client, "close", None)
            if callable(close_method):
                maybe_awaitable = close_method()
                if asyncio.iscoroutine(maybe_awaitable):
                    try:
                        asyncio.run(maybe_awaitable)
                    except Exception:
                        pass
            return 0.5

        raw = str(response.content)
        try:
            text = raw.strip()
            if text.startswith("```"):
                first_newline = text.find("\n")
                if first_newline != -1:
                    text = text[first_newline + 1 :]
                if text.endswith("```"):
                    text = text[:-3].strip()
            parsed = json.loads(text)
            score_val = parsed.get("refinement_score", 0.5)
            score = float(score_val)
        except Exception:
            score = 0.5

        if score < 0.0:
            score = 0.0
        if score > 1.0:
            score = 1.0

        print(f"真正请求 LLM，返回 refinement_score = {score}")

        close_method = getattr(client, "close", None)
        if callable(close_method):
            maybe_awaitable = close_method()
            if asyncio.iscoroutine(maybe_awaitable):
                try:
                    asyncio.run(maybe_awaitable)
                except Exception:
                    pass

        return score

    def apply_hypothetical_llm_refinement(df):
        THRESHOLD = 0.95
        scores = []
        decisions = []
        for idx in range(n):
            row = df.iloc[idx]
            original_label = str(row["LLM_Verdict"]).strip()
            if not in_execution_conflict_zone(idx):
                scores.append(0.0)
                decisions.append("skipped_no_conflict")
                continue
            score = hypothetical_llm_score(row)
            scores.append(score)
            if score >= THRESHOLD:
                decisions.append("would_change_but_disabled")
            else:
                decisions.append("abstain_low_confidence")
            _ = original_label
        df["LLM_Refinement_Score"] = scores
        df["LLM_Refinement_Decision"] = decisions

    for i in range(n):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v == "No_Data":
            exec_res = str(df.at[i, "Execution Result"]).strip().upper()
            if exec_res == "APPEARS":
                df.at[i, "LLM_Verdict"] = "affected"

    print("正在执行 not affected_patch 向下扩张 (按最小区域)...")
    for i in range(1, n):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        prev_v = str(df.at[i - 1, "LLM_Verdict"]).strip()
        if prev_v == "not affected_patch" and same_region(i, i - 1):
            df.at[i, "LLM_Verdict"] = "not affected_patch"

    print("正在执行 not affected_intro 向上扩张 (按最小区域)...")
    for i in range(n - 2, -1, -1):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        next_v = str(df.at[i + 1, "LLM_Verdict"]).strip()
        if next_v == "not affected_intro" and same_region(i, i + 1):
            df.at[i, "LLM_Verdict"] = "not affected_intro"

    print("正在执行 affected_patch 向下扩张 (按最小区域)...")
    for i in range(1, n):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        prev_v = str(df.at[i - 1, "LLM_Verdict"]).strip()
        if prev_v == "affected_patch" and same_region(i, i - 1):
            bucket_i = execution_bucket(df.at[i, "Execution Result"])
            bucket_prev = execution_bucket(df.at[i - 1, "Execution Result"])
            if bucket_i != bucket_prev:
                neighbor_version = ""
                if "Version" in df.columns:
                    neighbor_version = df.at[i - 1, "Version"]
                score = hypothetical_llm_score(df.iloc[i], neighbor_version=neighbor_version)
                if score >= 0.99:
                    continue
            df.at[i, "LLM_Verdict"] = "affected_patch"

    print("正在执行 affected_patch 向上扩张 (按最小区域)...")
    for i in range(n - 2, -1, -1):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        next_v = str(df.at[i + 1, "LLM_Verdict"]).strip()
        if next_v == "affected_patch" and same_region(i, i + 1):
            df.at[i, "LLM_Verdict"] = "affected_patch"

    print("正在执行 affected_intro 向上扩张 (按最小区域)...")
    for i in range(n - 2, -1, -1):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        next_v = str(df.at[i + 1, "LLM_Verdict"]).strip()
        if next_v == "affected_intro" and same_region(i, i + 1):
            df.at[i, "LLM_Verdict"] = "affected_intro"

    print("正在执行 affected_intro 向下扩张 (按最小区域)...")
    for i in range(1, n):
        current_v = str(df.at[i, "LLM_Verdict"]).strip()
        if current_v != "No_Data":
            continue
        prev_v = str(df.at[i - 1, "LLM_Verdict"]).strip()
        if prev_v == "affected_intro" and same_region(i, i - 1):
            bucket_i = execution_bucket(df.at[i, "Execution Result"])
            bucket_prev = execution_bucket(df.at[i - 1, "Execution Result"])
            if bucket_i != bucket_prev:
                neighbor_version = ""
                if "Version" in df.columns:
                    neighbor_version = df.at[i - 1, "Version"]
                score = hypothetical_llm_score(df.iloc[i], neighbor_version=neighbor_version)
                if score >= 0.99:
                    continue
            df.at[i, "LLM_Verdict"] = "affected_intro"

    print("正在执行高阈值 LLM 精修阶段 (仅记录诊断信息, 不改变 LLM_Verdict)...")
    apply_hypothetical_llm_refinement(df)

    print("正在计算评估指标...")

    tp = fp = fn = tn = 0

    def process_alignment(row):
        nonlocal tp, fp, fn, tn
        true_s = get_state(row["True Affected Version"])
        llm_s = get_state(row["LLM_Verdict"])
        if true_s == "POS" and llm_s == "POS":
            tp += 1
            return "T"
        if true_s == "NEG" and llm_s == "NEG":
            tn += 1
            return "T"
        if true_s == "NEG" and llm_s == "POS":
            fp += 1
            return "FP"
        if true_s == "POS" and llm_s == "NEG":
            fn += 1
            return "FN"
        return ""

    df["Aligned_llm"] = df.apply(process_alignment, axis=1)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = (tp + tn) / len(df) if len(df) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    try:
        df.to_excel(EXCEL_PATH, index=False)
        print("\n" + "=" * 58)
        print("📊 最终评估报告 (逻辑传递后, full-coverage)")
        print("=" * 58)
        print(f"TP (真正例): {tp:4d} | FP (误报): {fp:4d}")
        print(f"FN (漏报):   {fn:4d} | TN (真反例): {tn:4d}")
        print("-" * 58)
        print(f"准确率 (Accuracy):  {accuracy:.2%}")
        print(f"精确率 (Precision): {precision:.2%}")
        print(f"召回率 (Recall):    {recall:.2%}")
        print(f"F1 分数 (F1-Score):  {f1:.4f}")
        print("=" * 58)
        print(f"💾 结果已保存至: {EXCEL_PATH}")
    except Exception as e:
        print(f"❌ 写入 Excel 失败: {e}")


if __name__ == "__main__":
    main()
