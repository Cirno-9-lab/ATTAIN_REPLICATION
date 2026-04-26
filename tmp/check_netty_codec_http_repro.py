import json
from pathlib import Path

import pandas as pd

# 路径配置（假定当前工作目录为仓库根）
JSON_PATH = Path("code/difftrace/demo/target/seekpatch_only_20260416_103100/llm-stageb-full-20260417-160346/llm_vulnerability_presence_eval_seekpatch_style.json").resolve()
EXCEL_PATH = Path("dataset/execution_result.xlsx").resolve()

print(f"Using JSON: {JSON_PATH}")
print(f"Using Excel: {EXCEL_PATH}\n")

with JSON_PATH.open("r", encoding="utf-8") as f:
    data = json.load(f)

details = data.get("details", [])
netty_cases = [d for d in details if "netty-codec-http" in str(d.get("artifact", ""))]

print(f"total_netty_cases = {len(netty_cases)}")
cves = sorted({str(d.get("cve_id")) for d in netty_cases})
print("CVEs:", ", ".join(cves))

# 读取 Excel
_df = pd.read_excel(EXCEL_PATH, engine="openpyxl")

df = _df.copy()
df["CVE_ID_str"] = df["CVE_ID"].astype(str)
df["Library_str"] = df["Library"].astype(str)
df["Version_str"] = df["Version"].astype(str)


def verdict_sign(v: str) -> str:
    v = str(v)
    if "not affected" in v:
        return "neg"
    if "affected" in v:
        return "pos"
    return "other"


ok = 0
mismatch = 0
missing = 0

for d in netty_cases:
    cve = str(d.get("cve_id"))
    target = str(d.get("target_version"))
    predicted = d.get("predicted_label")

    mask = (
        (df["CVE_ID_str"] == cve)
        & df["Library_str"].str.contains("netty-codec-http", case=False, na=False)
        & (df["Version_str"] == target)
    )
    rows = df.loc[mask, [
        "CVE_ID",
        "Library",
        "Version",
        "Execution Result",
        "LLM_Verdict",
        "Aligned_llm",
        "True Affected Version",
    ]]

    print(f"- case_id={d.get('case_id')} cve={cve} target={target} predicted={predicted}")

    if rows.empty:
        print("  Excel rows: 0 (MISSING)")
        missing += 1
        continue

    if predicted == "affected":
        expected_sign = "pos"
    elif predicted == "not affected":
        expected_sign = "neg"
    else:
        expected_sign = "other"

    verdicts = rows["LLM_Verdict"].astype(str).tolist()
    signs = {verdict_sign(v) for v in verdicts}

    print(f"  Excel rows: {len(rows)}")
    print(f"  Excel LLM_Verdict: {verdicts}")

    if expected_sign == "other":
        print("  ==> predicted is 'unknown', skip strict comparison")
        continue

    if expected_sign in signs:
        print(f"  ==> MATCH (expected_sign={expected_sign}, signs={sorted(signs)})")
        ok += 1
    else:
        print(f"  ==> MISMATCH (expected_sign={expected_sign}, signs={sorted(signs)})")
        mismatch += 1

print("\nSummary:")
print(f"  total_cases: {len(netty_cases)}")
print(f"  matched: {ok}")
print(f"  mismatched: {mismatch}")
print(f"  missing_in_excel: {missing}")
