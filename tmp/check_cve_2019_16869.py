from pathlib import Path

import pandas as pd


def main() -> None:
    excel_path = Path("dataset/execution_result.xlsx").resolve()
    df = pd.read_excel(excel_path, engine="openpyxl")

    mask = df["CVE_ID"].astype(str).str.contains("CVE-2019-16869", case=False, na=False)
    cols = [
        "CVE_ID",
        "Library",
        "Version",
        "Execution Result",
        "LLM_Verdict",
        "Aligned_llm",
        "True Affected Version",
    ]
    subset = df.loc[mask, cols]

    print("rows=", len(subset))
    if not subset.empty:
        print(subset.to_string(index=False))


if __name__ == "__main__":
    main()
