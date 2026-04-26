#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Tuple

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXCEL_PATH = REPO_ROOT / "dataset" / "execution_result.xlsx"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "dataset" / "result" / "library_fp_fn_ranking"
DEFAULT_LIBRARY_COL = "Library"
DEFAULT_ALIGNED_COL = "Aligned_llm"
DEFAULT_TOP_N = 20


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "统计 execution_result.xlsx 中各个 Library 的 FN / FP 数量，"
            "并分别按 FN、FP 降序输出排名。"
        )
    )
    parser.add_argument(
        "--excel",
        default=str(DEFAULT_EXCEL_PATH),
        help=f"待分析的 Excel 路径，默认 {DEFAULT_EXCEL_PATH}",
    )
    parser.add_argument(
        "--library-col",
        default=DEFAULT_LIBRARY_COL,
        help=f"Library 列名，默认 {DEFAULT_LIBRARY_COL}",
    )
    parser.add_argument(
        "--aligned-col",
        default=DEFAULT_ALIGNED_COL,
        help=f"对齐结果列名，默认 {DEFAULT_ALIGNED_COL}",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP_N,
        help=f"终端展示前多少个 Library，默认 {DEFAULT_TOP_N}",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"CSV 输出目录，默认 {DEFAULT_OUTPUT_DIR}",
    )
    parser.add_argument(
        "--cve-col",
        default="CVE_ID",
        help="CVE 列名，默认 CVE_ID",
    )
    return parser.parse_args()


def normalize_text(value: object) -> str:
    if value is None:
        return ""
    if pd.isna(value):
        return ""
    return str(value).strip()


def build_summary(df: pd.DataFrame, library_col: str, aligned_col: str) -> pd.DataFrame:
    working = df.copy()
    working[library_col] = working[library_col].map(normalize_text)
    working[aligned_col] = working[aligned_col].map(normalize_text)

    working.loc[working[library_col] == "", library_col] = "(EMPTY_LIBRARY)"
    working["is_fn"] = working[aligned_col].eq("FN")
    working["is_fp"] = working[aligned_col].eq("FP")
    working["is_error"] = working["is_fn"] | working["is_fp"]

    summary = (
        working.groupby(library_col, dropna=False)
        .agg(
            total_rows=(library_col, "size"),
            fn_count=("is_fn", "sum"),
            fp_count=("is_fp", "sum"),
            error_count=("is_error", "sum"),
        )
        .reset_index()
        .rename(columns={library_col: "Library"})
    )

    summary["fn_ratio"] = summary["fn_count"] / summary["total_rows"]
    summary["fp_ratio"] = summary["fp_count"] / summary["total_rows"]
    summary["error_ratio"] = summary["error_count"] / summary["total_rows"]
    return summary


def sort_rankings(summary: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    by_fn = summary.sort_values(
        by=["fn_count", "fp_count", "error_count", "Library"],
        ascending=[False, False, False, True],
        kind="stable",
    ).reset_index(drop=True)

    by_fp = summary.sort_values(
        by=["fp_count", "fn_count", "error_count", "Library"],
        ascending=[False, False, False, True],
        kind="stable",
    ).reset_index(drop=True)

    by_error = summary.sort_values(
        by=["error_count", "fn_count", "fp_count", "Library"],
        ascending=[False, False, False, True],
        kind="stable",
    ).reset_index(drop=True)

    return by_fn, by_fp, by_error


def print_ranking(title: str, ranking: pd.DataFrame, top_n: int, key_col: str = "Library") -> None:
    cols = [key_col, "fn_count", "fp_count", "error_count", "total_rows", "fn_ratio", "fp_ratio"]
    display_df = ranking.loc[:, cols].head(top_n).copy()
    for ratio_col in ("fn_ratio", "fp_ratio"):
        display_df[ratio_col] = display_df[ratio_col].map(lambda x: f"{x:.2%}")

    print(f"\n{'=' * 88}")
    print(title)
    print(f"{'=' * 88}")
    print(display_df.to_string(index=False))


def main() -> None:
    args = parse_args()

    excel_path = Path(args.excel).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()

    if not excel_path.is_file():
        raise FileNotFoundError(f"Excel 文件不存在: {excel_path}")

    df = pd.read_excel(excel_path, engine="openpyxl")

    if args.library_col not in df.columns:
        raise KeyError(f"Excel 中缺少 Library 列: {args.library_col}")
    if args.aligned_col not in df.columns:
        raise KeyError(f"Excel 中缺少对齐结果列: {args.aligned_col}")
    if args.cve_col not in df.columns:
        raise KeyError(f"Excel 中缺少 CVE 列: {args.cve_col}")

    # 按 Library 统计 FN / FP
    summary = build_summary(df, args.library_col, args.aligned_col)
    by_fn, by_fp, by_error = sort_rankings(summary)

    # 按 CVE 统计 FN / FP
    cve_df = df.copy()
    cve_col = args.cve_col
    cve_df[cve_col] = cve_df[cve_col].map(normalize_text)
    cve_df[args.aligned_col] = cve_df[args.aligned_col].map(normalize_text)
    cve_df["is_fn"] = cve_df[args.aligned_col].eq("FN")
    cve_df["is_fp"] = cve_df[args.aligned_col].eq("FP")
    cve_df["is_error"] = cve_df["is_fn"] | cve_df["is_fp"]

    cve_summary = (
        cve_df.groupby(cve_col, dropna=False)
        .agg(
            total_rows=(cve_col, "size"),
            fn_count=("is_fn", "sum"),
            fp_count=("is_fp", "sum"),
            error_count=("is_error", "sum"),
        )
        .reset_index()
        .rename(columns={cve_col: "CVE"})
    )
    cve_summary["fn_ratio"] = cve_summary["fn_count"] / cve_summary["total_rows"]
    cve_summary["fp_ratio"] = cve_summary["fp_count"] / cve_summary["total_rows"]
    cve_summary["error_ratio"] = cve_summary["error_count"] / cve_summary["total_rows"]

    cve_by_fn = cve_summary.sort_values(
        by=["fn_count", "fp_count", "error_count", "CVE"],
        ascending=[False, False, False, True],
        kind="stable",
    ).reset_index(drop=True)

    cve_by_fp = cve_summary.sort_values(
        by=["fp_count", "fn_count", "error_count", "CVE"],
        ascending=[False, False, False, True],
        kind="stable",
    ).reset_index(drop=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    summary.to_csv(output_dir / "library_fn_fp_summary.csv", index=False, encoding="utf-8-sig")
    by_fn.to_csv(output_dir / "library_fn_ranking.csv", index=False, encoding="utf-8-sig")
    by_fp.to_csv(output_dir / "library_fp_ranking.csv", index=False, encoding="utf-8-sig")
    by_error.to_csv(output_dir / "library_error_ranking.csv", index=False, encoding="utf-8-sig")

    cve_summary.to_csv(output_dir / "cve_fn_fp_summary.csv", index=False, encoding="utf-8-sig")
    cve_by_fn.to_csv(output_dir / "cve_fn_ranking.csv", index=False, encoding="utf-8-sig")
    cve_by_fp.to_csv(output_dir / "cve_fp_ranking.csv", index=False, encoding="utf-8-sig")

    print(f"Excel: {excel_path}")
    print(f"输出目录: {output_dir}")
    print(f"Library 总数: {len(summary)}")
    print(f"总 FN: {int(summary['fn_count'].sum())}")
    print(f"总 FP: {int(summary['fp_count'].sum())}")
    print(f"CVE 总数: {len(cve_summary)}")

    print_ranking("FN 最多的 Library（降序）", by_fn, args.top, key_col="Library")
    print_ranking("FP 最多的 Library（降序）", by_fp, args.top, key_col="Library")

    print_ranking("FN 最多的 CVE（降序）", cve_by_fn, args.top, key_col="CVE")
    print_ranking("FP 最多的 CVE（降序）", cve_by_fp, args.top, key_col="CVE")

    top_fn = by_fn.iloc[0]
    top_fp = by_fp.iloc[0]
    top_cve_fn = cve_by_fn.iloc[0]
    top_cve_fp = cve_by_fp.iloc[0]

    print("\n结论：")
    print(
        f"- FN 最多的 Library: {top_fn['Library']} "
        f"(FN={int(top_fn['fn_count'])}, FP={int(top_fn['fp_count'])}, 总行数={int(top_fn['total_rows'])})"
    )
    print(
        f"- FP 最多的 Library: {top_fp['Library']} "
        f"(FP={int(top_fp['fp_count'])}, FN={int(top_fp['fn_count'])}, 总行数={int(top_fp['total_rows'])})"
    )
    print(
        f"- FN 最多的 CVE: {top_cve_fn['CVE']} "
        f"(FN={int(top_cve_fn['fn_count'])}, FP={int(top_cve_fn['fp_count'])}, 总行数={int(top_cve_fn['total_rows'])})"
    )
    print(
        f"- FP 最多的 CVE: {top_cve_fp['CVE']} "
        f"(FP={int(top_cve_fp['fp_count'])}, FN={int(top_cve_fp['fn_count'])}, 总行数={int(top_cve_fp['total_rows'])})"
    )


if __name__ == "__main__":
    main()
