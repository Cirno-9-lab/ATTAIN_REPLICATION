import json
from pathlib import Path

import pandas as pd


def norm_true(val):
    """Normalize ground-truth label from Excel.

    affected -> 1, not affected -> 0, others -> None.
    """
    if isinstance(val, str):
        v = val.strip().lower()
    else:
        v = "" if pd.isna(val) else str(val).strip().lower()
    if v == "affected":
        return 1
    if v == "not affected":
        return 0
    return None


def norm_verdict_no_data_as_neg(val):
    """Normalize verdict-like prediction into binary label.

    约定：
    - 以 'affected' 开头或显式 1/true -> 1
    - 以 'not affected' 开头、"no_data"、""、0/false -> 0
    用于统一处理 PatchorBreak (LLM_Verdict)、V-SZZ (vszz_verdict)、LLM4SZZ (llm4szz_verdict)，
    且 No_Data 一律视为 not affected。
    """
    if isinstance(val, str):
        v = val.strip().lower()
    else:
        v = "" if pd.isna(val) else str(val).strip().lower()

    if v in {"1", "true", "affected"}:
        return 1
    if v in {"0", "false", "not affected", "no_data", ""}:
        return 0
    if v.startswith("affected"):
        return 1
    if v.startswith("not affected"):
        return 0
    # 兜底：其它异常值也当作 not affected
    return 0


def norm_poc_pred(val):
    """Normalize PoC-only baseline prediction from Execution Result.

    APPEARS           -> 1 (affected)
    BUILD_SUCCESS     -> 0 (not affected)
    BUILD_FAILURE_OTHER -> 0 (not affected)
    Other / unknown values -> 0 (treated as not affected).
    """
    if isinstance(val, str):
        v = val.strip().upper()
    else:
        v = "" if pd.isna(val) else str(val).strip().upper()
    if v == "APPEARS":
        return 1
    if v in {"BUILD_SUCCESS", "BUILD_FAILURE_OTHER"}:
        return 0
    # 兜底：未知状态视为 not affected
    return 0


def compute_confusion(t, p):
    """Return (tp, fp, fn, tn)."""
    tp = int(((t == 1) & (p == 1)).sum())
    tn = int(((t == 0) & (p == 0)).sum())
    fp = int(((t == 0) & (p == 1)).sum())
    fn = int(((t == 1) & (p == 0)).sum())
    return tp, fp, fn, tn


def prf(tp: int, fp: int, fn: int):
    """Compute precision/recall/F1 from confusion counts."""
    prec = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
    rec = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else float("nan")
    return prec, rec, f1


def main():
    # Assume current working directory is the workspace root
    root = Path(".")

    cwe_stats_path = root / "dataset" / "cwe_statistics.csv"
    cve_list_path = root / "dataset" / "list" / "cve_list_v2.json"
    excel_path = root / "dataset" / "execution_result.xlsx"
    out_path = root / "dataset" / "cwe_cnt.csv"

    # 1) Top10 CWE from cwe_statistics.csv
    cwe_stats = pd.read_csv(cwe_stats_path)
    cwe_stats["pct_val"] = cwe_stats["Percentage"].str.rstrip("%").astype(float)
    TopN = 10
    cwe_top = cwe_stats.sort_values("pct_val", ascending=False).head(TopN)
    Top_cwe_ids = list(cwe_top["CWE_ID"])
    Top_cwe_set = set(Top_cwe_ids)
    print("Top10 CWE_ID:", Top_cwe_ids)

    # 2) CVE -> CWE mapping from cve_list_v2.json
    with cve_list_path.open("r") as f:
        cve_data = json.load(f)

    cve_to_cwe = {}
    for cve_id, entry in cve_data.items():
        cwes = entry.get("cwe") or []
        cve_to_cwe[cve_id] = {str(c) for c in cwes if c}

    # 3) Load Excel
    df = pd.read_excel(excel_path)

    # Column detection
    cve_col_candidates = [c for c in df.columns if c.upper().startswith("CVE")]
    if not cve_col_candidates:
        raise SystemExit(f"No CVE column found, columns: {list(df.columns)!r}")
    CVE_COL = cve_col_candidates[0]

    true_col_candidates = [c for c in df.columns if "true affected" in c.lower()]
    if not true_col_candidates:
        raise SystemExit(f"No True Affected column found, columns: {list(df.columns)!r}")
    TRUE_COL = true_col_candidates[0]

    pob_col_candidates = [c for c in df.columns if "llm_verdict" in c.lower()]
    if not pob_col_candidates:
        raise SystemExit(f"No LLM_Verdict column found, columns: {list(df.columns)!r}")
    PATCHORBREAK_COL = pob_col_candidates[0]

    exec_col_candidates = [c for c in df.columns if "execution result" in c.lower()]
    if not exec_col_candidates:
        raise SystemExit(f"No Execution Result column found, columns: {list(df.columns)!r}")
    POCONLY_COL = exec_col_candidates[0]

    vszz_col_candidates = [c for c in df.columns if "vszz_verdict" in c.lower()]
    if not vszz_col_candidates:
        raise SystemExit(f"No vszz_verdict column found, columns: {list(df.columns)!r}")
    VSZZ_COL = vszz_col_candidates[0]

    llm4_col_candidates = [c for c in df.columns if "llm4szz_verdict" in c.lower()]
    if not llm4_col_candidates:
        raise SystemExit(f"No llm4szz_verdict column found, columns: {list(df.columns)!r}")
    LLM4SZZ_COL = llm4_col_candidates[0]

    print(
        f"Using columns -> CVE:{CVE_COL}, TRUE:{TRUE_COL}, PatchorBreak_PRED:{PATCHORBREAK_COL}, "
        f"PoConly_PRED(source={POCONLY_COL}), V-SZZ:{VSZZ_COL}, LLM4SZZ:{LLM4SZZ_COL}"
    )

    # 4) Normalize labels
    true_labels = df[TRUE_COL].apply(norm_true)
    patchorbreak_pred_labels = df[PATCHORBREAK_COL].apply(norm_verdict_no_data_as_neg)
    poconly_pred_labels = df[POCONLY_COL].apply(norm_poc_pred)
    vszz_pred_labels = df[VSZZ_COL].apply(norm_verdict_no_data_as_neg)
    llm4szz_pred_labels = df[LLM4SZZ_COL].apply(norm_verdict_no_data_as_neg)

    # valid set: rows where ground truth is defined
    mask_valid = true_labels.notna()
    valid_idx = df.index[mask_valid]

    true_valid = true_labels[mask_valid].astype(int)
    patchorbreak_valid = patchorbreak_pred_labels[mask_valid].astype(int)
    poconly_valid = poconly_pred_labels[mask_valid].astype(int)
    vszz_valid = vszz_pred_labels[mask_valid].astype(int)
    llm4szz_valid = llm4szz_pred_labels[mask_valid].astype(int)

    print("Total valid samples (with ground truth):", len(valid_idx))

    # 5) Global metrics for four methods
    def print_global(name, pred_series):
        tp, fp, fn, tn = compute_confusion(true_valid, pred_series)
        prec, rec, f1 = prf(tp, fp, fn)
        print(
            f"GLOBAL {name}: n={len(true_valid)} TP={tp} FP={fp} FN={fn} TN={tn} "
            f"Precision={prec:.4f} Recall={rec:.4f} F1={f1:.4f}"
        )

    print_global("PatchorBreak", patchorbreak_valid)
    print_global("PoC only", poconly_valid)
    print_global("V-SZZ", vszz_valid)
    print_global("LLM4SZZ", llm4szz_valid)

    # 6) Build per-CWE groups (Top10 + others) on the same valid set
    cwe_to_indices = {cwe: [] for cwe in Top_cwe_ids}
    others_indices = []

    for idx in valid_idx:
        cve = str(df.loc[idx, CVE_COL])
        cwes = cve_to_cwe.get(cve, set())
        hit_top = cwes & Top_cwe_set
        if hit_top:
            for c in hit_top:
                cwe_to_indices[c].append(idx)
        else:
            others_indices.append(idx)

    def compute_metrics_for_indices(name: str, indices):
        if not indices:
            return {
                "CWE_ID": name,
                "Count": 0,
                "PatchorBreak_Precision": float("nan"),
                "PatchorBreak_Recall": float("nan"),
                "PatchorBreak_F1": float("nan"),
                "PoConly_Precision": float("nan"),
                "PoConly_Recall": float("nan"),
                "PoConly_F1": float("nan"),
                "V-SZZ_Precision": float("nan"),
                "V-SZZ_Recall": float("nan"),
                "V-SZZ_F1": float("nan"),
                "LLM4SZZ_Precision": float("nan"),
                "LLM4SZZ_Recall": float("nan"),
                "LLM4SZZ_F1": float("nan"),
            }

        t = true_valid.loc[indices]
        p_patchorbreak = patchorbreak_valid.loc[indices]
        p_poconly = poconly_valid.loc[indices]
        p_vszz = vszz_valid.loc[indices]
        p_llm4szz = llm4szz_valid.loc[indices]

        patchorbreak_tp, patchorbreak_fp, patchorbreak_fn, patchorbreak_tn = compute_confusion(t, p_patchorbreak)
        poconly_tp, poconly_fp, poconly_fn, poconly_tn = compute_confusion(t, p_poconly)
        vszz_tp, vszz_fp, vszz_fn, vszz_tn = compute_confusion(t, p_vszz)
        llm4szz_tp, llm4szz_fp, llm4szz_fn, llm4szz_tn = compute_confusion(t, p_llm4szz)

        patchorbreak_prec, patchorbreak_rec, patchorbreak_f1 = prf(patchorbreak_tp, patchorbreak_fp, patchorbreak_fn)
        poconly_prec, poconly_rec, poconly_f1 = prf(poconly_tp, poconly_fp, poconly_fn)
        vszz_prec, vszz_rec, vszz_f1 = prf(vszz_tp, vszz_fp, vszz_fn)
        llm4szz_prec, llm4szz_rec, llm4szz_f1 = prf(llm4szz_tp, llm4szz_fp, llm4szz_fn)

        return {
            "CWE_ID": name,
            "Count": len(indices),
            "ATTAIN_Precision": round(patchorbreak_prec, 4) if patchorbreak_prec == patchorbreak_prec else patchorbreak_prec,
            "ATTAIN_Recall": round(patchorbreak_rec, 4) if patchorbreak_rec == patchorbreak_rec else patchorbreak_rec,
            "ATTAIN_F1": round(patchorbreak_f1, 4) if patchorbreak_f1 == patchorbreak_f1 else patchorbreak_f1,
            "PoConly_Precision": round(poconly_prec, 4) if poconly_prec == poconly_prec else poconly_prec,
            "PoConly_Recall": round(poconly_rec, 4) if poconly_rec == poconly_rec else poconly_rec,
            "PoConly_F1": round(poconly_f1, 4) if poconly_f1 == poconly_f1 else poconly_f1,
            "V-SZZ_Precision": round(vszz_prec, 4) if vszz_prec == vszz_prec else vszz_prec,
            "V-SZZ_Recall": round(vszz_rec, 4) if vszz_rec == vszz_rec else vszz_rec,
            "V-SZZ_F1": round(vszz_f1, 4) if vszz_f1 == vszz_f1 else vszz_f1,
            "LLM4SZZ_Precision": round(llm4szz_prec, 4) if llm4szz_prec == llm4szz_prec else llm4szz_prec,
            "LLM4SZZ_Recall": round(llm4szz_rec, 4) if llm4szz_rec == llm4szz_rec else llm4szz_rec,
            "LLM4SZZ_F1": round(llm4szz_f1, 4) if llm4szz_f1 == llm4szz_f1 else llm4szz_f1,
        }

    rows = []
    for cwe in Top_cwe_ids:
        rows.append(compute_metrics_for_indices(cwe, cwe_to_indices[cwe]))
    rows.append(compute_metrics_for_indices("others", others_indices))

    out_df = pd.DataFrame(rows)

    # 转置整张表格：以 CWE_ID 作为列，指标作为行
    out_t = out_df.set_index("CWE_ID").T
    out_t.reset_index(inplace=True)
    out_t.rename(columns={"index": "Metric"}, inplace=True)

    out_t.to_csv(out_path, index=False)
    print("Transposed per-CWE metrics written to", out_path)


if __name__ == "__main__":
    main()
