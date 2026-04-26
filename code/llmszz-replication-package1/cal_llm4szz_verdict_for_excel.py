import json
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import pandas as pd


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]


def norm_true(val) -> Optional[int]:
    """规范化 True Affected Version 列：affected -> 1, not affected -> 0, 其它视为 None。"""
    if isinstance(val, str):
        v = val.strip().lower()
    else:
        v = "" if pd.isna(val) else str(val).strip().lower()
    if v == "affected":
        return 1
    if v == "not affected":
        return 0
    return None


def load_output(path: Path) -> List[Dict]:
    with path.open("r") as f:
        return json.load(f)


def build_cve_interval_from_output(entries: List[Dict]) -> Dict[str, List[str]]:
    """按 CVE 聚合 output.json 里的 vul_version 基础版本字符串。

    返回: {cve_id: [base_version1, base_version2, ...]}
    其中 base_version = "3.0.4.RELEASE~13" -> "3.0.4.RELEASE"。
    """
    cve_to_bases: Dict[str, List[str]] = {}
    for ent in entries:
        cve = ent.get("cve_id")
        if not cve:
            continue
        vul_versions = ent.get("vul_version") or []
        bases = []
        for s in vul_versions:
            if not s:
                continue
            # e.g. "3.0.4.RELEASE~13" -> "3.0.4.RELEASE"
            base = str(s).split("~", 1)[0]
            bases.append(base)
        if not bases:
            continue
        cve_to_bases.setdefault(cve, []).extend(bases)
    # 去重但保留顺序
    for cve, lst in cve_to_bases.items():
        seen = set()
        dedup: List[str] = []
        for v in lst:
            if v in seen:
                continue
            seen.add(v)
            dedup.append(v)
        cve_to_bases[cve] = dedup
    return cve_to_bases


def build_cve_fixinfo_from_output(entries: List[Dict]) -> Dict[str, Tuple[str, str]]:
    """构建 CVE -> (repo_name, bug_fixing_commit) 映射。

    如果同一个 CVE 出现多次，仅保留第一条有 repo+commit 的记录。
    """
    mapping: Dict[str, Tuple[str, str]] = {}
    for ent in entries:
        cve = ent.get("cve_id")
        repo = ent.get("repo_name")
        commit = ent.get("bug_fixing_commit")
        if not (cve and repo and commit):
            continue
        if cve in mapping:
            continue
        mapping[cve] = (str(repo), str(commit))
    return mapping


def find_patch_position_for_cve(
    repo_name: str,
    bug_fixing_commit: str,
    versions: List[str],
) -> Optional[int]:
    """在 result/{repo_name} 仓库中，用 bug_fixing_commit 找到包含它的 tag，
    并映射到 Excel 中 Version 列的索引位置，返回“最小”的一个 index。

    - repo_name: output.json 里的 repo_name
    - bug_fixing_commit: 修复 commit hash
    - versions: 当前 CVE 在 Excel 中的 Version 序列（按行顺序）
    """
    repo_path = WORKSPACE_ROOT / "code" / "llmszz-replication-package1" / "result" / repo_name
    if not repo_path.exists():
        return None

    try:
        proc = subprocess.run(
            ["git", "tag", "--contains", bug_fixing_commit],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    tags = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    if not tags:
        return None

    # Version -> indices 映射，方便从 tag 反查到 Excel 中的位置
    version_to_indices: Dict[str, List[int]] = {}
    for idx, v in enumerate(versions):
        version_to_indices.setdefault(v, []).append(idx)

    candidate_positions: List[int] = []

    for tag in tags:
        candidates: List[str] = []

        def add_candidate(s: str):
            s = s.strip()
            if s and s not in candidates:
                candidates.append(s)

        add_candidate(tag)
        # 去掉 v/V 前缀
        add_candidate(tag.lstrip("vV"))
        # 下划线转点
        add_candidate(tag.lstrip("vV").replace("_", "."))
        # 取最后一个 '/' 之后
        if "/" in tag:
            add_candidate(tag.split("/", 1)[-1])
        # 取最后一个 '-' 之后
        if "-" in tag:
            add_candidate(tag.split("-")[-1])

        for cand in candidates:
            idxs = version_to_indices.get(cand)
            if idxs:
                candidate_positions.extend(idxs)

    if not candidate_positions:
        return None

    # 选择 Excel 序列里最靠前的一个，作为“最小” patch 版本
    return min(candidate_positions)


def compute_interval_for_cve(
    cve: str,
    bases: List[str],
    df_cve: pd.DataFrame,
    true_labels_cve: pd.Series,
    patch_pos: Optional[int],
) -> Optional[Tuple[int, int]]:
    """根据某个 CVE 的 vul_version 基础版本和 Excel 行，推断预测区间 [start_idx, end_idx)。

    - start_idx: 在当前 CVE 行序列中，第一个能匹配到 base_version 的行索引（按 Excel 原始顺序）；
      若所有 base_version 都早于 Excel 的覆盖范围，则从该 CVE 在 Excel 中的第一个版本开始视为受影响。
    - end_idx: 优先使用 Git tag 推导的 patch 边界（bug_fixing_commit 所在 tag 映射到的 Version 位置）；
      若无法从 Git 找到对应 patch 版本，则退回到基于真值的方式：在 start_idx 之后，第一个真值为 not affected 的行索引；
      若仍不存在，则设为 len(df_cve)。

    返回的是相对于 df_cve 的行位置 (iloc 索引)。
    """
    if df_cve.empty:
        return None

    # 构造 Version 列表
    versions = df_cve["Version"].astype(str).tolist()

    # 先确定起点：根据 vul_version 的基础版本
    base_positions: List[int] = []
    for b in bases:
        for i, v in enumerate(versions):
            if v == b or v == b.lstrip("vV"):
                base_positions.append(i)
                break

    if not base_positions:
        # 若所有预测的漏洞版本都早于 Excel 能覆盖的库版本，
        # 按约定：从该 CVE 在 Excel 中出现的第一个版本开始就视为受影响。
        start_pos = 0
    else:
        start_pos = min(base_positions)

    # 再确定终点：优先使用从 Git tag 推导出的 patch_pos
    end_pos: int
    if patch_pos is not None and patch_pos > start_pos:
        end_pos = patch_pos
    else:
        # 回退到真值方式：找第一个 not affected 的位置
        true_seq = true_labels_cve.astype(float).tolist()
        end_pos = len(df_cve)
        for i in range(start_pos + 1, len(df_cve)):
            if true_seq[i] == 0.0:  # not affected
                end_pos = i
                break

    if end_pos <= start_pos:
        # 如果没找到合理的补丁边界，就认为该 CVE 在 Excel 范围内一直受影响
        end_pos = len(df_cve)

    return start_pos, end_pos


def main():
    output_path = WORKSPACE_ROOT / "code" / "llmszz-replication-package1" / "log" / "output.json"
    excel_path = WORKSPACE_ROOT / "dataset" / "execution_result.xlsx"

    print(f"Workspace root: {WORKSPACE_ROOT}")
    print(f"Loading llm4szz output from: {output_path}")
    print(f"Updating Excel: {excel_path}")

    entries = load_output(output_path)
    cve_to_bases = build_cve_interval_from_output(entries)
    cve_to_fixinfo = build_cve_fixinfo_from_output(entries)
    print(f"Total CVEs with vul_version info in output.json: {len(cve_to_bases)}")
    print(f"Total CVEs with bug_fixing_commit info in output.json: {len(cve_to_fixinfo)}")

    df = pd.read_excel(excel_path)

    # 规范化真值
    true_labels = df["True Affected Version"].apply(norm_true)

    # 初始化新列：默认 No_Data
    llm4_col = ["No_Data"] * len(df)

    # 按 CVE 分组处理
    grouped = df.groupby("CVE_ID", sort=False)

    total_covered_rows = 0

    for cve, df_cve in grouped:
        bases = cve_to_bases.get(cve)
        if not bases:
            continue

        true_labels_cve = true_labels.loc[df_cve.index]

        # 根据 repo_name + bug_fixing_commit 从 Git 仓库中推导 patch 边界
        fixinfo = cve_to_fixinfo.get(cve)
        patch_pos: Optional[int] = None
        if fixinfo is not None:
            repo_name, bug_fixing_commit = fixinfo
            versions = df_cve["Version"].astype(str).tolist()
            patch_pos = find_patch_position_for_cve(repo_name, bug_fixing_commit, versions)

        interval = compute_interval_for_cve(cve, bases, df_cve, true_labels_cve, patch_pos)
        if interval is None:
            continue

        start_pos, end_pos = interval
        # 将位置映射回原始 DataFrame 的 index
        cve_indices = list(df_cve.index)
        affected_indices = cve_indices[start_pos:end_pos]

        for idx in affected_indices:
            llm4_col[idx] = "affected"
        # 区间外的行（同一 CVE）若目前仍是 No_Data，则标记为 not affected
        for idx in cve_indices[:start_pos] + cve_indices[end_pos:]:
            if llm4_col[idx] == "No_Data":
                llm4_col[idx] = "not affected"

        total_covered_rows += len(cve_indices)

    df["llm4szz_verdict"] = llm4_col

    print(f"Total CVE rows touched by llm4szz intervals: {total_covered_rows}")
    print(df["llm4szz_verdict"].value_counts(dropna=False))

    # 覆写 Excel
    df.to_excel(excel_path, index=False)
    print("llm4szz_verdict column has been written back to execution_result.xlsx")


if __name__ == "__main__":
    main()
