#!/usr/bin/env python3

"""RQ3 专用的 unified time scan 脚本。

作用：
- 仍然复用现有的 `version_switch_unified_time_scan.py` 的全部逻辑；
- 但固定改用 RQ3 构建的 Excel：`dataset/execution_result_rq3.xlsx`；
- 输出到：`dataset/list/cve_list_rq3.json`；
- 其余输入（`cve_ghrepo.json`、`mvn_test/*.json`、`disclosed-version.txt`、Maven 缓存等）与主脚本保持一致。

用法示例：

    # 在 workspace 根目录下运行
    python code/difftrace/demo/scripts/version_switch_unified_time_scan_rq3.py

你也可以额外追加原脚本支持的参数（例如 `--cve CVE-2025-48976` 只跑单个 CVE），
这些参数会透传给原始的 `version_switch_unified_time_scan.py`。
"""

import os
import subprocess
import sys
from typing import List

import pandas as pd


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.dirname(SCRIPT_DIR)
DIFFTRACE_DIR = os.path.dirname(DEMO_DIR)
CODE_DIR = os.path.dirname(DIFFTRACE_DIR)
WORKSPACE_DIR = os.path.dirname(CODE_DIR)

RQ3_SOURCE_EXCEL = os.path.join(WORKSPACE_DIR, "dataset", "execution_result_rq3.xlsx")
RQ3_MAPPED_EXCEL = os.path.join(WORKSPACE_DIR, "dataset", "execution_result_rq3_mapped.xlsx")


def prepare_mapped_excel() -> str:
    """基于 execution_result_rq3.xlsx 生成一个供 unified time scan 使用的映射版 Excel。

    映射规则：
    - 'Appears'  → 'APPEARS'（保持为 PoC 成功）；
    - 'Not Appears' → 'BUILD_FAILURE_OTHER'（视作 PoC 失败的一类，统一归到 failure）。

    这样就能复用原脚本中 is_poc_success / is_poc_fail 的逻辑，只靠“成功 vs 失败”划分边界。
    """

    if not os.path.exists(RQ3_SOURCE_EXCEL):
        raise SystemExit(f"找不到 RQ3 Excel: {RQ3_SOURCE_EXCEL}")

    df = pd.read_excel(RQ3_SOURCE_EXCEL)
    # 统一小写列名，方便定位
    df.columns = [str(c).strip().lower() for c in df.columns]
    if "execution result" not in df.columns:
        raise SystemExit("RQ3 Excel 中缺少 'Execution Result' 列")

    def map_status(value: object) -> object:
        text = str(value).strip()
        if not text:
            return value
        lower = text.lower()
        if lower == "appears":
            return "APPEARS"
        if lower == "not appears":
            return "BUILD_FAILURE_OTHER"
        return value

    df["execution result"] = df["execution result"].map(map_status)

    # 写出映射后的 Excel（列名保持当前形式即可，主脚本会再次小写处理）
    df.to_excel(RQ3_MAPPED_EXCEL, index=False)
    return RQ3_MAPPED_EXCEL


def build_base_command(extra_args: List[str]) -> List[str]:
    """构造调用原版 version_switch_unified_time_scan.py 的命令行。

    - Excel 使用映射后的 RQ3 表：dataset/execution_result_rq3_mapped.xlsx
    - 输出 JSON 固定为：dataset/list/cve_list_rq3.json
    其它路径与原脚本默认值保持一致。
    """

    base_script = os.path.join(SCRIPT_DIR, "version_switch_unified_time_scan.py")

    excel_path = prepare_mapped_excel()
    ghrepo_json = os.path.join(WORKSPACE_DIR, "dataset", "cve_ghrepo.json")
    mvn_test_dir = os.path.join(WORKSPACE_DIR, "dataset", "mvn_test")
    disclosed_version_file = os.path.join(
        WORKSPACE_DIR, "code", "PoCEmpirical", "reproduce", "disclosed-version.txt"
    )
    cache_json = os.path.join(WORKSPACE_DIR, "dataset", "maven_release_history_cache.json")
    artifact_cache_json = os.path.join(WORKSPACE_DIR, "dataset", "maven_artifact_lookup_cache.json")
    output_json = os.path.join(WORKSPACE_DIR, "dataset", "list", "cve_list_rq3.json")

    command: List[str] = [
        sys.executable,
        base_script,
        "--excel",
        excel_path,
        "--ghrepo-json",
        ghrepo_json,
        "--mvn-test-dir",
        mvn_test_dir,
        "--disclosed-version-file",
        disclosed_version_file,
        "--cache-json",
        cache_json,
        "--artifact-cache-json",
        artifact_cache_json,
        "--output-json",
        output_json,
    ]

    # 将用户在 rq3 脚本后面追加的参数透传给原脚本
    command.extend(extra_args)
    return command


def main() -> int:
    extra_args = sys.argv[1:]
    command = build_base_command(extra_args)

    # 在 workspace 根目录下执行，保持与原脚本一致的相对路径语义
    completed = subprocess.run(
        command,
        cwd=WORKSPACE_DIR,
    )
    return completed.returncode


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
