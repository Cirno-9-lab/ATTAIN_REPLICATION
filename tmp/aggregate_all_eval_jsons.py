from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple


def load_details(path: Path) -> List[dict]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    details = payload.get("details")
    if not isinstance(details, list):
        raise ValueError(f"{path} 中缺少合法的 details 列表")
    return details


def aggregate_eval_jsons(root: Path) -> Dict[str, dict]:
    """遍历 root 下所有 llm_vulnerability_presence_eval.json，按 case_id 去重聚合。

    对于同一个 case_id 出现在多个文件的情况，保留修改时间更新的那一份。
    """

    case_map: Dict[str, Tuple[dict, float]] = {}

    for json_path in root.rglob("llm_vulnerability_presence_eval.json"):
        if not json_path.is_file():
            continue
        mtime = json_path.stat().st_mtime
        try:
            details = load_details(json_path)
        except Exception as e:
            print(f"跳过 {json_path}: 解析失败: {e}")
            continue

        print(f"加载 {json_path} | details={len(details)}")

        for item in details:
            case_id = str(item.get("case_id") or "").strip()
            if not case_id:
                # 没有 case_id 的条目直接跳过
                continue
            existing = case_map.get(case_id)
            if existing is None or mtime >= existing[1]:
                case_map[case_id] = (item, mtime)

    aggregated_details = [entry for entry, _ in case_map.values()]
    aggregated_details.sort(key=lambda d: str(d.get("case_id", "")))
    return {"details": aggregated_details}


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser("聚合指定根目录下所有 llm_vulnerability_presence_eval.json")
    parser.add_argument("root", help="要扫描的批次根目录，例如 code/difftrace/demo/target/seekpatch_only_20260416_103100")
    parser.add_argument(
        "--output",
        default="dataset/llm_vulnerability_presence_eval.json",
        help="聚合结果输出路径（相对项目根），默认 dataset/llm_vulnerability_presence_eval.json",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    root = (repo_root / args.root).expanduser().resolve()
    output_path = (repo_root / args.output).expanduser().resolve()

    if not root.is_dir():
        raise NotADirectoryError(f"根目录不存在: {root}")

    aggregated = aggregate_eval_jsons(root)

    # 简单统计一下
    details = aggregated["details"]
    total = len(details)
    label_counts: Dict[str, int] = {}
    for item in details:
        label = str(item.get("predicted_label") or "").strip().lower()
        label_counts[label] = label_counts.get(label, 0) + 1

    # 先备份旧文件
    if output_path.exists():
        backup = output_path.with_suffix(output_path.suffix + ".bak")
        output_path.replace(backup)
        print(f"已备份旧文件到: {backup}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(aggregated, f, ensure_ascii=False, indent=2)

    print(f"聚合完成: {output_path}")
    print(f"总 case 条数: {total}")
    print(f"预测标签分布: {label_counts}")


if __name__ == "__main__":
    main()
