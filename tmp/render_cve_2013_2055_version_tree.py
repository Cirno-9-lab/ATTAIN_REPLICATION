import html
import json
from pathlib import Path

WORKSPACE = Path('/home/xinweimao/alv_evaluate/myResearch/workspace')
ENTRY_SOURCE = WORKSPACE / 'tmp/cve_2013_2055_unified_time_scan.json'
SNAPSHOT_SOURCE = WORKSPACE / 'tmp/cve_2013_2055_matrix_latest.json'
OUTPUT_PATH = WORKSPACE / 'tmp/CVE-2013-2055_version_tree.svg'
CVE_ID = 'CVE-2013-2055'


def escape(value: str) -> str:
    return html.escape(str(value), quote=True)


def load_payload():
    entry = None
    if ENTRY_SOURCE.exists():
        with ENTRY_SOURCE.open('r', encoding='utf-8') as f:
            payload = json.load(f)
        entry = payload.get(CVE_ID)

    snapshot_entry = None
    if SNAPSHOT_SOURCE.exists():
        with SNAPSHOT_SOURCE.open('r', encoding='utf-8') as f:
            payload = json.load(f)
        snapshot_entry = payload.get(CVE_ID)

    if entry is None and snapshot_entry is None:
        raise FileNotFoundError(f'Could not find {CVE_ID} in tree sources')

    merged_entry = {}
    if snapshot_entry:
        merged_entry.update(snapshot_entry)
    if entry:
        merged_entry.update(entry)

    version_tree = merged_entry.get('version_tree')
    if not version_tree:
        raise ValueError(f'{CVE_ID} does not contain version_tree data')
    return version_tree, merged_entry


def collect_boundary_versions(entry: dict):
    appears = set()
    not_appears = set()
    for pair in entry.get('version_pair', []):
        appears.add(str(pair.get('appears') or '').strip())
        not_appears.add(str(pair.get('not appears') or '').strip())
    return appears, not_appears


def shorten(version: str, max_len: int = 15) -> str:
    if len(version) <= max_len:
        return version
    return version[: max_len - 3] + '...'


def compute_layout(version_tree):
    branch_infos = sorted(version_tree, key=lambda item: int(item.get('branch_row') or 0))
    left_margin = 34
    label_w = 280
    top_margin = 160
    right_margin = 40
    bottom_margin = 46
    node_w = 118
    node_h = 34
    col_gap = 10
    row_gap = 76
    root_start_x = left_margin + label_w

    version_pos = {}
    branch_pos = {}
    max_x = root_start_x

    for idx, branch in enumerate(branch_infos):
        row_index = int(branch.get('branch_row') if branch.get('branch_row') is not None else idx)
        y = top_margin + row_index * (node_h + row_gap)
        versions = branch.get('versions') or []
        parent_anchor = str(branch.get('fork_anchor_version') or '').strip()

        if parent_anchor and parent_anchor in version_pos:
            start_x = version_pos[parent_anchor]['x'] + node_w + 26
        else:
            start_x = root_start_x

        branch_key = str(branch.get('branch_key') or f'branch-{row_index}')
        branch_pos[branch_key] = {
            'row': row_index,
            'y': y,
            'start_x': start_x,
        }

        for local_index, item in enumerate(versions):
            x = start_x + local_index * (node_w + col_gap)
            version = str(item.get('version') or '')
            version_pos[version] = {
                'x': x,
                'y': y,
                'row': row_index,
                'branch_key': branch_key,
            }
            max_x = max(max_x, x + node_w)

    width = max_x + right_margin
    height = top_margin + (len(branch_infos) - 1) * (node_h + row_gap) + node_h + bottom_margin if branch_infos else 360

    return {
        'branches': branch_infos,
        'branch_pos': branch_pos,
        'version_pos': version_pos,
        'width': width,
        'height': height,
        'left_margin': left_margin,
        'node_w': node_w,
        'node_h': node_h,
    }


def render_svg(version_tree, entry: dict, output_path: Path):
    layout = compute_layout(version_tree)
    branches = layout['branches']
    branch_pos = layout['branch_pos']
    version_pos = layout['version_pos']
    width = layout['width']
    height = layout['height']
    left_margin = layout['left_margin']
    node_w = layout['node_w']
    node_h = layout['node_h']

    colors = {
        'stable': ('#DBEAFE', '#1D4ED8'),
        'stable-backport': ('#EDE9FE', '#7C3AED'),
        'pre-release': ('#FFEDD5', '#EA580C'),
        'runtime-fork': ('#DCFCE7', '#16A34A'),
        'suffix-fork': ('#F3E8FF', '#9333EA'),
        'hotfix': ('#FEF3C7', '#D97706'),
        'excel-unresolved': ('#F3F4F6', '#9CA3AF'),
    }
    connector_palette = ['#2563EB', '#7C3AED', '#059669', '#EA580C', '#DC2626']
    appears_versions, not_appears_versions = collect_boundary_versions(entry)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<style>',
        'text { font-family: "DejaVu Sans", "Arial", sans-serif; }',
        '.title { font-size: 24px; font-weight: 700; fill: #111827; }',
        '.subtitle { font-size: 13px; fill: #4B5563; }',
        '.branchTitle { font-size: 12px; font-weight: 700; fill: #111827; }',
        '.branchMeta { font-size: 11px; fill: #6B7280; }',
        '.celltext { font-size: 11px; font-weight: 600; fill: #111827; }',
        '.legendtext { font-size: 12px; fill: #374151; }',
        '.badge { font-size: 10px; font-weight: 700; }',
        '</style>',
        f'<rect width="{width}" height="{height}" fill="#FFFFFF"/>',
        f'<text class="title" x="{left_margin}" y="36">{escape(CVE_ID)} 版本树状图</text>',
        f'<text class="subtitle" x="{left_margin}" y="58">artifact: {escape(entry.get("artifact", "unknown"))} | branches: {len(branches)} | matrix snapshot driven tree</text>',
        f'<text class="subtitle" x="{left_margin}" y="80">布局语义：每一行是一条真实 branch；彩色连线表示 fork 派生关系，节点角标来自 version_pair 边界。</text>',
        f'<text class="subtitle" x="{left_margin}" y="100">备注：本图读取 `tmp/cve_2013_2055_matrix_latest.json` 中的 `version_tree`，不依赖主 `cve_list_v2.json`。</text>',
    ]

    legend_y = 126
    legend_x = max(left_margin + 600, width - 860)
    legend_items = [
        ('stable', 'stable'),
        ('stable-backport', 'stable backport'),
        ('pre-release', 'pre-release'),
        ('runtime-fork', 'runtime fork'),
        ('suffix-fork', 'suffix fork'),
        ('hotfix', 'hotfix'),
        ('excel-unresolved', 'excel unresolved'),
    ]
    for idx, (kind, label) in enumerate(legend_items):
        fill, stroke = colors[kind]
        x = legend_x + idx * 120
        parts.append(f'<rect x="{x}" y="{legend_y - 12}" width="18" height="18" rx="4" fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>')
        parts.append(f'<text class="legendtext" x="{x + 24}" y="{legend_y + 2}">{escape(label)}</text>')

    for branch in branches:
        branch_key = str(branch.get('branch_key') or '')
        versions = branch.get('versions') or []
        if not versions:
            continue
        first_version = str(versions[0].get('version') or '')
        parent_anchor = str(branch.get('fork_anchor_version') or '').strip()
        if not parent_anchor or parent_anchor not in version_pos or first_version not in version_pos:
            continue

        parent = version_pos[parent_anchor]
        child = version_pos[first_version]
        color = connector_palette[int(branch.get('branch_depth') or 0) % len(connector_palette)]
        x1 = parent['x'] + node_w / 2
        y1 = parent['y'] + node_h
        x2 = child['x'] + node_w / 2
        y2 = child['y']
        lane_y = y1 + 12
        lane_x = child['x'] - 6
        if lane_x <= x1:
            lane_x = x1 + 18
        entry_y = y2 - 12
        if entry_y < lane_y:
            entry_y = lane_y
        parts.append(
            f'<path d="M {x1:.1f} {y1:.1f} V {lane_y:.1f} H {lane_x:.1f} V {entry_y:.1f} H {x2:.1f} V {y2:.1f}" fill="none" stroke="{color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
        )
        parts.append(f'<circle cx="{x1:.1f}" cy="{y1:.1f}" r="3.5" fill="{color}"/>')

    for branch in branches:
        row_index = int(branch.get('branch_row') if branch.get('branch_row') is not None else 0)
        y = branch_pos[str(branch.get('branch_key') or f'branch-{row_index}')]['y']
        title_y = y + 13
        meta_y = y + 29
        branch_type = str(branch.get('branch_type') or 'branch')
        line_key = str(branch.get('line_key') or 'unknown')
        depth = int(branch.get('branch_depth') or 0)
        anchor_version = str(branch.get('fork_anchor_version') or 'root')
        parts.append(f'<text class="branchTitle" x="{left_margin}" y="{title_y}">[{row_index}] {escape(branch_type)} · line {escape(line_key)}</text>')
        parts.append(f'<text class="branchMeta" x="{left_margin}" y="{meta_y}">fork from {escape(anchor_version)} · depth {depth} · branch key {escape(str(branch.get("branch_key") or ""))}</text>')

        for cell in branch.get('versions') or []:
            version = str(cell.get('version') or '')
            pos = version_pos[version]
            x = pos['x']
            branch_kind = str(cell.get('branch_kind') or 'stable')
            branch_key = str(branch.get('branch_key') or '')
            if branch_key != 'main' and branch_kind == 'stable':
                fill, stroke = colors['stable-backport']
            else:
                fill, stroke = colors.get(branch_kind, ('#F3F4F6', '#9CA3AF'))

            parts.append(f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>')
            parts.append(f'<text class="celltext" x="{x + 8}" y="{y + 22}">{escape(shorten(version))}</text>')

            if version in appears_versions:
                bx = x + node_w - 38
                by = y + 4
                parts.append(f'<rect x="{bx}" y="{by}" width="17" height="14" rx="4" fill="#FEE2E2" stroke="#DC2626" stroke-width="1"/>')
                parts.append(f'<text class="badge" x="{bx + 5.5}" y="{by + 11}" fill="#B91C1C">A</text>')
            if version in not_appears_versions:
                bx = x + node_w - 19
                by = y + 4
                parts.append(f'<rect x="{bx}" y="{by}" width="17" height="14" rx="4" fill="#DCFCE7" stroke="#16A34A" stroke-width="1"/>')
                parts.append(f'<text class="badge" x="{bx + 5.5}" y="{by + 11}" fill="#166534">N</text>')

    parts.append('</svg>')
    output_path.write_text('\n'.join(parts), encoding='utf-8')


def main():
    version_tree, entry = load_payload()
    render_svg(version_tree, entry, OUTPUT_PATH)
    print(str(OUTPUT_PATH))


if __name__ == '__main__':
    main()
