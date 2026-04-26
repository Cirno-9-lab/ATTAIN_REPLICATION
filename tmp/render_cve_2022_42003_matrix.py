import json
import html
from pathlib import Path

WORKSPACE = Path('/home/xinweimao/alv_evaluate/myResearch/workspace')
SOURCE_CANDIDATES = [
    WORKSPACE / 'tmp/cve_2022_42003_matrix_latest.json',
    WORKSPACE / 'dataset/list/cve_list_v2.json',
    WORKSPACE / 'tmp/cve_2022_42003_matrix_reordered_v2.json',
    WORKSPACE / 'tmp/cve_2022_42003_matrix_reordered.json',
    WORKSPACE / 'tmp/cve_2022_42003_matrix_check.json',
]
OUTPUT_FULL = WORKSPACE / 'tmp/CVE-2022-42003_branch_matrix_full_v5.svg'
OUTPUT_FOCUS = WORKSPACE / 'tmp/CVE-2022-42003_branch_matrix_focus_v5.svg'
CVE_ID = 'CVE-2022-42003'


def load_cve_entry():
    for path in SOURCE_CANDIDATES:
        if not path.exists():
            continue
        with path.open('r', encoding='utf-8') as f:
            data = json.load(f)
        if CVE_ID in data:
            return data[CVE_ID], path
    raise FileNotFoundError(f'Could not find {CVE_ID} in any source file')


def escape(value: str) -> str:
    return html.escape(str(value), quote=True)


def render_svg(rows, output_path: Path, title: str, subtitle: str):
    cell_w = 190
    cell_h = 34
    row_gap = 8
    left_margin = 40
    top_margin = 110
    right_margin = 40
    bottom_margin = 40
    width = left_margin + max(len(row) for row in rows) * cell_w + right_margin
    height = top_margin + len(rows) * (cell_h + row_gap) + bottom_margin

    colors = {
        'stable': ('#DBEAFE', '#1D4ED8'),
        'stable-backport': ('#EDE9FE', '#7C3AED'),
        'pre-release': ('#FFEDD5', '#EA580C'),
        'runtime-fork': ('#DCFCE7', '#16A34A'),
    }

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<style>',
        'text { font-family: "DejaVu Sans", "Arial", sans-serif; }',
        '.title { font-size: 24px; font-weight: 700; fill: #111827; }',
        '.subtitle { font-size: 13px; fill: #4B5563; }',
        '.rowlabel { font-size: 12px; fill: #6B7280; }',
        '.celltext { font-size: 13px; font-weight: 600; fill: #111827; }',
        '.legendtext { font-size: 12px; fill: #374151; }',
        '</style>',
        f'<rect width="{width}" height="{height}" fill="#FFFFFF"/>',
        f'<text class="title" x="{left_margin}" y="36">{escape(title)}</text>',
        f'<text class="subtitle" x="{left_margin}" y="60">{escape(subtitle)}</text>',
        f'<text class="subtitle" x="{left_margin}" y="80">矩阵语义：仅保留 Excel 测试版本；第 0 列为主链，后续列为回跳分支或按 Excel 顺序顺接的 unresolved 版本。</text>',
    ]

    legend_y = 60
    legend_x = width - 430
    legend_items = [
        ('stable', 'main / stable'),
        ('stable-backport', 'stable backport'),
        ('pre-release', 'pre-release fork'),
    ]
    for idx, (kind, label) in enumerate(legend_items):
        fill, stroke = colors[kind]
        x = legend_x + idx * 135
        parts.append(f'<rect x="{x}" y="{legend_y - 12}" width="18" height="18" rx="4" fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>')
        parts.append(f'<text class="legendtext" x="{x + 26}" y="{legend_y + 2}">{escape(label)}</text>')

    for r_idx, row in enumerate(rows):
        y = top_margin + r_idx * (cell_h + row_gap)
        parts.append(f'<text class="rowlabel" x="{left_margin - 10}" y="{y + 21}" text-anchor="end">[{r_idx}]</text>')
        for c_idx, cell in enumerate(row):
            x = left_margin + c_idx * cell_w
            branch_kind = cell.get('branch_kind', 'stable')
            branch_key = cell.get('branch_key', 'main')
            if branch_key != 'main' and branch_kind == 'stable':
                fill, stroke = colors['stable-backport']
            else:
                fill, stroke = colors.get(branch_kind, ('#F3F4F6', '#9CA3AF'))
            version = cell.get('version', '')
            if len(version) > 20:
                version = version[:17] + '...'
            parts.append(f'<rect x="{x}" y="{y}" width="{cell_w - 12}" height="{cell_h}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>')
            parts.append(f'<text class="celltext" x="{x + 12}" y="{y + 22}">{escape(version)}</text>')

    parts.append('</svg>')
    output_path.write_text('\n'.join(parts), encoding='utf-8')


def main():
    entry, source_path = load_cve_entry()
    branch_matrix = entry['branch_matrix']

    full_title = f'{CVE_ID} 版本二维矩阵（当前算法 V5）'
    full_subtitle = f'来源: {source_path.name} | 共 {len(branch_matrix)} 行，最大 {max(len(row) for row in branch_matrix)} 列'
    render_svg(branch_matrix, OUTPUT_FULL, full_title, full_subtitle)

    interesting = {
        '2.2.0', '2.2.1', '2.2.2', '2.2.3', '2.2.4',
        '2.3.0-rc1', '2.3.0', '2.3.1', '2.3.2', '2.3.3', '2.3.4', '2.3.5',
        '2.10.0.pr1', '2.10.0.pr2', '2.10.0.pr3', '2.10.0', '2.10.1', '2.10.2', '2.10.3', '2.10.4', '2.10.5', '2.10.5.1',
        '2.12.0', '2.12.6', '2.12.6.1', '2.12.7', '2.12.7.1', '2.12.7.2',
        '2.18.3', '2.18.4', '2.18.5', '2.19.0-rc2', '2.19.0', '2.19.1', '2.19.2', '2.19.3', '2.19.4',
        '2.20.0-rc1', '2.20.0', '2.20.1',
    }
    focus_rows = [row for row in branch_matrix if any(cell.get('version') in interesting for cell in row)]
    focus_subtitle = '聚焦最新规则：回跳版本挂到该 x.y 当前最大版本之后；未解析版本也按 Excel 顺序直接顺接前一个版本'
    render_svg(focus_rows, OUTPUT_FOCUS, f'{CVE_ID} 分支焦点图（当前算法 V5）', focus_subtitle)

    print(str(OUTPUT_FULL))
    print(str(OUTPUT_FOCUS))


if __name__ == '__main__':
    main()
