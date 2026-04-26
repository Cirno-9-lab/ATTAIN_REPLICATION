import html
import json
from pathlib import Path

WORKSPACE = Path('/home/xinweimao/alv_evaluate/myResearch/workspace')
SOURCE_PATH = WORKSPACE / 'tmp/cve_2019_20445_matrix_latest.json'
ENTRY_CANDIDATES = [
    WORKSPACE / 'tmp/cve_2019_20445_unified_time_scan.json',
    WORKSPACE / 'dataset/list/cve_list_v2.json',
]
OUTPUT_PATH = WORKSPACE / 'tmp/CVE-2019-20445_branch_matrix_2d.svg'
CVE_ID = 'CVE-2019-20445'


def escape(value: str) -> str:
    return html.escape(str(value), quote=True)


def load_payload():
    with SOURCE_PATH.open('r', encoding='utf-8') as f:
        matrix_payload = json.load(f)

    entry = None
    for entry_path in ENTRY_CANDIDATES:
        if not entry_path.exists():
            continue
        with entry_path.open('r', encoding='utf-8') as f:
            entry_payload = json.load(f)
        if CVE_ID in entry_payload:
            entry = entry_payload[CVE_ID]
            break

    if entry is None:
        raise FileNotFoundError(f'Could not find {CVE_ID} in any entry source')

    branch_matrix = matrix_payload[CVE_ID]['branch_matrix']
    return branch_matrix, entry


def collect_boundary_versions(entry: dict):
    appears = set()
    not_appears = set()
    for pair in entry.get('version_pair', []):
        appears.add(str(pair.get('appears') or '').strip())
        not_appears.add(str(pair.get('not appears') or '').strip())
    return appears, not_appears


def render_svg(rows, entry: dict, output_path: Path):
    cell_w = 166
    cell_h = 34
    row_gap = 8
    left_margin = 48
    top_margin = 126
    right_margin = 40
    bottom_margin = 40
    max_cols = max(len(row) for row in rows)
    width = left_margin + max_cols * cell_w + right_margin
    height = top_margin + len(rows) * (cell_h + row_gap) + bottom_margin

    colors = {
        'stable': ('#DBEAFE', '#1D4ED8'),
        'stable-backport': ('#EDE9FE', '#7C3AED'),
        'pre-release': ('#FFEDD5', '#EA580C'),
        'runtime-fork': ('#DCFCE7', '#16A34A'),
        'suffix-fork': ('#F3E8FF', '#9333EA'),
        'excel-unresolved': ('#F3F4F6', '#9CA3AF'),
    }

    appears_versions, not_appears_versions = collect_boundary_versions(entry)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<style>',
        'text { font-family: "DejaVu Sans", "Arial", sans-serif; }',
        '.title { font-size: 24px; font-weight: 700; fill: #111827; }',
        '.subtitle { font-size: 13px; fill: #4B5563; }',
        '.rowlabel { font-size: 12px; fill: #6B7280; }',
        '.celltext { font-size: 11.5px; font-weight: 600; fill: #111827; }',
        '.legendtext { font-size: 12px; fill: #374151; }',
        '.badge { font-size: 10px; font-weight: 700; }',
        '</style>',
        f'<rect width="{width}" height="{height}" fill="#FFFFFF"/>',
        f'<text class="title" x="{left_margin}" y="36">{escape(CVE_ID)} 版本二维矩阵图</text>',
        f'<text class="subtitle" x="{left_margin}" y="58">artifact: {escape(entry.get("artifact", "unknown"))} | Excel-only rows: {len(rows)} | max cols: {max_cols}</text>',
        f'<text class="subtitle" x="{left_margin}" y="80">矩阵语义：仅保留 Excel 测试版本；第 0 列为主链，右侧列为回跳分支、后缀分支或按 Excel 顺序顺接的 unresolved 版本。</text>',
        f'<text class="subtitle" x="{left_margin}" y="100">边界标记：红角标 A = appears，绿角标 N = not appears。</text>',
    ]

    legend_y = 58
    legend_x = max(left_margin + 520, width - 760)
    legend_items = [
        ('stable', 'main / stable'),
        ('stable-backport', 'stable backport'),
        ('pre-release', 'pre-release'),
        ('runtime-fork', 'runtime fork'),
        ('suffix-fork', 'suffix fork'),
        ('excel-unresolved', 'excel unresolved'),
    ]
    for idx, (kind, label) in enumerate(legend_items):
        fill, stroke = colors[kind]
        x = legend_x + idx * 124
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

            version = str(cell.get('version', ''))
            label = version if len(version) <= 17 else version[:14] + '...'

            parts.append(f'<rect x="{x}" y="{y}" width="{cell_w - 12}" height="{cell_h}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="1.2"/>')
            parts.append(f'<text class="celltext" x="{x + 10}" y="{y + 22}">{escape(label)}</text>')

            if version in appears_versions:
                bx = x + cell_w - 40
                by = y + 5
                parts.append(f'<rect x="{bx}" y="{by}" width="18" height="14" rx="4" fill="#FEE2E2" stroke="#DC2626" stroke-width="1"/>')
                parts.append(f'<text class="badge" x="{bx + 6}" y="{by + 11}" fill="#B91C1C">A</text>')
            if version in not_appears_versions:
                bx = x + cell_w - 20
                by = y + 5
                parts.append(f'<rect x="{bx}" y="{by}" width="18" height="14" rx="4" fill="#DCFCE7" stroke="#16A34A" stroke-width="1"/>')
                parts.append(f'<text class="badge" x="{bx + 6}" y="{by + 11}" fill="#166534">N</text>')

    parts.append('</svg>')
    output_path.write_text('\n'.join(parts), encoding='utf-8')


def main():
    branch_matrix, entry = load_payload()
    render_svg(branch_matrix, entry, OUTPUT_PATH)
    print(str(OUTPUT_PATH))


if __name__ == '__main__':
    main()
