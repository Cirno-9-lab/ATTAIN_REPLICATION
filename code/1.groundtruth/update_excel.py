import os
import pandas as pd
import json

# --- 路径配置 ---
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)
workspace_dir = os.path.dirname(os.path.dirname(script_dir))

excel_file_path = os.path.join(workspace_dir, "dataset", "cve_dataset.xlsx")
head_tag_json_file_path = os.path.join(script_dir, "trueresult.json")
versions_json_file_path = os.path.join(workspace_dir, "dataset", "cve_maven_version.json")

GITHUB_BASE_URL = "https://github.com/"
MAVEN_BASE_URL = "https://repo1.maven.org/maven2/"

def update_excel_compare():
    if not os.path.exists(excel_file_path):
        return

    df = pd.read_excel(excel_file_path)
    df.columns = [str(c).strip() for c in df.columns]
    cols = df.columns.tolist()

    # 自动识别 OWNER 和 REPO 列
    owner_col = next((c for c in cols if 'owner' in c.lower()), None)
    repo_col = next((c for c in cols if 'repo' in c.lower()), None)

    if not owner_col or not repo_col:
        return

    # --- 1. 生成 GITHUB_URL (带 /compare 后缀) ---
    def make_github(row):
        u = str(row[owner_col]).strip()
        r = str(row[repo_col]).strip()
        if u and r and u.lower() != 'nan' and r.lower() != 'nan':
            # 在仓库路径后追加 /compare
            return f"{GITHUB_BASE_URL}{u}/{r}/compare"
        return ""

    # --- 2. 生成 MAVEN_URL ---
    def make_maven(row):
        gid = str(row.get('target_group_id', '')).strip()
        aid = str(row.get('target_artifact_id', '')).strip()
        if gid and aid and gid.lower() != 'nan' and aid.lower() != 'nan':
            return MAVEN_BASE_URL + gid.replace('.', '/') + '/' + aid + '/'
        return ""

    df['GITHUB_URL'] = df.apply(make_github, axis=1)
    df['MAVEN_URL'] = df.apply(make_maven, axis=1)

    # --- 3. 更新 HEAD_TAG 和 BASE_TAG ---
    if os.path.exists(head_tag_json_file_path) and os.path.exists(versions_json_file_path):
        with open(head_tag_json_file_path, 'r', encoding='utf-8') as f:
            cve_result_data = json.load(f)
        with open(versions_json_file_path, 'r', encoding='utf-8') as f:
            cve_maven_versions = json.load(f)

        cve_head_tags = {k: str(v['affected'][0]).strip() for k, v in cve_result_data.items() 
                         if isinstance(v, dict) and v.get('affected')}

        for index, row in df.iterrows():
            cve_id = str(row['cve_id']).strip()
            
            if cve_id in cve_head_tags:
                head_tag = cve_head_tags[cve_id]
                df.at[index, 'HEAD_TAG'] = head_tag
                
                if cve_id in cve_maven_versions:
                    versions = cve_maven_versions[cve_id]
                    if head_tag in versions:
                        idx = versions.index(head_tag)
                        df.at[index, 'BASE_TAG'] = versions[idx - 1] if idx > 0 else "FIRST_VERSION_NO_BASE_TAG"

    # --- 4. 保存文件 ---
    try:
        df.to_excel(excel_file_path, index=False, engine='openpyxl')
    except:
        pass

if __name__ == "__main__":
    update_excel_compare()