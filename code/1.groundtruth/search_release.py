import requests

GITHUB_API_BASE_URL = "https://api.github.com"
OWNER = "spring-projects"  # 替换为实际的组织/用户
REPO = "spring-framework"   # 替换为实际的仓库名
TARGET_COMMIT_SHA = "7a7df66" # 您的目标 commit hash
GITHUB_TOKEN = "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" # 如果有速率限制，请取消注释并设置

def get_json(url):
    """辅助函数，用于发送 GET 请求并解析 JSON 响应"""
    headers = {}
    # if GITHUB_TOKEN:
    #     headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    response = requests.get(url, headers=headers)
    response.raise_for_status() # 如果请求失败 (例如 4xx 或 5xx 状态码)，则抛出异常
    return response.json()

def get_all_tags(owner, repo):
    """获取一个仓库的所有标签"""
    tags = []
    page = 1
    while True:
        url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/tags?per_page=100&page={page}"
        print(f"Fetching tags from: {url}")
        current_tags = get_json(url)
        if not current_tags:
            break
        tags.extend(current_tags)
        page += 1
    return tags

def is_ancestor(ancestor_sha, descendant_sha, owner, repo):
    """
    检查 ancestor_sha 是否是 descendant_sha 的祖先。
    这是通过检查比较 API 实现的。
    注意：此方法可能因大量API调用而导致速率限制。
    更高效的方法可能是克隆仓库并在本地使用 Git 命令，或对Commit的父节点进行递归遍历。
    """
    url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo}/compare/{ancestor_sha}...{descendant_sha}"
    try:
        data = get_json(url)
        # 如果 ancestor_sha 是 descendant_sha 的祖先，
        # 则 status 会是 'ahead' 或 'identical' (如果 ancestor_sha == descendant_sha)
        # 或者 'diverged'/'behind'，但只要能在历史中找到，就说明是祖先。
        # 最直接的判断是看其是否在 'commits' 列表中。
        # 更准确的判断是利用 Git 的概念，例如 Git Python 库会更方便。
        # 对于简单的API调用，如果 compare 成功并返回 commits 列表，
        # 且目标 commit_sha 在其中，则可以认为它是祖先或相等。
        
        # 简单判断: 如果 compare 成功且没有 404/422 错误，可以认为是祖先
        # 但 GitHub API 的 compare 端点不是直接的 'is_ancestor' 检查
        # 最准确的方法是获取 descendant_sha 的完整历史并查找 ancestor_sha
        
        # 更可靠的检查方法是获取 descendant_sha 的完整历史（通过获取其父提交）
        # 这里为了简化，我们假设 if response.status_code == 200 implies ancestor
        # 或者更精确地，查看其 status 是否是 'identical' 或 'ahead'
        if data.get('status') in ['ahead', 'identical']:
            return True
        # 如果是 diverged，也可能是祖先，需要进一步判断
        # GitHub API并没有直接的“is_ancestor”布尔值，这需要我们自己遍历
        
        # 替代方案：获取 descendant_sha 的所有父提交直到根，然后检查 ancestor_sha 是否在其中
        # 这会产生大量API请求，效率不高
        # 更好的方法是使用 gitPython 库在本地克隆仓库后判断。
        return False # 默认认为不是，除非有更精确的判断

    except requests.exceptions.RequestException as e:
        # 如果发生 404 Not Found 或 422 Unprocessable Entity, 可能是没有关系
        print(f"Error checking ancestor relationship: {e}")
        return False

def find_commit_in_tags(owner, repo, target_commit_sha):
    """
    查找目标 commit 存在于哪个 release (tag) 中。
    此方法为简化演示，可能在大型仓库上效率不高，
    因为它需要遍历所有标签并对每个标签进行潜在的祖先检查。
    """
    all_tags = get_all_tags(owner, repo)
    
    found_releases = []
    
    print(f"Searching for commit {target_commit_sha} in {len(all_tags)} tags...")
    
    for tag in all_tags:
        tag_name = tag['name']
        tag_commit_sha = tag['commit']['sha']
        
        # 如果标签直接指向目标 commit
        if tag_commit_sha == target_commit_sha:
            print(f"Commit {target_commit_sha} directly matches tag '{tag_name}' ({tag_commit_sha})")
            found_releases.append(tag_name)
            continue
            
        # 如果目标 commit 是标签指向 commit 的祖先
        # 这是一个复杂的逻辑，GitHub API没有直接的 is_ancestor。
        # 真正实现时，需要获取 tag_commit_sha 的历史，并检查 target_commit_sha 是否在其中。
        # 最直接但在API层面略微复杂的方式是获取tag_commit_sha的graph，或者递归获取其父提交。
        # 
        # 简化版（不准确，仅为演示概念）：
        # 你可以认为如果tag_commit_sha是target_commit_sha的“后代”，那么tag包含这个commit
        # 这需要一个能够判断“A是否包含B”或“A是否B的祖先”的API
        # GitHub REST API v3 本身没有直接的 API 来判断一个 SHA 是否是另一个 SHA 的祖先。
        # 通常做法是：获取 tag_commit_sha 的父提交链，然后检查 target_commit_sha 是否在该链中。
        # 这涉及到对 '/commits/{ref}' 端点的多次调用以获取父提交。
        #
        # 为了避免过多API调用和复杂性，通常会：
        # 1. 下载仓库使用本地 Git 命令 (如 `git tag --contains <commit>`)。
        # 2. 如果非要API，需要实现一个递归获取父提交的函数，然后检查。
        #
        # 鉴于此，下面仅作示意，实际可能需要更复杂的逻辑或外部库/工具。
        # 假设我们有一个可靠的 `is_ancestor` 函数：
        # if is_ancestor(target_commit_sha, tag_commit_sha, owner, repo):
        #     print(f"Commit {target_commit_sha} is an ancestor of tag '{tag_name}' ({tag_commit_sha})")
        #     found_releases.append(tag_name)
    
    return found_releases

if __name__ == "__main__":
    print(f"Attempting to find release versions for commit: {TARGET_COMMIT_SHA}")
    
    releases = find_commit_in_tags(OWNER, REPO, TARGET_COMMIT_SHA)
    
    if releases:
        print(f"\nCommit {TARGET_COMMIT_SHA} is found in the following release(s) / tag(s):")
        for release in releases:
            print(f"- {release}")
    else:
        print(f"\nCould not determine specific release version for commit {TARGET_COMMIT_SHA} using direct tag matching.")
        print("This could mean:")
        print("  - The commit is not directly tagged.")
        print("  - The commit is part of an untagged development branch.")
        print("  - The commit is an ancestor of a tag, but the API logic for ancestor checking is not fully implemented here.")
        print("  - It's a very old commit not associated with a specific release tag.")