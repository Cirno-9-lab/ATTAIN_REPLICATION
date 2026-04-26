import requests
import os
import json
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, unquote

class CVEStrictScraper:
    def __init__(self):
        os.environ['HTTP_PROXY'] = PROXIES['http']
        os.environ['HTTPS_PROXY'] = PROXIES['https']
        # 严格匹配核心补丁路径
        self.patch_re = re.compile(r'https?://github\.com/[\w\-/]+/(?:commit|pull|blob)/[a-f0-9]+')
        self.ghsa_id_re = re.compile(r'GHSA-[a-z0-9-]+', re.IGNORECASE)

    def _clean_search_url(self, url):
        if url.startswith('//'): url = 'https:' + url
        parsed = urlparse(url)
        if 'duckduckgo.com' in parsed.netloc:
            query_params = parse_qs(parsed.query)
            if 'uddg' in query_params: return unquote(query_params['uddg'][0])
        return url

    def extract_from_nvd(self, cve_id):
        """仅从 NVD 的 References 表格中提取直连 GitHub 链接"""
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        print(f"[1] 扫描 NVD 表格: {url}")
        headers = {"User-Agent": "Mozilla/5.0"}
        links = []
        try:
            resp = requests.get(url, headers=headers, timeout=20, proxies=PROXIES)
            soup = BeautifulSoup(resp.text, 'html.parser')
            # 准确定位 References 所在的表格
            table = soup.find('table', {'data-testid': 'vuln-hyperlinks-table'})
            if table:
                for a in table.find_all('a', href=True):
                    href = a['href']
                    if "github.com" in href:
                        links.append(href)
        except Exception as e:
            print(f"    [!] NVD 请求失败: {e}")
        return links

    def extract_from_ghsa(self, cve_id):
        """搜索并仅从 GitHub Advisory 的 References 区域提取链接"""
        query = f"{cve_id} site:github.com/advisories"
        search_url = f"https://html.duckduckgo.com/html/?q={query}"
        print(f"[2] 执行定向搜索: {query}")
        
        headers = {"User-Agent": "Mozilla/5.0"}
        links = []
        try:
            resp = requests.get(search_url, headers=headers, timeout=15, proxies=PROXIES)
            soup = BeautifulSoup(resp.text, 'html.parser')
            results = soup.find_all('a', class_='result__a', limit=2)
            
            for r in results:
                raw_url = self._clean_search_url(r['href'])
                # 清洗为纯净的 GHSA 详情页链接
                match = self.ghsa_id_re.search(raw_url)
                if match:
                    pure_url = f"https://github.com/advisories/{match.group(0)}"
                    print(f"    [>] 访问 Advisory 详情: {pure_url}")
                    
                    adv_resp = requests.get(pure_url, headers=headers, timeout=15, proxies=PROXIES)
                    adv_soup = BeautifulSoup(adv_resp.text, 'html.parser')
                    
                    # 仅定位 References 标题后的内容区域
                    ref_header = adv_soup.find(['h2', 'h3'], string=re.compile(r'References', re.I))
                    if ref_header:
                        # 遍历该标题后的兄弟节点，直到遇到下一个标题
                        for sibling in ref_header.find_next_siblings():
                            if sibling.name in ['h2', 'h3']: break
                            for a in sibling.find_all('a', href=True):
                                if "github.com" in a['href'] and "/advisories/" not in a['href']:
                                    links.append(a['href'])
        except Exception as e:
            print(f"    [!] GHSA 搜索/提取失败: {e}")
        return links

    def run(self, cve_id):
        final_targets = set()
        
        # 执行两个核心捕获任务
        nvd_links = self.extract_from_nvd(cve_id)
        ghsa_links = self.extract_from_ghsa(cve_id)
        
        final_targets.update(nvd_links)
        final_targets.update(ghsa_links)
        
        # 仅保留符合 Patch 特征的链接（commit/pull/blob）
        cleaned_targets = [l for l in final_targets if self.patch_re.search(l)]
        
        print(f"[*] 任务结束。锁定精确链接数: {len(cleaned_targets)}")
        
        all_results = {"cve_id": cve_id, "findings": []}
        for url in cleaned_targets:
            print(f"    [+] 抓取正文: {url}")
            try:
                r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, proxies=PROXIES)
                s = BeautifulSoup(r.text, 'html.parser')
                # 剔除噪音
                for tag in s(["script", "style", "nav", "footer", "header", "svg"]): tag.decompose()
                content = s.get_text(separator=' ', strip=True)[:15000]
                all_results["findings"].append({"url": url, "content": content})
            except: continue

        # 存储
        os.makedirs("patch_info", exist_ok=True)
        with open(f"patch_info/{cve_id}.json", 'w', encoding='utf-8') as f:
            json.dump(all_results, f, ensure_ascii=False, indent=4)
        print(f"[OK] 结果已写入 patch_info/{cve_id}.json")

if __name__ == "__main__":
    target_cve = "CVE-2014-3625"
    scraper = CVEStrictScraper()
    scraper.run(target_cve)