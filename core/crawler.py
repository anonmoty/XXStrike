import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.colors import Colors as C
from core.config import Config

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.parsed = urlparse(base_url)
        self.domain = self.parsed.netloc
        self.visited = set()
        self.forms = []
        self.params = []
        self.urls = []

    def crawl(self, max_pages=20):
        print(f"\n  {C.info(f'Crawling: {self.base_url}')}")
        print(f"  {C.info(f'Max pages: {max_pages}')}\n")
        self._crawl_page(self.base_url, max_pages)
        print(f"\n  {C.success(f'Pages crawled: {len(self.visited)}')}")
        print(f"  {C.success(f'Forms found: {len(self.forms)}')}")
        print(f"  {C.success(f'URLs with params: {len(self.params)}')}")
        return {
            "urls": list(self.visited),
            "forms": self.forms,
            "params": self.params
        }

    def _crawl_page(self, url, max_pages):
        if len(self.visited) >= max_pages:
            return
        if url in self.visited:
            return
        if self.domain not in urlparse(url).netloc:
            return

        self.visited.add(url)
        try:
            resp = requests.get(url, timeout=Config.TIMEOUT, headers=Config.HEADERS, allow_redirects=True)
            if resp.status_code != 200:
                return
            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                return

            soup = BeautifulSoup(resp.text, 'html.parser')

            # Extract forms
            for form in soup.find_all('form'):
                form_data = self._parse_form(form, url)
                if form_data:
                    self.forms.append(form_data)

            # Extract links with parameters
            for tag in soup.find_all('a', href=True):
                href = urljoin(url, tag['href'])
                parsed = urlparse(href)
                if self.domain in parsed.netloc and parsed.query:
                    if href not in self.params:
                        self.params.append(href)
                if self.domain in parsed.netloc and href not in self.visited:
                    self._crawl_page(href, max_pages)

        except Exception:
            pass

    def _parse_form(self, form, page_url):
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        full_action = urljoin(page_url, action) if action else page_url
        inputs = []

        for inp in form.find_all(['input', 'textarea', 'select']):
            inp_name = inp.get('name', '')
            inp_type = inp.get('type', 'text')
            if inp_name:
                inputs.append({
                    "name": inp_name,
                    "type": inp_type,
                    "value": inp.get('value', '')
                })

        if inputs:
            return {
                "action": full_action,
                "method": method,
                "inputs": inputs,
                "page": page_url
            }
        return None
