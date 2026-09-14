import requests
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from core.colors import Colors as C
from core.config import Config

class ParamFinder:
    name = "Parameter Discovery"

    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc

    def run(self):
        print(f"\n{C.BLUE}{'=' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}🔍 PARAMETER DISCOVERY{C.RESET}")
        print(f"{C.BLUE}{'=' * 60}{C.RESET}")

        results = {"url_params": [], "form_params": [], "hidden_params": [], "json_params": []}

        try:
            resp = requests.get(self.url, timeout=Config.TIMEOUT, headers=Config.HEADERS)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # 1. URL Parameters
            parsed = urlparse(self.url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for key in params:
                    results["url_params"].append(key)
                    print(f"  {C.vuln(f'URL Param: {key}')}")

            # 2. Common parameter names to test
            common_params = ['q', 'search', 'id', 'page', 'file', 'url', 'path',
                           'name', 'query', 'keyword', 'term', 'input', 'value',
                           'data', 'text', 'msg', 'message', 'comment', 'title',
                           'content', 'body', 'desc', 'description', 'redirect',
                           'return', 'next', 'callback', 'jsonp', 'api_key',
                           'token', 'user', 'email', 'username']

            print(f"\n  {C.info('Testing common parameter names...')}")
            found_params = []
            total = len(common_params)
            for i, param in enumerate(common_params):
                if (i + 1) % 5 == 0 or (i + 1) == total:
                    C.progress(i + 1, total, f"Testing ?{param}=")
                test_url = f"{self.url}{'&' if parsed.query else '?'}{param}=xxstest"
                try:
                    r = requests.get(test_url, timeout=5, headers=Config.HEADERS)
                    if 'xxstest' in r.text:
                        found_params.append(param)
                        print(f"\n    {C.vuln(f'Reflected param: {param}')}")
                except Exception:
                    pass

            results["reflected_params"] = found_params

            # 3. Form Parameters
            for form in soup.find_all('form'):
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name', '')
                    inp_type = inp.get('type', 'text')
                    if name:
                        results["form_params"].append({"name": name, "type": inp_type})
                        if inp_type == 'hidden':
                            results["hidden_params"].append(name)

            # 4. JavaScript variables
            scripts = soup.find_all('script')
            js_params = []
            for script in scripts:
                if script.string:
                    for source in Config.DOM_SOURCES:
                        if source in script.string:
                            js_params.append(source)
            results["js_sources"] = list(set(js_params))

            # Summary
            form_count = len(results["form_params"])
            refl_count = len(found_params)
            total_params = len(results["url_params"]) + form_count + refl_count
            print(f"\n  {C.success(f'Total parameters found: {total_params}')}")
            print(f"  {C.success(f'Reflected parameters: {refl_count}')}")
            print(f"  {C.success(f'Form inputs: {form_count}')}")

        except Exception as e:
            print(f"  {C.error(f'Parameter discovery failed: {e}')}")

        return results
