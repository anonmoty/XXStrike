import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from core.colors import Colors as C
from core.config import Config

class JSAnalysis:
    name = "JavaScript Sink Analysis"

    def __init__(self, url):
        self.url = url

    def run(self):
        print(f"\n{C.BLUE}{'=' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}📜 JAVASCRIPT SINK ANALYSIS{C.RESET}")
        print(f"{C.BLUE}{'=' * 60}{C.RESET}")

        results = {"external_scripts": [], "inline_scripts": 0, "dangerous_patterns": [], "event_handlers": []}

        try:
            resp = requests.get(self.url, timeout=Config.TIMEOUT, headers=Config.HEADERS)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # External scripts
            ext_scripts = soup.find_all('script', src=True)
            for s in ext_scripts:
                src = urljoin(self.url, s['src'])
                results["external_scripts"].append(src)

            ext_count = len(results["external_scripts"])
            print(f"  {C.info(f'External scripts: {ext_count}')}")
            for src in results["external_scripts"][:10]:
                print(f"    {C.DIM}→ {src}{C.RESET}")

            # Inline scripts analysis
            inline_scripts = soup.find_all('script')
            inline_count = 0
            all_js = ""
            for s in inline_scripts:
                if s.string:
                    inline_count += 1
                    all_js += s.string + "\n"

            results["inline_scripts"] = inline_count
            print(f"  {C.info(f'Inline scripts: {inline_count}')}")

            # Dangerous patterns
            dangerous = {
                "eval()": r'eval\s*\(',
                "document.write()": r'document\.write\s*\(',
                "innerHTML": r'\.innerHTML\s*=',
                "outerHTML": r'\.outerHTML\s*=',
                "setTimeout(string)": r'setTimeout\s*\(\s*["\']',
                "setInterval(string)": r'setInterval\s*\(\s*["\']',
                "Function()": r'new\s+Function\s*\(',
                "location.assign": r'location\.assign\s*\(',
                "location.replace": r'location\.replace\s*\(',
                "window.open": r'window\.open\s*\(',
                "postMessage": r'\.postMessage\s*\(',
                "insertAdjacentHTML": r'\.insertAdjacentHTML\s*\(',
            }

            print(f"\n  {C.info('Scanning for dangerous JS patterns...')}")
            for pattern_name, regex in dangerous.items():
                matches = re.findall(regex, all_js, re.IGNORECASE)
                if matches:
                    match_count = len(matches)
                    results["dangerous_patterns"].append({
                        "pattern": pattern_name,
                        "count": match_count
                    })
                    print(f"    {C.vuln(f'{pattern_name}: {match_count} occurrence(s)')}")

            # Event handlers in HTML
            event_attrs = ['onclick', 'onload', 'onerror', 'onmouseover',
                          'onfocus', 'onblur', 'onsubmit', 'onchange',
                          'onkeydown', 'onkeyup', 'oninput']
            for attr in event_attrs:
                tags = soup.find_all(attrs={attr: True})
                if tags:
                    tag_count = len(tags)
                    results["event_handlers"].append({
                        "event": attr,
                        "count": tag_count
                    })
                    print(f"    {C.warning(f'{attr}: {tag_count} element(s)')}")

            if not results["dangerous_patterns"] and not results["event_handlers"]:
                print(f"\n  {C.safe('No dangerous JS patterns found')}")
            else:
                total = len(results["dangerous_patterns"]) + len(results["event_handlers"])
                print(f"\n  {C.RED}[!] {total} potential XSS vectors in JavaScript{C.RESET}")

        except Exception as e:
            print(f"  {C.error(f'JS analysis failed: {e}')}")

        return results
