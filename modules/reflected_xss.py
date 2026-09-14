import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.colors import Colors as C
from core.config import Config

class ReflectedXSS:
    name = "Reflected XSS Scanner"

    def __init__(self, url):
        self.url = url
        self.findings = []

    def run(self):
        print(f"\n{C.BLUE}{'=' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}💉 REFLECTED XSS SCANNER{C.RESET}")
        print(f"{C.BLUE}{'=' * 60}{C.RESET}")

        parsed = urlparse(self.url)
        if not parsed.query:
            print(f"  {C.warning('No URL parameters found. Add params like ?q=test')}")
            print(f"  {C.info('Example: http://target.com/search?q=test')}")
            return self.findings

        params = parse_qs(parsed.query, keep_blank_values=True)
        payloads = Config.XSS_PAYLOADS
        total_tests = len(params) * len(payloads)
        done = 0

        print(f"  {C.info(f'Parameters: {list(params.keys())}')}")
        print(f"  {C.info(f'Payloads: {len(payloads)}')}")
        print(f"  {C.info(f'Total tests: {total_tests}')}\n")

        for param_name in params:
            for payload in payloads:
                done += 1
                if done % 5 == 0 or done == total_tests:
                    C.progress(done, total_tests, f"Testing {param_name}...")

                test_params = dict(params)
                test_params[param_name] = [payload]
                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query_string, parsed.fragment
                ))

                try:
                    resp = requests.get(test_url, timeout=Config.TIMEOUT, headers=Config.HEADERS)
                    body = resp.text

                    if payload in body:
                        context = self._get_context(body, payload)
                        severity = self._assess_severity(context, payload)

                        finding = {
                            "type": "Reflected XSS",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "context": context,
                            "severity": severity
                        }
                        self.findings.append(finding)
                        print(f"\n    {C.vuln(f'{param_name} = {payload}')}")
                        print(f"      {C.DIM}Context: {context} | Severity: {severity}{C.RESET}")

                except Exception:
                    pass

        if self.findings:
            print(f"\n  {C.RED}{C.BOLD}[!] Reflected Reflection Found: {len(self.findings)}{C.RESET}")
        else:
            print(f"\n  {C.safe('No reflected patterns detected')}")

        return self.findings

    def _get_context(self, html, payload):
        idx = html.find(payload)
        if idx == -1:
            return "Unknown"
        before = html[max(0, idx - 50):idx].lower()

        if '<script' in before and '</script' not in before:
            return "Inside <script> tag"
        elif '<' in before and '>' not in before.split('<')[-1]:
            return "Inside HTML attribute"
        elif 'on' in before and '=' in before:
            return "Inside event handler"
        elif '<!--' in before and '-->' not in before:
            return "Inside HTML comment"
        elif '<style' in before and '</style' not in before:
            return "Inside <style> tag"
        else:
            return "HTML body (text context)"

    def _assess_severity(self, context, payload):
        if "script" in context.lower():
            return "HIGH"
        elif "attribute" in context.lower() or "event" in context.lower():
            return "HIGH"
        elif "body" in context.lower() and "<" in payload:
            return "MEDIUM"
        elif "comment" in context.lower():
            return "LOW"
        else:
            return "LOW"
