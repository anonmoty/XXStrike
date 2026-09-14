import requests
import time
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.colors import Colors as C
from core.config import Config

class Fuzzer:
    name = "XSS Fuzzer"

    def __init__(self, url):
        self.url = url
        self.findings = []

    def _generate_random_tag(self):
        tag = "xxs" + "".join(random.choices(string.ascii_lowercase, k=4))
        return tag

    def run(self):
        print(f"\n{C.BLUE}{'=' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}🎯 XSS FUZZER (Advanced){C.RESET}")
        print(f"{C.BLUE}{'=' * 60}{C.RESET}")

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            print(f"  {C.warning('No URL parameters found to fuzz')}")
            print(f"  {C.info('Example: http://target.com/page?q=test')}")
            return self.findings

        param_names = list(params.keys())
        print(f"  {C.info(f'Target params: {param_names}')}")

        # ---- Fuzz Categories ----
        fuzz_vectors = {
            "Basic Tags": [
                "<xxs>",
                "<xxs/>",
                "<xxs ></xxs>",
                "<xxs foo=bar>",
                "<xxs:xxs>",
            ],
            "Event Handlers": [
                "<img src=x onerror=xxs>",
                "<body onload=xxs>",
                "<svg onload=xxs>",
                "<input onfocus=xxs autofocus>",
                "<details open ontoggle=xxs>",
                "<marquee onstart=xxs>",
                "<video onerror=xxs>",
                "<audio onerror=xxs>",
                "<iframe onload=xxs>",
                "<object onerror=xxs>",
            ],
            "Encoding Bypass": [
                "%3Cxxs%3E",
                "&#60;xxs&#62;",
                "&#x3C;xxs&#x3E;",
                "\\u003cxxs\\u003e",
                "%253Cxxs%253E",
                "<xxs>",
                "<<xxs>>",
                "<xxs\x00>",
            ],
            "Context Breakers": [
                "'xxs'",
                '"xxs"',
                "`xxs`",
                "';xxs;//",
                '";xxs;//',
                "</xxs>",
                "/*xxs*/",
                "//xxs",
                "xxs\\",
                "xxs\n",
                "xxs\r\n",
            ],
            "Protocol Handlers": [
                "javascript:xxs",
                "data:text/html,xxs",
                "vbscript:xxs",
                "livescript:xxs",
            ],
            "Nested/Obfuscated": [
                "<svg><xxs>",
                "<math><xxs>",
                "<noscript><xxs></noscript>",
                "<template><xxs>",
                "<foreignObject><xxs>",
                "<xxs style=xxs>",
                "<xxs class=xxs>",
                "<xxs id=xxs>",
            ],
        }

        all_payloads = []
        for category, payloads in fuzz_vectors.items():
            for p in payloads:
                all_payloads.append((category, p))

        total_tests = len(param_names) * len(all_payloads)
        done = 0
        reflected_count = 0
        blocked_count = 0

        print(f"  {C.info(f'Total fuzz vectors: {len(all_payloads)}')}")
        print(f"  {C.info(f'Total tests: {total_tests}')}\n")

        for param_name in param_names:
            print(f"\n  {C.CYAN}[Fuzzing param: {param_name}]{C.RESET}")

            for category, payload in all_payloads:
                done += 1
                if done % 10 == 0 or done == total_tests:
                    C.progress(done, total_tests, f"Fuzzing...")

                test_params = dict(params)
                test_params[param_name] = [payload]
                query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query, parsed.fragment
                ))

                try:
                    resp = requests.get(
                        test_url,
                        timeout=Config.TIMEOUT,
                        headers=Config.HEADERS,
                        allow_redirects=False
                    )

                    status = resp.status_code
                    body = resp.text

                    # Check if blocked by WAF
                    if status in [403, 406, 429, 503]:
                        blocked_count += 1
                        continue

                    # Check reflection
                    if payload in body:
                        reflected_count += 1
                        context = self._detect_context(body, payload)
                        severity = self._rate_severity(context, category)

                        finding = {
                            "type": "Fuzz Reflection",
                            "url": test_url,
                            "param": param_name,
                            "payload": payload,
                            "category": category,
                            "context": context,
                            "severity": severity,
                            "status_code": status
                        }
                        self.findings.append(finding)
                        print(f"\n    {C.vuln(f'[{category}] {param_name}={payload}')}")
                        print(f"      {C.DIM}Context: {context} | Severity: {severity}{C.RESET}")

                    # Check partial reflection (encoded)
                    elif "xxs" in body.lower():
                        idx = body.lower().find("xxs")
                        snippet = body[max(0, idx - 20):idx + 20]
                        snippet_clean = snippet.replace("\n", " ").strip()
                        print(f"\n    {C.warning(f'Partial match: ...{snippet_clean}...')}")

                except requests.exceptions.Timeout:
                    pass
                except Exception:
                    pass

        # Summary
        print(f"\n  {C.BOLD}{'─' * 50}{C.RESET}")
        print(f"  {C.info(f'Total tests: {total_tests}')}")
        print(f"  {C.info(f'Reflections: {reflected_count}')}")
        print(f"  {C.info(f'Blocked by WAF: {blocked_count}')}")

        if self.findings:
            print(f"\n  {C.RED}{C.BOLD}[!] Fuzzer found {len(self.findings)} reflection points!{C.RESET}")
        else:
            print(f"\n  {C.safe('No significant reflections found')}")

        return self.findings

    def _detect_context(self, html, payload):
        idx = html.find(payload)
        if idx == -1:
            return "Unknown"

        before = html[max(0, idx - 80):idx].lower()
        after = html[idx + len(payload):idx + len(payload) + 80].lower()

        if "<script" in before and "</script" not in before:
            return "Inside <script>"
        elif "<style" in before and "</style" not in before:
            return "Inside <style>"
        elif "<!--" in before and "-->" not in before:
            return "Inside comment"
        elif '="' in before and '"' not in before.split('="')[-1]:
            return "Inside attribute (double quote)"
        elif "='" in before and "'" not in before.split("='")[-1]:
            return "Inside attribute (single quote)"
        elif "<" in before and ">" not in before.split("<")[-1]:
            return "Inside HTML tag"
        else:
            return "HTML body text"

    def _rate_severity(self, context, category):
        if "script" in context.lower():
            return "HIGH"
        elif "attribute" in context.lower():
            return "HIGH"
        elif "tag" in context.lower() and "Event" in category:
            return "HIGH"
        elif "body" in context.lower():
            return "MEDIUM"
        elif "comment" in context.lower():
            return "LOW"
        elif "style" in context.lower():
            return "LOW"
        else:
            return "LOW"
