import requests
from core.colors import Colors as C
from core.config import Config

class HeaderXSS:
    name = "XSS Header Audit"

    def __init__(self, url):
        self.url = url

    def run(self):
        print(f"\n{C.BLUE}{'═' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}🔒 XSS-RELATED HEADER AUDIT{C.RESET}")
        print(f"{C.BLUE}{'═' * 60}{C.RESET}")

        results = {"headers": {}, "score": 0, "issues": [], "grade": "F"}

        try:
            resp = requests.get(self.url, timeout=Config.TIMEOUT, headers=Config.HEADERS, allow_redirects=True)
            headers = resp.headers

            checks = {
                "X-XSS-Protection": {
                    "expected": "1; mode=block",
                    "desc": "Browser XSS filter",
                    "weight": 2
                },
                "Content-Security-Policy": {
                    "expected": "present",
                    "desc": "Prevents inline script execution",
                    "weight": 3
                },
                "X-Content-Type-Options": {
                    "expected": "nosniff",
                    "desc": "Prevents MIME-type sniffing",
                    "weight": 2
                },
                "X-Frame-Options": {
                    "expected": "DENY or SAMEORIGIN",
                    "desc": "Prevents clickjacking (iframe XSS)",
                    "weight": 1
                },
                "Content-Type": {
                    "expected": "charset",
                    "desc": "Charset prevents UTF-7 XSS",
                    "weight": 2
                },
                "Referrer-Policy": {
                    "expected": "present",
                    "desc": "Controls referrer leakage",
                    "weight": 1
                },
                "Permissions-Policy": {
                    "expected": "present",
                    "desc": "Restricts browser features",
                    "weight": 1
                }
            }

            score = 0
            max_score = sum(c["weight"] for c in checks.values())

            print(f"\n  {C.CYAN}{'Header':35s} {'Status':10s} {'Value'}{C.RESET}")
            print(f"  {C.DIM}{'─' * 70}{C.RESET}")

            for header, check in checks.items():
                value = headers.get(header, '')
                if value:
                    score += check["weight"]
                    status = f"{C.GREEN}✓ SET{C.RESET}"
                    print(f"  {header:35s} {status}    {C.DIM}{value[:40]}{C.RESET}")
                else:
                    results["issues"].append(f"Missing: {header} ({check['desc']})")
                    status = f"{C.RED}✗ MISS{C.RESET}"
                    print(f"  {header:35s} {status}    {C.DIM}{check['desc']}{C.RESET}")

            results["score"] = f"{score}/{max_score}"
            pct = int(score / max_score * 100) if max_score > 0 else 0

            if pct >= 85:
                grade = "A+"
            elif pct >= 70:
                grade = "A"
            elif pct >= 55:
                grade = "B"
            elif pct >= 40:
                grade = "C"
            elif pct >= 25:
                grade = "D"
            else:
                grade = "F"

            results["grade"] = grade
            grade_color = C.GREEN if pct >= 70 else C.YELLOW if pct >= 40 else C.RED

            print(f"\n  {C.BOLD}XSS Protection Score: {grade_color}{results['score']} ({pct}%) — Grade: {grade}{C.RESET}")

            if results["issues"]:
                print(f"\n  {C.YELLOW}Recommendations:{C.RESET}")
                for issue in results["issues"]:
                    print(f"    {C.DIM}→ {issue}{C.RESET}")

        except Exception as e:
            print(f"  {C.error(f'Header audit failed: {e}')}")

        return results
