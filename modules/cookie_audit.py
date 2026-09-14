import requests
from core.colors import Colors as C
from core.config import Config

class CookieAudit:
    name = "Cookie Security Audit"

    def __init__(self, url):
        self.url = url

    def run(self):
        print(f"\n{C.BLUE}{'=' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}🍪 COOKIE SECURITY AUDIT{C.RESET}")
        print(f"{C.BLUE}{'=' * 60}{C.RESET}")

        results = {"cookies": [], "issues": [], "score": 0}

        try:
            session = requests.Session()
            resp = session.get(self.url, timeout=Config.TIMEOUT, headers=Config.HEADERS, allow_redirects=True)

            cookies = session.cookies
            if not cookies:
                print(f"  {C.warning('No cookies set by target')}")
                return results

            print(f"  {C.info(f'Cookies found: {len(cookies)}')}\n")

            score = 0
            max_score = len(cookies) * 3

            for cookie in cookies:
                issues = []
                cookie_score = 0

                # Check Secure flag
                if cookie.secure:
                    cookie_score += 1
                    secure_status = f"{C.GREEN}✓{C.RESET}"
                else:
                    issues.append("Missing Secure flag")
                    secure_status = f"{C.RED}✗{C.RESET}"

                # Check HttpOnly flag
                if cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in str(cookie._rest).lower():
                    cookie_score += 1
                    httponly_status = f"{C.GREEN}✓{C.RESET}"
                else:
                    set_cookie = resp.headers.get('Set-Cookie', '')
                    if 'httponly' in set_cookie.lower():
                        cookie_score += 1
                        httponly_status = f"{C.GREEN}✓{C.RESET}"
                    else:
                        issues.append("Missing HttpOnly flag (XSS risk!)")
                        httponly_status = f"{C.RED}✗{C.RESET}"

                # Check SameSite
                set_cookie = resp.headers.get('Set-Cookie', '')
                if 'samesite' in set_cookie.lower():
                    cookie_score += 1
                    samesite_status = f"{C.GREEN}✓{C.RESET}"
                else:
                    issues.append("Missing SameSite attribute")
                    samesite_status = f"{C.YELLOW}?{C.RESET}"

                score += cookie_score

                print(f"  {C.CYAN}Cookie: {cookie.name}{C.RESET}")
                print(f"    Secure:   {secure_status}")
                print(f"    HttpOnly: {httponly_status}")
                print(f"    SameSite: {samesite_status}")
                if issues:
                    for issue in issues:
                        print(f"    {C.RED}→ {issue}{C.RESET}")
                        results["issues"].append(f"{cookie.name}: {issue}")
                print()

                results["cookies"].append({
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "issues": issues
                })

            results["score"] = f"{score}/{max_score}"
            pct = int(score / max_score * 100) if max_score > 0 else 100
            print(f"  {C.BOLD}Cookie Security Score: {pct}%{C.RESET}")

            if results["issues"]:
                print(f"\n  {C.RED}[!] {len(results['issues'])} cookie security issues found{C.RESET}")
                print(f"  {C.DIM}Missing HttpOnly makes cookies accessible via XSS{C.RESET}")
            else:
                print(f"\n  {C.safe('All cookies properly secured')}")

        except Exception as e:
            print(f"  {C.error(f'Cookie audit failed: {e}')}")

        return results
