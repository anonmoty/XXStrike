import requests
import re
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
from core.colors import Colors as C
from core.config import Config

class HTMLParser:
    name = "HTML Parser & Injection Point Analyzer"

    def __init__(self, url):
        self.url = url

    def run(self):
        print(f"\n{C.BLUE}{'=' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}🔬 HTML PARSER & INJECTION ANALYZER{C.RESET}")
        print(f"{C.BLUE}{'=' * 60}{C.RESET}")

        results = {
            "injection_points": [],
            "dangerous_tags": [],
            "dangerous_attrs": [],
            "sanitization": [],
            "meta_info": {},
            "forms_analysis": [],
            "comments": [],
            "iframes": [],
            "scripts_analysis": [],
        }

        try:
            resp = requests.get(
                self.url,
                timeout=Config.TIMEOUT,
                headers=Config.HEADERS,
                allow_redirects=True
            )
            html = resp.text
            soup = BeautifulSoup(html, 'html.parser')

            # ---- 1. Page Meta Info ----
            print(f"\n  {C.CYAN}[Page Information]{C.RESET}")
            title = soup.title.string if soup.title else "N/A"
            charset = "N/A"
            meta_tag = soup.find('meta', attrs={'charset': True})
            if meta_tag:
                charset = meta_tag.get('charset')
            else:
                meta_ct = soup.find('meta', attrs={'http-equiv': re.compile('content-type', re.I)})
                if meta_ct:
                    charset = meta_ct.get('content', '')

            results["meta_info"] = {
                "title": title,
                "charset": charset,
                "status_code": resp.status_code,
                "content_length": len(html),
                "content_type": resp.headers.get('Content-Type', 'N/A'),
            }

            print(f"    {C.info(f'Title: {title}')}")
            print(f"    {C.info(f'Charset: {charset}')}")
            print(f"    {C.info(f'Size: {len(html)} bytes')}")

            if 'utf-8' not in charset.lower() and 'utf8' not in charset.lower():
                print(f"    {C.warning('Non-UTF-8 charset may allow UTF-7 XSS!')}")
                results["sanitization"].append("Non-UTF-8 charset detected")

            # ---- 2. Dangerous HTML Tags ----
            print(f"\n  {C.CYAN}[Dangerous Tags]{C.RESET}")
            dangerous_tags = {
                "script": "Executes JavaScript",
                "iframe": "Embeds external content",
                "object": "Embeds plugins/active content",
                "embed": "Embeds external resources",
                "applet": "Java applets (deprecated)",
                "form": "User input submission",
                "input": "User input field",
                "textarea": "Multi-line user input",
                "select": "Dropdown user input",
                "base": "Base URL override (can redirect scripts)",
                "link": "External resource loading",
                "meta": "Can trigger redirects",
                "svg": "Can contain event handlers",
                "math": "Can contain event handlers",
                "video": "Can have event handlers",
                "audio": "Can have event handlers",
                "details": "ontoggle event",
                "marquee": "onstart/onbounce events",
            }

            for tag_name, desc in dangerous_tags.items():
                tags = soup.find_all(tag_name)
                if tags:
                    results["dangerous_tags"].append({
                        "tag": tag_name,
                        "count": len(tags),
                        "desc": desc
                    })
                    print(f"    {C.warning(f'<{tag_name}>: {len(tags)} found — {desc}')}")

            # ---- 3. Dangerous Attributes ----
            print(f"\n  {C.CYAN}[Dangerous Attributes]{C.RESET}")
            event_handlers = [
                'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
                'onmouseover', 'onmousemove', 'onmouseout', 'onmouseenter',
                'onmouseleave', 'onkeydown', 'onkeypress', 'onkeyup',
                'onfocus', 'onblur', 'onchange', 'oninput', 'onsubmit',
                'onreset', 'onselect', 'onload', 'onerror', 'onunload',
                'onresize', 'onscroll', 'onhashchange', 'onpopstate',
                'onanimationend', 'ontransitionend', 'ontoggle',
                'onwheel', 'ondrag', 'ondrop', 'oncopy', 'onpaste',
                'oncut', 'oncontextmenu', 'onabort', 'oncanplay',
                'onemptied', 'onended', 'onpause', 'onplay', 'onplaying',
                'onprogress', 'onseeked', 'onseeking', 'onstalled',
                'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting',
            ]

            found_handlers = {}
            for attr in event_handlers:
                tags = soup.find_all(attrs={attr: True})
                if tags:
                    found_handlers[attr] = len(tags)
                    results["dangerous_attrs"].append({
                        "attr": attr,
                        "count": len(tags)
                    })

            if found_handlers:
                for attr, count in sorted(found_handlers.items(), key=lambda x: -x[1])[:15]:
                    print(f"    {C.vuln(f'{attr}: {count} element(s)')}")
            else:
                print(f"    {C.safe('No inline event handlers found')}")

            # ---- 4. Injection Points Analysis ----
            print(f"\n  {C.CYAN}[Injection Points]{C.RESET}")

            # 4a. Search forms
            search_forms = soup.find_all('form')
            for form in search_forms:
                action = form.get('action', 'self')
                method = form.get('method', 'GET').upper()
                inputs = form.find_all(['input', 'textarea'])
                text_inputs = [
                    inp for inp in inputs
                    if inp.get('type', 'text') in ['text', 'search', 'email', 'url', 'tel']
                ]

                if text_inputs:
                    point = {
                        "type": "Form Input",
                        "action": action,
                        "method": method,
                        "inputs": [inp.get('name', 'unnamed') for inp in text_inputs],
                        "risk": "HIGH" if method == "GET" else "MEDIUM"
                    }
                    results["injection_points"].append(point)
                    names = ", ".join(point["inputs"])
                    print(f"    {C.vuln(f'Form [{method}] {action} → inputs: {names}')}")

            # 4b. URL-based reflection points (links with params)
            links_with_params = []
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if '?' in href or '=' in href:
                    full = urljoin(self.url, href)
                    links_with_params.append(full)

            if links_with_params:
                results["injection_points"].append({
                    "type": "Parameterized Links",
                    "count": len(links_with_params),
                    "risk": "MEDIUM"
                })
                print(f"    {C.warning(f'Links with parameters: {len(links_with_params)}')}")
                for link in links_with_params[:5]:
                    print(f"      {C.DIM}→ {link}{C.RESET}")

            # 4c. Contenteditable elements
            editable = soup.find_all(attrs={"contenteditable": True})
            if editable:
                results["injection_points"].append({
                    "type": "ContentEditable",
                    "count": len(editable),
                    "risk": "HIGH"
                })
                print(f"    {C.vuln(f'ContentEditable elements: {len(editable)} (HIGH risk)')}")

            # ---- 5. HTML Comments (Info Disclosure) ----
            print(f"\n  {C.CYAN}[HTML Comments]{C.RESET}")
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            sensitive_keywords = ['todo', 'fixme', 'hack', 'password', 'secret',
                                 'api', 'key', 'token', 'admin', 'debug',
                                 'test', 'temp', 'backup', 'sql', 'query']

            for comment in comments:
                comment_text = comment.strip()
                if len(comment_text) > 5:
                    is_sensitive = any(kw in comment_text.lower() for kw in sensitive_keywords)
                    results["comments"].append({
                        "text": comment_text[:100],
                        "sensitive": is_sensitive
                    })
                    if is_sensitive:
                        print(f"    {C.vuln(f'Sensitive: {comment_text[:80]}')}")
                    else:
                        print(f"    {C.DIM}→ {comment_text[:80]}{C.RESET}")

            if not comments:
                print(f"    {C.safe('No HTML comments found')}")

            # ---- 6. Iframe Analysis ----
            print(f"\n  {C.CYAN}[Iframe Analysis]{C.RESET}")
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                src = iframe.get('src', 'N/A')
                sandbox = iframe.get('sandbox', 'NONE')
                allow = iframe.get('allow', 'N/A')

                iframe_info = {
                    "src": src,
                    "sandbox": sandbox,
                    "allow": allow
                }
                results["iframes"].append(iframe_info)

                if sandbox == "NONE":
                    print(f"    {C.vuln(f'Iframe without sandbox: {src[:60]}')}")
                else:
                    print(f"    {C.safe(f'Iframe (sandboxed): {src[:60]}')}")

            if not iframes:
                print(f"    {C.safe('No iframes found')}")

            # ---- 7. Script Analysis ----
            print(f"\n  {C.CYAN}[Script Analysis]{C.RESET}")
            scripts = soup.find_all('script')
            inline_count = 0
            external_count = 0
            inline_dangerous = 0

            for script in scripts:
                if script.get('src'):
                    external_count += 1
                    src = script['src']
                    results["scripts_analysis"].append({
                        "type": "external",
                        "src": src
                    })
                elif script.string:
                    inline_count += 1
                    js_code = script.string

                    # Check for dangerous patterns
                    dangerous = ['eval(', 'document.write(', '.innerHTML',
                                'setTimeout("', 'setInterval("', 'new Function(']
                    for d in dangerous:
                        if d in js_code:
                            inline_dangerous += 1
                            break

            print(f"    {C.info(f'External scripts: {external_count}')}")
            print(f"    {C.info(f'Inline scripts: {inline_count}')}")
            if inline_dangerous:
                print(f"    {C.vuln(f'Inline scripts with dangerous patterns: {inline_dangerous}')}")
                results["sanitization"].append(f"{inline_dangerous} dangerous inline scripts")

            # ---- 8. Sanitization Detection ----
            print(f"\n  {C.CYAN}[Sanitization Detection]{C.RESET}")

            # Check for common sanitization libraries
            sanitization_libs = {
                "DOMPurify": "dompurify",
                "sanitize-html": "sanitize-html",
                "xss-filters": "xss-filters",
                "js-xss": "js-xss",
                "bleach": "bleach",
                "Angular Sanitizer": "ng-sanitize",
                "React DOM": "react-dom",
            }

            found_sanitizers = []
            for lib_name, signature in sanitization_libs.items():
                if signature in html.lower():
                    found_sanitizers.append(lib_name)
                    print(f"    {C.safe(f'Sanitizer detected: {lib_name}')}")

            if not found_sanitizers:
                print(f"    {C.warning('No client-side sanitization library detected')}")
                results["sanitization"].append("No client-side sanitizer found")

            # ---- Final Summary ----
            total_injection = len(results["injection_points"])
            total_dangerous_tags = len(results["dangerous_tags"])
            total_handlers = len(results["dangerous_attrs"])

            print(f"\n  {C.BOLD}{'─' * 50}{C.RESET}")
            print(f"  {C.BOLD}HTML Parser Summary:{C.RESET}")
            print(f"    {C.info(f'Injection points: {total_injection}')}")
            print(f"    {C.info(f'Dangerous tags: {total_dangerous_tags}')}")
            print(f"    {C.info(f'Event handlers: {total_handlers}')}")
            print(f"    {C.info(f'HTML comments: {len(results["comments"])}')}")
            print(f"    {C.info(f'Iframes: {len(results["iframes"])}')}")

            risk_score = total_injection * 3 + total_handlers * 2 + total_dangerous_tags
            if risk_score > 30:
                risk_level = "HIGH"
                color = C.RED
            elif risk_score > 15:
                risk_level = "MEDIUM"
                color = C.YELLOW
            else:
                risk_level = "LOW"
                color = C.GREEN

            print(f"\n    {color}{C.BOLD}Overall XSS Risk: {risk_level} (Score: {risk_score}){C.RESET}")

        except Exception as e:
            print(f"  {C.error(f'HTML parsing failed: {e}')}")

        return results
