import requests
import re
from bs4 import BeautifulSoup
from core.colors import Colors as C
from core.config import Config

class DOMXSS:
    name = "DOM-Based XSS Detector"

    def __init__(self, url):
        self.url = url

    def run(self):
        print(f"\n{C.BLUE}{'═' * 60}{C.RESET}")
        print(f"  {C.BOLD}{C.RED}🌐 DOM-BASED XSS DETECTOR{C.RESET}")
        print(f"{C.BLUE}{'═' * 60}{C.RESET}")

        results = {"sinks_found": [], "sources_found": [], "risk_level": "LOW"}

        try:
            resp = requests.get(self.url, timeout=Config.TIMEOUT, headers=Config.HEADERS)
            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script')

            all_js = ""
            for script in scripts:
                if script.string:
                    all_js += script.string + "\n"

            # Also check inline event handlers
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr.startswith('on'):
                        all_js += f" {tag.attrs[attr]} "

            if not all_js.strip():
                print(f"  {C.warning('No JavaScript found on page')}")
                return results

            # Check for DOM Sinks
            print(f"\n  {C.info('Checking for DOM Sinks...')}")
            for sink in Config.DOM_SINKS:
                if sink in all_js:
                    results["sinks_found"].append(sink)
                    # Find line context
                    lines = all_js.split('\n')
                    for i, line in enumerate(lines):
                        if sink in line:
                            snippet = line.strip()[:80]
                            print(f"    {C.vuln(f'Sink: {sink}')}")
                            print(f"      {C.DIM}Code: {snippet}{C.RESET}")
                            break

            # Check for DOM Sources
            print(f"\n  {C.info('Checking for DOM Sources...')}")
            for source in Config.DOM_SOURCES:
                if source in all_js:
                    results["sources_found"].append(source)
                    print(f"    {C.warning(f'Source: {source}')}")

            # Risk Assessment
            if results["sinks_found"] and results["sources_found"]:
                results["risk_level"] = "HIGH"
                print(f"\n  {C.RED}{C.BOLD}[!] HIGH RISK: Both sources and sinks detected!{C.RESET}")
                print(f"  {C.DIM}User-controlled data may flow into dangerous sinks{C.RESET}")
            elif results["sinks_found"]:
                results["risk_level"] = "MEDIUM"
                print(f"\n  {C.YELLOW}[!] MEDIUM RISK: Dangerous sinks found{C.RESET}")
            elif results["sources_found"]:
                results["risk_level"] = "LOW"
                print(f"\n  {C.GREEN}[✓] LOW RISK: Sources found but no dangerous sinks{C.RESET}")
            else:
                print(f"\n  {C.safe('No DOM XSS indicators found')}")

            print(f"\n  {C.info(f'Sinks: {len(results["sinks_found"])} | Sources: {len(results["sources_found"])}')}")

        except Exception as e:
            print(f"  {C.error(f'DOM XSS scan failed: {e}')}")

        return results
