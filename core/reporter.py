import json
import os
from datetime import datetime
from core.config import Config
from core.colors import Colors as C

class Reporter:
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.vulns = []
        self.start_time = datetime.now()
        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)

    def add(self, module_name, data):
        self.results[module_name] = data

    def add_vuln(self, vuln_type, url, param, payload, severity):
        entry = {
            "type": vuln_type,
            "url": url,
            "param": param,
            "payload": payload,
            "severity": severity,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulns.append(entry)

    def save_json(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace("://", "_").replace("/", "_").replace(":", "_")
        filepath = os.path.join(Config.OUTPUT_DIR, f"xxstrike_{safe_target}_{ts}.json")
        report = {
            "tool": Config.TOOL_NAME,
            "version": Config.VERSION,
            "target": self.target,
            "scan_start": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_end": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": len(self.vulns),
            "vulnerabilities": self.vulns,
            "module_results": self.results
        }
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n  {C.success(f'JSON Report: {filepath}')}")
        return filepath

    def save_html(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace("://", "_").replace("/", "_").replace(":", "_")
        filepath = os.path.join(Config.OUTPUT_DIR, f"xxstrike_{safe_target}_{ts}.html")

        vuln_rows = ""
        for v in self.vulns:
            sev_color = "#ff4444" if v["severity"] == "HIGH" else "#ffd700" if v["severity"] == "MEDIUM" else "#00ff88"
            vuln_rows += f"""<tr>
                <td>{v['type']}</td>
                <td>{v['url']}</td>
                <td>{v['param']}</td>
                <td><code>{v['payload']}</code></td>
                <td style="color:{sev_color};font-weight:bold;">{v['severity']}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><head>
<title>XXStrike Report - {self.target}</title>
<style>
body {{ font-family: 'Courier New', monospace; background: #0a0e17; color: #00ff88; padding: 20px; }}
h1 {{ color: #ff4444; text-align: center; }}
h2 {{ color: #00d4ff; border-left: 4px solid #00d4ff; padding-left: 10px; }}
.card {{ background: #111827; border: 1px solid #1e3a5f; border-radius: 8px; padding: 15px; margin: 10px 0; }}
table {{ width: 100%; border-collapse: collapse; }}
td, th {{ border: 1px solid #1e3a5f; padding: 8px; text-align: left; }}
th {{ background: #1e3a5f; color: #fff; }}
code {{ background: #1a1a2e; padding: 2px 6px; border-radius: 3px; color: #ff6b6b; }}
.stat {{ font-size: 2em; color: #ff4444; text-align: center; }}
</style></head><body>
<h1>⚡ XXStrike XSS Scanner Report</h1>
<div class="card">
<p>Target: {self.target}</p>
<p>Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p class="stat">Vulnerabilities Found: {len(self.vulns)}</p>
</div>
<h2>Vulnerability Details</h2>
<div class="card">
<table>
<tr><th>Type</th><th>URL</th><th>Parameter</th><th>Payload</th><th>Severity</th></tr>
{vuln_rows if vuln_rows else '<tr><td colspan="5" style="text-align:center;">No vulnerabilities found</td></tr>'}
</table>
</div>
<h2>Module Results</h2>
<div class="card"><pre>{json.dumps(self.results, indent=2, default=str)}</pre></div>
</body></html>"""

        with open(filepath, 'w') as f:
            f.write(html)
        print(f"  {C.success(f'HTML Report: {filepath}')}")
        return filepath

    def print_summary(self):
        print(f"\n{C.RED}{C.BOLD}{'═' * 60}{C.RESET}")
        print(f"  {C.BOLD}SCAN SUMMARY{C.RESET}")
        print(f"{C.RED}{'═' * 60}{C.RESET}")
        print(f"  {C.info(f'Target: {self.target}')}")
        print(f"  {C.info(f'Duration: {(datetime.now() - self.start_time).total_seconds():.2f}s')}")
        print(f"  {C.info(f'Total Vulnerabilities: {len(self.vulns)}')}")

        high = sum(1 for v in self.vulns if v["severity"] == "HIGH")
        medium = sum(1 for v in self.vulns if v["severity"] == "MEDIUM")
        low = sum(1 for v in self.vulns if v["severity"] == "LOW")

        if high:
            print(f"  {C.RED}{C.BOLD}  HIGH:   {high}{C.RESET}")
        if medium:
            print(f"  {C.YELLOW}  MEDIUM: {medium}{C.RESET}")
        if low:
            print(f"  {C.GREEN}  LOW:    {low}{C.RESET}")
        if not self.vulns:
            print(f"  {C.GREEN}{C.BOLD}  No XSS vulnerabilities detected!{C.RESET}")
        print(f"{C.RED}{'═' * 60}{C.RESET}")
