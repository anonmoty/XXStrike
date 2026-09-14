import os
import random
from datetime import datetime
from core.colors import Colors as C

os.system('clear')

BANNERS = [
    f"""{C.RED}{C.BOLD}
    ██╗  ██╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ╚██╗██╔╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
     ╚███╔╝  ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
     ██╔██╗  ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
    ██╔╝ ██╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{C.RESET}""",
    f"""{C.RED}{C.BOLD}
     _  __ _  __  ___ _  _ _  _ _  _ ___ ___
    \ \/ /\ \/ / / __|| |(_)| || ||_ _/ __|
     >  <  >  <  \__ \| || | | __ | | |\__ \\
    /_/\_\/_/\_\ |___/|_||_| |_||_||___|___/  v2.0{C.RESET}"""
]

def show_banner():
    line = "─" * 60
    banner = random.choice(BANNERS)
    print(banner)
    print(f"    {C.CYAN}{line}{C.RESET}")
    print(f"    {C.BOLD}{C.WHITE}  XSS Vulnerability Scanner Framework v2.0{C.RESET}")
    print(f"    {C.GREEN}  8 Modules | Auto-Crawl | Smart Detection{C.RESET}")
    print(f"    {C.MAGENTA}  Developer: Maxod anonmoty 🔰{C.RESET}")
    print(f"    {C.YELLOW}  ⚠  Authorized Security Testing Only{C.RESET}")
    print(f"    {C.DIM}  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"    {C.CYAN}{line}{C.RESET}")
