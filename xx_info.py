#!/usr/bin/env python3
R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; D = '\033[2m'
BOLD = '\033[1m'; RESET = '\033[0m'
line = "═" * 60

print(f"""
{R}{BOLD}
    ██╗  ██╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ╚██╗██╔╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
     ╚███╔╝  ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
     ██╔██╗  ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
    ██╔╝ ██╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{RESET}
{C}{line}{RESET}
  {M}{BOLD}👨‍💻 Developer :{RESET} {G}Maxod anonmoty 🔰{RESET}
  {M}{BOLD}📂 GitHub    :{RESET} {C}https://github.com/anonmoty/XXStrike{RESET}
  {M}{BOLD}📌 Version   :{RESET} {Y}2.0{RESET}
  {M}{BOLD}🐍 Language  :{RESET} {Y}Python 3.8+{RESET}
{C}{line}{RESET}
  {BOLD}{W}⚡ XXStrike is an advanced XSS vulnerability scanner{RESET}
  {W}that detects Reflected, DOM-based, and Stored XSS.{RESET}
{C}{line}{RESET}
  {G}[1]{RESET} Parameter Discovery      {D}Find injectable params{RESET}
  {G}[2]{RESET} Reflected XSS Scanner    {D}Test URL param reflection{RESET}
  {G}[3]{RESET} DOM-Based XSS Detector   {D}JS source-to-sink analysis{RESET}
  {G}[4]{RESET} XSS Header Audit         {D}CSP, X-XSS-Protection{RESET}
  {G}[5]{RESET} WAF/Filter Detection     {D}12 bypass techniques{RESET}
  {G}[6]{RESET} JS Sink Analysis         {D}eval, innerHTML, etc.{RESET}
  {G}[7]{RESET} Cookie Security Audit    {D}HttpOnly, Secure, SameSite{RESET}
  {G}[8]{RESET} Stored XSS Analysis      {D}Form storage vectors{RESET}
{C}{line}{RESET}
  {Y}python xxstrike.py{RESET}   {D}← Main scanner{RESET}
  {Y}python xx_info.py{RESET}    {D}← This info{RESET}
{C}{line}{RESET}
  {R}⚠ Authorized testing only. Developer not responsible.{RESET}
  {BOLD}{G}Made with ❤️ by Maxod anonmoty 🔰{RESET}
{C}{line}{RESET}
""")
