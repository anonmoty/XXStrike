# XXStrike
<img width="1024" height="695" alt="Image" src="https://github.com/user-attachments/assets/85dd7d59-b8e6-4956-a71d-a04443b97117" />
<img width="720" height="478" alt="Image" src="https://github.com/user-attachments/assets/6de29819-f2e3-4a36-bf17-6f2da4867a2b" />
<img width="720" height="592" alt="Image" src="https://github.com/user-attachments/assets/13fb3882-55b2-4abc-9d5d-3d78cb43be38" />









cat << 'READMEEOF' > README.md
<p align="center">
  <img src="https://img.shields.io/badge/XXStrike-v2.0_Stable-red?style=for-the-badge&logo=target">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20macOS-success?style=for-the-badge&logo=linux">
  <img src="https://img.shields.io/badge/XSS_Modules-10+-orange?style=for-the-badge&logo=shield">
  <img src="https://img.shields.io/badge/License-Educational-yellow?style=for-the-badge">
</p>

<h1 align="center">⚡ XXStrike v2.0</h1>
<h3 align="center">Next-Generation XSS (Cross-Site Scripting) Scanner & Fuzzing Suite</h3>

<p align="center">
  <b>Developed by:</b> <a href="https://github.com/anonmoty">Maxod anonmoty 🔰</a><br>
  <b>Official Repository:</b> <a href="https://github.com/anonmoty/XXStrike">https://github.com/anonmoty/XXStrike</a>
</p>

<p align="center">
  <a href="#-overview">Overview</a> •
  <a href="#-key-features">Key Features</a> •
  <a href="#-modules-breakdown">Modules</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-comparison">Comparison</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

---

## 📌 Overview

**XXStrike** is an advanced, multi-threaded **Cross-Site Scripting (XSS)** detection and vulnerability assessment framework engineered for penetration testers, bug bounty hunters, application security engineers, and DevSecOps professionals.

Designed as a modern, lightweight, and high-speed alternative to legacy XSS scanners, XXStrike combines **intelligent parameter discovery**, **DOM source-to-sink tracking**, **context-aware payload fuzzing**, and **WAF/filter bypass heuristics** into a single cohesive terminal interface.

Optimized natively for both **Android (Termux)** and standard **Linux distributions**.

---

## 🚀 Key Features

* ⚡ **Multi-Engine Detection:** Identifies Reflected, DOM-based, and Potential Stored XSS vectors in single runs.
* 🎯 **Context-Aware Fuzzer:** 45+ specialized payloads categorized into HTML body, attributes, scripts, comments, and event handlers.
* 🛡️ **WAF & Filter Bypass Engine:** Heuristic checks for 14+ firewalls (Cloudflare, AWS WAF, ModSecurity, Imperva, Sucuri).
* 🔬 **Intelligent HTML & JS Parser:** Deep syntax analysis for DOM sinks (`innerHTML`, `document.write`, `eval()`, `postMessage`).
* 🔒 **Security Headers & Cookie Audit:** Evaluates CSP, X-XSS-Protection, HSTS, SameSite, HttpOnly, and Secure flags with letter grades (A+ to F).
* 📊 **Automated Reporting:** Generates clean, production-ready reports in **HTML** and **JSON** formats.
* 📱 **Termux Native:** Zero external compilation required, 100% pure Python with minimal footprint.

---

## 🧩 Modules Breakdown (10 Powerful Modules)

| # | Module Name | Method & Capabilities |
|---|-------------|-----------------------|
| `01` | **Parameter Discovery** | Uncovers query parameters, hidden form fields, and reflected arguments. |
| `02` | **Reflected XSS Scanner** | Contextual injection verification with boundary-breaking tests. |
| `03` | **DOM-Based XSS Detector** | JavaScript source-to-sink flow tracing and dangerous pattern extraction. |
| `04` | **XSS Header Audit** | Evaluates Content-Security-Policy (CSP), X-XSS-Protection, and X-Content-Type-Options. |
| `05` | **WAF / Filter Detection** | Tests 12 bypass transformations (Unicode, Hex, Double-encoding, mixed cases). |
| `06` | **JavaScript Sink Analysis** | Scans external scripts and inline blocks for insecure APIs. |
| `07` | **Cookie Security Audit** | Checks session token flags (`HttpOnly`, `Secure`, `SameSite`) for XSS-assisted exfiltration. |
| `08` | **Stored XSS Vector Analyzer** | Detects persistent storage entry points (forms, textareas, comment fields). |
| `09` | **Advanced XSS Fuzzer** | 45+ categorized vectors testing encoding, protocol handlers (`javascript:`, `data:`), and nested tags. |
| `10` | **HTML & Injection Point Analyzer** | Parses meta tags, sandboxed iframes, event attributes, and sanitizers (`DOMPurify`, `Bleach`). |

---

## 📊 Comparison: XXStrike vs Legacy Tools

| Capability | Legacy XSStrike | Generic Scanners | ⚡ XXStrike v2.0 |
|---|:---:|:---:|:---:|
| **Termux / Mobile Linux Support** | ⚠️ Unstable | ❌ No | ✅ Native (100% Optimized) |
| **Integrated DOM Sink Tracker** | Partial | ❌ No | ✅ Full Source-to-Sink |
| **Cookie Flag & CSP Security Scoring** | ❌ No | Partial | ✅ Comprehensive (A+ to F) |
| **Interactive CLI + Full Auto Scan** | ❌ CLI Only | ❌ CLI Only | ✅ Dual (Menu + Batch 99) |
| **HTML / JSON Auto-Reporter** | ❌ No | Partial | ✅ Built-in Exporter |
| **Active Development** | Stale | Varies | ✅ Active (2025 Release) |

---

## 💻 Installation

### 📱 Android (Termux)
```bash
# Update repository lists
pkg update && pkg upgrade -y

# Install dependencies
pkg install python git -y

# Clone repository
git clone https://github.com/anonmoty/XXStrike.git

# Navigate to project directory
cd XXStrike

# Install required Python packages
pip install -r requirements.txt

# Launch XXStrike
python XSStrike.py

