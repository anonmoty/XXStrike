import os

class Config:
    VERSION = "2.0"
    TOOL_NAME = "XXStrike"
    TIMEOUT = 10
    MAX_DEPTH = 2
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    HEADERS = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    OUTPUT_DIR = os.path.join(BASE_DIR, "output")
    PAYLOAD_DIR = os.path.join(BASE_DIR, "payloads")

    # Safe detection payloads (non-destructive)
    XSS_PAYLOADS = [
        "xxstest123",
        "<xxstest>",
        "'xxstest'",
        '"xxstest"',
        "xxstest<script>",
        "xxstest\"onmouseover=\"",
        "xxstest'onclick='",
        "xxstest<svg>",
        "xxstest<img>",
        "xxstest<body>",
        "xxstest<iframe>",
        "xxstest<math>",
        "xxstest<table>",
        "xxstest<div>",
        "xxstest<input>",
        "xxstest<select>",
        "xxstest<textarea>",
        "xxstest<details>",
        "xxstest<marquee>",
        "xxstest<object>",
    ]

    DOM_SINKS = [
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "eval(", "setTimeout(", "setInterval(", "Function(",
        "location.hash", "location.search", "location.href",
        "document.URL", "document.referrer", "window.name",
        "postMessage", "localStorage", "sessionStorage",
        "insertAdjacentHTML", "createContextualFragment",
    ]

    DOM_SOURCES = [
        "location.hash", "location.search", "location.href",
        "document.URL", "document.referrer", "window.name",
        "document.cookie", "localStorage.getItem",
        "sessionStorage.getItem", "URLSearchParams",
    ]
