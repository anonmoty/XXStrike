class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

    @staticmethod
    def success(text):
        return f"{Colors.GREEN}[✓]{Colors.RESET} {text}"

    @staticmethod
    def error(text):
        return f"{Colors.RED}[✗]{Colors.RESET} {text}"

    @staticmethod
    def warning(text):
        return f"{Colors.YELLOW}[!]{Colors.RESET} {text}"

    @staticmethod
    def info(text):
        return f"{Colors.CYAN}[*]{Colors.RESET} {text}"

    @staticmethod
    def vuln(text):
        return f"{Colors.RED}{Colors.BOLD}[VULN]{Colors.RESET} {text}"

    @staticmethod
    def safe(text):
        return f"{Colors.GREEN}[SAFE]{Colors.RESET} {text}"

    @staticmethod
    def progress(current, total, text=""):
        bar_len = 30
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
        pct = int(100 * current / total) if total > 0 else 0
        print(f"\r  {Colors.CYAN}[{bar}]{Colors.RESET} {pct}% {text}", end='', flush=True)
        if current == total:
            print()
