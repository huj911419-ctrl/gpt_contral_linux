#!/usr/bin/env python3
"""Conservative allowlist and sensitive-data checks before publishing source."""
import ast
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
ALLOW = {
    ".gitignore", "LICENSE", "README.md", "SECURITY.md", "requirements.txt",
    "config.example.json", "server.py", "ubuntu_mcp_local_oauth.py",
    "remote_dev_tools.py", "dev_access.py", "approval_store.py", "approve.py",
    "scripts/setup_local.py", "scripts/register_client.py",
    "scripts/check_release.py", "tests/test_release.py",
}
FORBIDDEN_NAMES = {
    "oauth_config.json", "config.json", "oauth_login.txt",
    "oauth_clients.sqlite3", "approvals.sqlite3", "dev_armed.json",
    "chatgpt_client_manual.json",
}
REDACTED_PATTERNS = [
    ("personal Linux home path", re.compile(r"/home/(?:hjj|[A-Za-z0-9_.-]{2,})/")),
    ("Cloudflare temporary tunnel", re.compile(r"[a-z0-9-]+\.trycloudflare\.com", re.I)),
    ("Tailscale personal tailnet", re.compile(r"\.tail[0-9a-z]{5,}\.ts\.net", re.I)),
    ("email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("possible 64+ hex secret", re.compile(r"\b[0-9a-f]{64,}\b", re.I)),
    ("literal OAuth client secret", re.compile(r'["\']client_secret["\']\s*:\s*["\'][a-zA-Z0-9_-]{24,}["\']')),
]

def check() -> list[str]:
    failures = []
    for f in ROOT.rglob("*"):
        if not f.is_file():
            continue
        rel = f.relative_to(ROOT)
        if ".git" in rel.parts or "__pycache__" in rel.parts:
            continue
        name = str(rel)
        if any(part in {".mcp_private", ".venv", "backups"} for part in rel.parts):
            failures.append(f"Forbidden directory: {name}")
            continue
        if rel.name in FORBIDDEN_NAMES or rel.suffix in {".db", ".sqlite3", ".pem", ".key", ".log"}:
            failures.append(f"Forbidden filename: {name}")
            continue
        if name not in ALLOW:
            failures.append(f"Unexpected file (not allowlisted): {name}")
            continue
        try:
            data = f.read_text(encoding="utf-8")
        except UnicodeError:
            failures.append(f"Non-text file: {name}")
            continue
        for label, pat in REDACTED_PATTERNS:
            if pat.search(data):
                failures.append(f"{name}: detected {label}")
        if f.suffix == ".py":
            try:
                ast.parse(data, filename=name)
            except SyntaxError as e:
                failures.append(f"{name}: Python syntax error at line {e.lineno}")
    for name in ALLOW:
        if not (ROOT / name).is_file():
            failures.append(f"Missing expected file: {name}")
    return failures

if __name__ == "__main__":
    errors = check()
    if errors:
        for line in errors:
            print("BLOCK:", line)
        sys.exit(1)
    print(f"PASS: {len(ALLOW)} explicit files, no known secret patterns")
