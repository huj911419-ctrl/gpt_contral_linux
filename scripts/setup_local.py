#!/usr/bin/env python3
"""Create local configuration and OAuth password hash without leaking the password."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets

BASE = Path(__file__).resolve().parents[1]
HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")


def private_json(path: Path, value: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(description="Initial Ubuntu MCP setup")
    parser.add_argument("--host", required=True, help="Public HTTPS hostname (no https://)")
    parser.add_argument("--project-root", default="~/Development")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--username", default="")
    args = parser.parse_args()
    host = args.host.strip().lower().rstrip(".")
    if not HOST_PATTERN.fullmatch(host) or "." not in host or ".." in host or len(host) > 253:
        parser.error("Invalid hostname, e.g. your-device.your-tailnet.ts.net")
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be 1024-65535")
    root = Path(args.project_root).expanduser().resolve()
    if not root.is_dir():
        parser.error(f"Project root does not exist: {root}")
    if (BASE / "config.json").exists() or (BASE / "oauth_config.json").exists():
        parser.error("Existing configuration detected; refusing to overwrite")
    username = args.username.strip() or input("Create OAuth username: ").strip()
    if not username or len(username) > 128 or any(c.isspace() for c in username):
        parser.error("Invalid username")
    password = getpass.getpass("New OAuth password (12+ characters): ")
    again = getpass.getpass("Confirm OAuth password: ")
    if len(password) < 12 or password != again:
        parser.error("Password too short or passwords do not match")
    salt = secrets.token_bytes(16)
    rounds = 600_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    config = {
        "public_host": host,
        "project_root": str(root),
        "port": args.port,
        "stm32_programmer_cli": ""
    }
    auth = {
        "username": username,
        "salt": salt.hex(),
        "hash": digest.hex(),
        "rounds": rounds
    }
    private_json(BASE / "oauth_config.json", auth)
    private_json(BASE / "config.json", config)
    p = BASE / ".mcp_private"
    p.mkdir(mode=0o700, exist_ok=True)
    os.chmod(p, 0o700)
    print(f"Configuration created. Public MCP URL: https://{host}/mcp")
    print("Credentials not printed; keep oauth_config.json and .mcp_private private.")
    print("Developer shell starts locked; enable it locally only when needed.")


if __name__ == "__main__":
    main()
