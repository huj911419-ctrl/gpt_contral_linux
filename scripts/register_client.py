#!/usr/bin/env python3
"""Register a ChatGPT OAuth callback with local MCP (never print client_secret)."""
import argparse
import json
import os
from pathlib import Path
import secrets
import urllib.request
from urllib.parse import urlsplit

BASE = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--redirect-uri", required=True, help="Callback URL copied from ChatGPT")
    ap.add_argument("--port", type=int)
    args = ap.parse_args()
    redirect = args.redirect_uri.strip()
    u = urlsplit(redirect)
    if u.scheme != "https" or u.hostname != "chatgpt.com" or not u.path.startswith("/connector/oauth/"):
        ap.error("Expected https://chatgpt.com/connector/oauth/...")
    conf = json.loads((BASE / "config.json").read_text())
    port = args.port or int(conf.get("port", 8766))
    body = json.dumps({
        "client_name": "ChatGPT Ubuntu MCP",
        "redirect_uris": [redirect],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    }).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/register", method="POST", data=body,
        headers={"Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=15) as response:
        data = json.load(response)
    if not data.get("client_id") or not data.get("client_secret"):
        raise RuntimeError("Registration response missing client credentials")
    private = BASE / ".mcp_private"
    private.mkdir(mode=0o700, exist_ok=True)
    os.chmod(private, 0o700)
    target = private / ("chatgpt_client_" + secrets.token_hex(5) + ".json")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=2)
        out.write("\n")
    print("Registered Client ID:", data["client_id"])
    print("Client Secret is saved locally (not printed):", target)
    print("Use token endpoint auth method: client_secret_post")


if __name__ == "__main__":
    main()
