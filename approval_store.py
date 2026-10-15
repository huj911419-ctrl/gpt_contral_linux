"""Local, one-time authorization gate for sensitive MCP tools.

Only the local Ubuntu user can approve requests via approve.py. Remote clients
cannot approve requests through any MCP tool.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

ROOT = Path(__file__).resolve().parent
STATE_DIR = ROOT / '.mcp_private'
DB_PATH = STATE_DIR / 'approvals.sqlite3'
TTL_SECONDS = 600


def db():
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    con = sqlite3.connect(DB_PATH, timeout=5)
    os.chmod(DB_PATH, 0o600)
    con.execute('''CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        action TEXT NOT NULL,
        payload TEXT NOT NULL,
        digest TEXT NOT NULL,
        created INTEGER NOT NULL,
        expires INTEGER NOT NULL,
        approved INTEGER NOT NULL DEFAULT 0,
        consumed INTEGER NOT NULL DEFAULT 0
    )''')
    con.commit()
    return con


def json_payload(payload):
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def authorize(action, payload, request_id=''):
    """Return (granted, message). Authorization is one-shot and argument-bound."""
    raw = json_payload(payload)
    digest = hashlib.sha256((action + '\0' + raw).encode()).hexdigest()
    now = int(time.time())
    with db() as con:
        con.execute('DELETE FROM approvals WHERE expires < ? OR consumed = 1', (now,))
        if request_id:
            row = con.execute(
                'SELECT action,digest,expires,approved,consumed FROM approvals WHERE id=?',
                (request_id,),
            ).fetchone()
            if (not row or row[0] != action or row[1] != digest or row[2] < now
                    or row[3] != 1 or row[4] != 0):
                return False, '授权不存在、已失效、尚未批准，或调用参数已经变化。请重新请求。'
            updated = con.execute(
                'UPDATE approvals SET consumed=1 WHERE id=? AND approved=1 AND consumed=0 AND expires>=?',
                (request_id, now),
            )
            return (True, '') if updated.rowcount == 1 else (False, '授权已使用。')
        # Cap unauthenticated requests to prevent unbounded approval-queue growth.
        active = con.execute('SELECT count(*) FROM approvals WHERE expires>=?', (now,)).fetchone()[0]
        if active >= 30:
            return False, '待审批请求已达上限。请稍后再试。'
        rid = secrets.token_hex(8)
        con.execute(
            'INSERT INTO approvals(id,action,payload,digest,created,expires) VALUES(?,?,?,?,?,?)',
            (rid, action, raw, digest, now, now + TTL_SECONDS),
        )
        return False, (
            f'需要 Ubuntu 本机批准。请求编号：{rid}\n'
            f'操作：{action}\n参数：{raw}\n'
            f'请在 Ubuntu 终端执行：python3 ./approve.py approve {rid}\n'
            f'批准后，在十分钟内使用相同参数并附带 request_id="{rid}" 重新调用本工具。'
        )
