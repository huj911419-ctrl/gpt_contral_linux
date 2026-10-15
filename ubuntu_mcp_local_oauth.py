"""Experimental single-user OAuth provider for the MCP Python SDK.

DCR + PKCE; OAuth clients persist in SQLite; access/refresh tokens are in memory.
Not a security-audited production identity provider.
"""
import hashlib
import hmac
import html
import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
import secrets
import time
from urllib.parse import urlencode

from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken


class LocalOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, public_host: str, auth_config_path: str):
        self.issuer = 'https://' + public_host
        self.resource = self.issuer + '/mcp'
        info = json.loads(Path(auth_config_path).read_text(encoding='utf-8'))
        self.username = info['username']
        self.salt = bytes.fromhex(info['salt'])
        self.pw_hash = bytes.fromhex(info['hash'])
        self.rounds = int(info['rounds'])
        self._client_db_path = (Path(auth_config_path).resolve().parent
                                / '.mcp_private' / 'oauth_clients.sqlite3')
        self._initialize_client_store()
        self.login_states: dict[str, dict] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.refresh: dict[str, RefreshToken] = {}
        self.failed_logins: list[float] = []

    def _initialize_client_store(self) -> None:
        private = self._client_db_path.parent
        if private.is_symlink():
            raise RuntimeError('OAuth private directory must not be a symlink')
        private.mkdir(mode=0o700, exist_ok=True)
        if private.stat().st_uid != os.geteuid():
            raise RuntimeError('OAuth private directory has an unexpected owner')
        os.chmod(private, 0o700)
        fd = os.open(self._client_db_path,
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or not stat.S_ISREG(info.st_mode):
                raise RuntimeError('OAuth registration store has an unexpected owner or type')
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with closing(sqlite3.connect(self._client_db_path, timeout=5)) as connection:
            connection.execute('CREATE TABLE IF NOT EXISTS oauth_clients ('
                               'client_id TEXT PRIMARY KEY, metadata TEXT NOT NULL)')
            connection.commit()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with closing(sqlite3.connect(self._client_db_path, timeout=5)) as connection:
            row = connection.execute(
                'SELECT metadata FROM oauth_clients WHERE client_id=?', (client_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            client = OAuthClientInformationFull.model_validate_json(row[0])
            if client.client_id != client_id:
                raise ValueError('Stored client ID does not match')
            return client
        except ValueError:
            # Do not echo stored metadata, which includes OAuth client secrets.
            raise RuntimeError('Invalid stored OAuth client metadata') from None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            raise ValueError('Missing client ID')
        raw = client_info.model_dump_json(by_alias=True, exclude_none=True)
        with closing(sqlite3.connect(self._client_db_path, timeout=5)) as connection:
            with connection:
                connection.execute('BEGIN IMMEDIATE')
                known = connection.execute(
                    'SELECT 1 FROM oauth_clients WHERE client_id=?', (client_info.client_id,)
                ).fetchone()
                count = connection.execute('SELECT count(*) FROM oauth_clients').fetchone()[0]
                if known is None and count >= 30:
                    raise ValueError('OAuth client registration limit reached; remove unused local registrations')
                connection.execute(
                    'INSERT INTO oauth_clients(client_id, metadata) VALUES(?,?) '
                    'ON CONFLICT(client_id) DO UPDATE SET metadata=excluded.metadata',
                    (client_info.client_id, raw),
                )

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not client.client_id:
            raise HTTPException(400, 'Invalid client')
        if params.resource is not None and params.resource.rstrip('/') != self.resource:
            raise HTTPException(400, 'Unknown resource')
        now = time.time()
        self.login_states = {k:v for k,v in self.login_states.items() if v['expires']>now}
        if len(self.login_states) >= 50:
            raise HTTPException(429, 'Too many pending login attempts')
        login_state = secrets.token_urlsafe(32)
        self.login_states[login_state] = {
            'client_id':client.client_id,
            'redirect':str(params.redirect_uri),
            'explicit':params.redirect_uri_provided_explicitly,
            'code_challenge':params.code_challenge,
            'oauth_state':params.state,
            'expires':now + 300,
        }
        return self.issuer + '/login?' + urlencode({'state': login_state})

    async def login_page(self, request: Request) -> HTMLResponse:
        state = request.query_params.get('state','')
        row = self.login_states.get(state)
        if not row or row['expires'] < time.time():
            raise HTTPException(400, 'Expired login link')
        s = html.escape(state, quote=True)
        body = f'''<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ubuntu MCP 登录</title><style>body{{font-family:sans-serif;max-width:420px;margin:55px auto;padding:18px}}input{{display:block;padding:12px;width:95%;margin:12px 0}}button{{padding:12px}}</style>
<h2>Ubuntu MCP 身份验证</h2><p>仅在你自己发起的 ChatGPT MCP 连接中登录。</p>
<form method="POST" action="/login/callback">
<input type="hidden" name="state" value="{s}">
<label>用户名 <input name="username" autocomplete="username" required></label>
<label>密码 <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">授权连接</button></form></html>'''
        return HTMLResponse(body, headers={'Cache-Control':'no-store','X-Frame-Options':'DENY',
                    'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"})

    async def login_callback(self, request: Request) -> RedirectResponse:
        form = await request.form()
        state, user, pwd = form.get('state'),form.get('username'),form.get('password')
        if not all(isinstance(x,str) for x in (state,user,pwd)):
            raise HTTPException(400, 'Invalid login form')
        row = self.login_states.get(state)
        if not row or row['expires'] < time.time():
            raise HTTPException(400, 'Expired login attempt')
        now = time.time()
        self.failed_logins = [t for t in self.failed_logins if now-t<900]
        if len(self.failed_logins)>=8:
            raise HTTPException(429, 'Too many attempts, retry after 15 minutes')
        pwd_hash = hashlib.pbkdf2_hmac('sha256',pwd.encode('utf-8'),self.salt,self.rounds)
        valid = hmac.compare_digest(user,self.username) and hmac.compare_digest(pwd_hash,self.pw_hash)
        if not valid:
            self.failed_logins.append(now)
            raise HTTPException(401, 'Invalid credentials')
        self.failed_logins.clear()
        del self.login_states[state]
        code = secrets.token_urlsafe(36)
        auth_code = AuthorizationCode(code=code, client_id=row['client_id'],
            redirect_uri=AnyHttpUrl(row['redirect']),
            redirect_uri_provided_explicitly=row['explicit'],
            expires_at=now+300, scopes=['mcp'], code_challenge=row['code_challenge'],
            resource=self.resource, subject=self.username)
        self.codes[code]=auth_code
        dest=construct_redirect_uri(row['redirect'], code=code, state=row['oauth_state'])
        return RedirectResponse(dest, status_code=302, headers={'Cache-Control':'no-store'})

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        value = self.codes.get(authorization_code)
        if value and value.expires_at > time.time() and client.client_id==value.client_id:
            return value
        return None

    def _mint(self, client_id: str, scopes: list[str], subject: str):
        now = int(time.time())
        a=secrets.token_urlsafe(40)
        r=secrets.token_urlsafe(48)
        self.tokens[a] = AccessToken(token=a,client_id=client_id,scopes=scopes,
            expires_at=now+3600, resource=self.resource,subject=subject)
        self.refresh[r] = RefreshToken(token=r,client_id=client_id,scopes=scopes,
            expires_at=now+86400,resource=self.resource,subject=subject)
        return OAuthToken(access_token=a,token_type='Bearer',expires_in=3600,
            refresh_token=r,scope=' '.join(scopes))

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        known=self.codes.pop(authorization_code.code,None)
        if not known or known.client_id!=client.client_id or known.expires_at<time.time():
            raise ValueError('Invalid or expired authorization code')
        return self._mint(known.client_id,known.scopes,known.subject or self.username)

    async def load_access_token(self, token: str) -> AccessToken | None:
        t=self.tokens.get(token)
        if t and t.expires_at and t.expires_at<=time.time():
            self.tokens.pop(token,None)
            return None
        return t

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        r=self.refresh.get(refresh_token)
        if r and r.client_id==client.client_id and r.expires_at and r.expires_at>time.time():
            return r
        return None

    async def exchange_refresh_token(self,client:OAuthClientInformationFull,
            refresh_token:RefreshToken,scopes:list[str]) -> OAuthToken:
        old=self.refresh.pop(refresh_token.token,None)
        if not old or old.expires_at<time.time() or old.client_id!=client.client_id:
            raise ValueError('Invalid refresh token')
        if scopes and not set(scopes).issubset(set(old.scopes)):
            raise ValueError('Invalid scopes')
        return self._mint(old.client_id, scopes or old.scopes,old.subject or self.username)

    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:
        self.tokens.pop(token,None)
        self.refresh.pop(token,None)
