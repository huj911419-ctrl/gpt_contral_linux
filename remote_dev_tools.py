"""Powerful MCP developer tools behind existing OAuth AND local time-based arming.

This module does NOT include a remote unlock API. It runs commands as the
ordinary Linux account running the existing MCP server, never via sudo.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from dev_access import remaining_seconds, is_always_enabled

BASE = Path(__file__).resolve().parent
PRIVATE = BASE / '.mcp_private'
CONFIG = json.loads((BASE / 'config.json').read_text(encoding='utf-8'))
PROJECT_ROOT = Path(CONFIG.get('project_root', str(Path.home() / 'Development'))).expanduser().resolve()
LOCK = threading.Lock()
READ_MAX = 65536
OUTPUT_LIMIT = 7 * 1024 * 1024
READ_EXT = {'.c','.h','.cpp','.hpp','.cc','.py','.rs','.go','.sh','.md','.txt','.json','.yaml','.yml','.toml','.cmake','.ioc','.ld','.s','.S','.ini','.cfg','.mk','.log'}
BASENAMES = {'Makefile','CMakeLists.txt','Kconfig','Dockerfile','meson.build'}


def _require_armed() -> int:
    seconds = remaining_seconds()
    if seconds <= 0:
        raise PermissionError(
            '高权限开发会话尚未开启或已过期。请在 Ubuntu 本机运行：'
            'python3 ./dev_access.py unlock --minutes 20；'
            '输入 ENABLE SHELL 后，在有效期内无需逐次审批。'
        )
    if os.geteuid() == 0:
        raise PermissionError('拒绝在 root 身份下执行远程开发命令。')
    return seconds


def _audit(action: str, details: dict):
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    record = {'at': datetime.now(timezone.utc).isoformat(), 'uid': os.geteuid(),
              'action': action, 'details': details}
    path = PRIVATE / 'dev_audit.jsonl'
    fd = os.open(path, os.O_APPEND | os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')


def _within_projects(path: str, *, must_exist=False) -> Path:
    if not path or len(path) > 1024:
        raise ValueError('路径不能为空或过长')
    raw = Path(path).expanduser()
    candidate = raw if raw.is_absolute() else PROJECT_ROOT / raw
    if any(part.is_symlink() for part in (candidate, *candidate.parents)):
        raise ValueError('文件 API 不操作符号链接')
    target = candidate.resolve(strict=False)
    if not target.is_relative_to(PROJECT_ROOT):
        raise ValueError(f'文件 API 仅能操作 {PROJECT_ROOT}；其它目录可通过已授权的 Bash 使用普通用户权限。')
    if any(x.startswith('.') for x in target.relative_to(PROJECT_ROOT).parts):
        raise ValueError('文件 API 不操作隐藏文件/目录')
    if must_exist and not target.exists():
        raise FileNotFoundError(str(target))
    return target


def _allowed_file(path: Path) -> bool:
    return path.suffix in READ_EXT or path.name in BASENAMES


def register_tools(mcp):
    @mcp.tool()
    def dev_access_status() -> str:
        """查询 Ubuntu 本机高权限开发会话是否已解锁；不会解锁。"""
        remaining = remaining_seconds()
        return ('已长期开放普通用户开发权限；本机可随时 lock 关闭' if is_always_enabled() else (f'已解锁，剩余 {remaining} 秒' if remaining else '已锁定。Ubuntu 本机：python3 ./dev_access.py unlock --minutes 20'))

    @mcp.tool()
    def terminal_run(command: str, cwd: str = '~/Development', timeout_seconds: int = 90) -> str:
        """在本机已解锁会话内执行 Bash 命令（Ubuntu 普通用户权限）；能编译、运行脚本、操作串口及用户文件。无 sudo 提权；命令会被审计。"""
        try:
            _require_armed()
            if not isinstance(command, str) or not command.strip() or len(command) > 15000:
                raise ValueError('命令不能为空且最多15000字符')
            if not 1 <= timeout_seconds <= 300:
                raise ValueError('运行时间须为1~300秒')
            here = Path(cwd).expanduser().resolve()
            if not here.is_dir():
                raise FileNotFoundError(f'工作目录不存在：{here}')
            if not LOCK.acquire(blocking=False):
                return '当前有另一个远程操作正在执行，请稍后重试。'
            try:
                _require_armed()
                _audit('terminal_run.started', {'cwd': str(here), 'command': command[:15000], 'timeout': timeout_seconds})
                with tempfile.TemporaryFile(mode='w+b') as f:
                    p = subprocess.Popen(['/bin/bash', '--noprofile', '--norc', '-c', command],
                                         cwd=here, stdout=f, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL, start_new_session=True)
                    reason = 'finished'
                    deadline = time.monotonic() + timeout_seconds
                    try:
                        while p.poll() is None:
                            if remaining_seconds() <= 0:
                                reason = 'session_locked_or_expired'
                                break
                            if time.monotonic() > deadline:
                                reason = 'timeout'
                                break
                            if os.fstat(f.fileno()).st_size > OUTPUT_LIMIT:
                                reason = 'output_limit'
                                break
                            time.sleep(0.1)
                    finally:
                        if p.poll() is None:
                            try: os.killpg(p.pid, signal.SIGKILL)
                            except ProcessLookupError: pass
                        p.wait()
                    f.seek(0, os.SEEK_END)
                    total = f.tell()
                    f.seek(max(0,total-25000))
                    tail = f.read().decode('utf-8', errors='replace')
                _audit('terminal_run.finished', {'reason':reason,'return_code':p.returncode,'output_bytes':total})
                return (f'cwd: {here}\n退出码: {p.returncode}\n结束原因: {reason}\n'
                        f'总输出字节: {total}\n末尾输出（最多25KB）:\n{tail}')
            finally:
                LOCK.release()
        except (OSError, ValueError, PermissionError) as exc:
            return f'无法执行：{type(exc).__name__}: {exc}'

    @mcp.tool()
    def dev_list(path: str='.', max_entries: int=150) -> str:
        """不再逐次批准：在本机解锁时列出 ~/Development 项目目录的文件/文件夹。"""
        try:
            _require_armed()
            directory=_within_projects(path, must_exist=True)
            if not directory.is_dir():
                raise NotADirectoryError(str(directory))
            max_entries=max(1,min(int(max_entries),300))
            out=[]
            for item in sorted(directory.iterdir(), key=lambda p:p.name.lower()):
                if item.name.startswith('.') or not item.resolve().is_relative_to(PROJECT_ROOT):
                    continue
                if item.is_symlink(): continue
                out.append(('目录' if item.is_dir() else '文件')+': '+item.name)
                if len(out)>=max_entries: break
            return f'目录：{directory}\n'+('\n'.join(out) if out else '(空目录)')
        except (OSError, ValueError, PermissionError) as exc:
            return f'无法列出目录：{type(exc).__name__}: {exc}'

    @mcp.tool()
    def dev_read(path: str, start_line: int=1, max_lines: int=300) -> str:
        """不再逐次批准：读取 ~/Development 下的源代码和文本文件，返回SHA256以便安全修改。"""
        try:
            _require_armed()
            p=_within_projects(path, must_exist=True)
            if not p.is_file() or p.is_symlink() or not _allowed_file(p):
                raise ValueError('不是允许的文本源文件')
            if p.stat().st_size > READ_MAX:
                raise ValueError('文件大于64KB；可使用 terminal_run 分段读取')
            b=p.read_bytes()
            t=b.decode('utf-8')
            start_line=max(1,int(start_line))
            max_lines=max(1,min(int(max_lines),700))
            lines=t.splitlines(keepends=True)
            extract=''.join(f'{idx+1:4d} {s}' for idx,s in enumerate(lines) if start_line<=idx+1<start_line+max_lines)
            return f'文件：{p}\nSHA256：{hashlib.sha256(b).hexdigest()}\n总行数：{len(lines)}\n'+extract[:45000]
        except (OSError, ValueError, PermissionError, UnicodeError) as exc:
            return f'无法读取：{type(exc).__name__}: {exc}'

    @mcp.tool()
    def dev_write(path: str, content: str, expected_sha256: str='') -> str:
        """无需逐次批准：原子修改 ~/Development 的文本源码；覆盖已有文件时必须提供 dev_read 返回的 SHA256，自动备份。"""
        try:
            _require_armed()
            if not isinstance(content,str) or len(content.encode('utf-8')) > 200000:
                raise ValueError('内容过大（最多200KB）')
            p=_within_projects(path)
            if not _allowed_file(p) or p.is_symlink():
                raise ValueError('不允许写入这种文件或符号链接')
            if not p.parent.is_dir():
                raise ValueError('父目录不存在；请先用终端创建目录')
            if not LOCK.acquire(blocking=False):
                return '另一个远程操作正在执行，请稍后重试。'
            try:
                _require_armed()
                old=b''
                if p.exists():
                    if not p.is_file(): raise ValueError('目标不是普通文件')
                    old=p.read_bytes()
                    if not expected_sha256 or hashlib.sha256(old).hexdigest()!=expected_sha256.lower():
                        raise ValueError('已有文件必须提供匹配的 expected_sha256；先调用 dev_read')
                    backup = PRIVATE/'file_backups'
                    backup.mkdir(mode=0o700,parents=True,exist_ok=True)
                    saved = backup/(f'{int(time.time()*1000)}-{hashlib.sha256(str(p).encode()).hexdigest()[:10]}.bak')
                    shutil.copy2(p,saved)
                    os.chmod(saved,0o600)
                elif expected_sha256:
                    raise ValueError('目标不存在，不应传 expected_sha256')
                payload=content.encode('utf-8')
                fd,tmp=tempfile.mkstemp(prefix='.mcp-tmp-',dir=p.parent)
                try:
                    with os.fdopen(fd,'wb') as out:
                        out.write(payload)
                        out.flush();os.fsync(out.fileno())
                    if p.exists():
                        os.chmod(tmp,p.stat().st_mode & 0o777)
                    else:
                        os.chmod(tmp,0o600)
                    os.replace(tmp,p)
                finally:
                    if os.path.exists(tmp): os.unlink(tmp)
                digest=hashlib.sha256(payload).hexdigest()
                _audit('dev_write', {'path':str(p),'bytes':len(payload),'sha256':digest})
                return f'✅ 已写入：{p}\n字节数：{len(payload)}\nSHA256：{digest}\n已有文件自动备份在 ~/.mcp_private/file_backups （实际位于 ./.mcp_private/file_backups）'
            finally:
                LOCK.release()
        except (OSError, ValueError, PermissionError) as exc:
            return f'无法写入：{type(exc).__name__}: {exc}'

    @mcp.tool()
    def dev_search(query: str,path: str='.') -> str:
        """无需逐次批准：在 ~/Development 中搜索文本源代码，最多检查500个文件，最多返回60处匹配。"""
        try:
            _require_armed()
            if not 2<=len(query)<=100 or '\n' in query: raise ValueError('搜索词长度2~100字符，不能含换行')
            parent=_within_projects(path,must_exist=True)
            if not parent.is_dir(): raise NotADirectoryError(str(parent))
            found=[]; scanned=0
            for root,dirs,files in os.walk(parent,followlinks=False):
                dirs[:]=[d for d in dirs if not d.startswith('.') and not (Path(root)/d).is_symlink()]
                for name in files:
                    f=Path(root)/name
                    if name.startswith('.') or f.is_symlink() or not _allowed_file(f): continue
                    try:
                        if f.stat().st_size>150000: continue
                        scanned+=1
                        for n,line in enumerate(f.read_text(encoding='utf-8',errors='replace').splitlines(),1):
                            if query.casefold() in line.casefold():
                                found.append(f'{f.relative_to(PROJECT_ROOT)}:{n}: {line[:180]}')
                                if len(found)>=60: break
                    except OSError: pass
                    if scanned>=500 or len(found)>=60:break
                if scanned>=500 or len(found)>=60:break
            return f'已扫描文件：{scanned}\n'+('\n'.join(found) if found else '无匹配结果')
        except (OSError, ValueError, PermissionError) as exc:
            return f'搜索失败：{type(exc).__name__}: {exc}'
