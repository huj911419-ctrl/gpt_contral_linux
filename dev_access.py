"""Local-only, time-limited arming for powerful remote MCP tools.

Only a person using the Ubuntu account can unlock; there is no MCP unlock tool.
"""
import argparse
import json
import os
from pathlib import Path
import time

BASE = Path(__file__).resolve().parent
PRIVATE = BASE / '.mcp_private'
ARM_FILE = PRIVATE / 'dev_armed.json'
MAX_MINUTES = 60
# Fixed large positive value for tools which check >0 and poll during a command.
PERMANENT_REMAINING_SECONDS = 1_000_000_000


def remaining_seconds():
    try:
        data = json.loads(ARM_FILE.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            return 0
        # Never trust writable group/other files.
        permissions = ARM_FILE.stat()
        if permissions.st_mode & 0o077 or permissions.st_uid != os.geteuid():
            return 0
        if data.get('armed_by_uid') != os.geteuid() or data.get('version') != 1:
            return 0
        if data.get('mode') == 'always':
            return PERMANENT_REMAINING_SECONDS
        return max(0, int(data['expires_at'] - time.time()))
    except (OSError, ValueError, KeyError, TypeError):
        return 0


def is_always_enabled():
    try:
        data = json.loads(ARM_FILE.read_text(encoding='utf-8'))
        info = ARM_FILE.stat()
        return (isinstance(data, dict) and info.st_uid == os.geteuid()
                and not (info.st_mode & 0o077)
                and data.get('armed_by_uid') == os.geteuid()
                and data.get('version') == 1 and data.get('mode') == 'always')
    except (OSError, ValueError, TypeError):
        return False


def arm_always():
    if os.geteuid() == 0:
        raise SystemExit('请使用普通用户，禁止使用 sudo。')
    print('警告：这将长期允许已授权的 MCP 客户端执行本机普通用户权限下的 Bash。')
    print('本机私人文件可能被读取、修改或删除。仅适合你信任所有已授权客户端的情况。')
    if input('确认永久开启请输入：ENABLE ALWAYS SHELL\n> ').strip() != 'ENABLE ALWAYS SHELL':
        raise SystemExit('已取消。')
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    payload = json.dumps({'mode': 'always', 'expires_at': 4102444800,
                          'armed_by_uid': os.geteuid(), 'version': 1})
    temp = PRIVATE / f'.armed-{os.getpid()}'
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(payload + '\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, ARM_FILE)
    print('✅ 已永久开启普通用户远程开发权限。可随时运行 lock 锁定。')


def arm(minutes):
    if not 1 <= minutes <= MAX_MINUTES:
        raise SystemExit('时长必须在 1~60 分钟之间。')
    if os.geteuid() == 0:
        raise SystemExit('请使用普通用户，禁止用 sudo 解锁。')
    print('\n即将允许已通过 OAuth 登录的 MCP 客户端执行本机账户权限下的任意 Bash 命令。')
    print('这包括修改/删除你有权限访问的文件，以及读取个人账户可访问的资料。')
    print('即使使用 OAuth，恶意指令或受污染的代码内容仍然可能带来风险。')
    print(f'有效期：{minutes} 分钟；到期自动锁定。')
    if input('确认开启请输入：ENABLE SHELL\n> ').strip() != 'ENABLE SHELL':
        raise SystemExit('已取消。')
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    payload = json.dumps({'expires_at': time.time()+minutes*60,
                          'armed_by_uid': os.geteuid(), 'version': 1})
    temp = PRIVATE / f'.armed-{os.getpid()}'
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(payload+'\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, ARM_FILE)
    print(f'✅ 已开启 {minutes} 分钟。到期后自动恢复锁定。')


def main():
    p = argparse.ArgumentParser(description='Ubuntu MCP 高权限会话开关')
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('unlock', help='本机解锁一段时间')
    a.add_argument('--minutes', type=int, default=20)
    sub.add_parser('always', help='本机确认后长期开放普通用户开发权限')
    sub.add_parser('lock', help='立刻结束会话')
    sub.add_parser('status', help='查询剩余时间')
    args = p.parse_args()
    if args.command == 'unlock':
        arm(args.minutes)
    elif args.command == 'always':
        arm_always()
    elif args.command == 'lock':
        ARM_FILE.unlink(missing_ok=True)
        print('🔒 已锁定高权限工具。')
    else:
        print('♾️ 已长期开放普通用户开发权限' if is_always_enabled() else (f'剩余 {remaining_seconds()} 秒' if remaining_seconds() else '🔒 当前已锁定'))


if __name__ == '__main__':
    main()
