"""Run ONLY on the Ubuntu computer, never expose it as an MCP tool."""
import json
import sys
import time
from approval_store import db


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('list', 'approve'):
        print('用法：python3 ~/mcp-ubuntu/approve.py list')
        print('      python3 ~/mcp-ubuntu/approve.py approve 请求编号')
        return 2
    now = int(time.time())
    with db() as con:
        if sys.argv[1] == 'list':
            rows = con.execute('''SELECT id,action,payload,expires FROM approvals
                                  WHERE expires>=? AND approved=0 AND consumed=0
                                  ORDER BY created DESC LIMIT 30''', (now,)).fetchall()
            if not rows:
                print('当前没有待批准请求。')
            for rid, action, raw, expiry in rows:
                print(f'请求 {rid} | {action} | 剩余 {expiry-now} 秒')
                print(json.dumps(json.loads(raw), ensure_ascii=False, indent=2))
            return 0
        if len(sys.argv) != 3:
            print('缺少请求编号')
            return 2
        rid = sys.argv[2]
        row = con.execute('''SELECT action,payload,expires,approved,consumed FROM approvals
                             WHERE id=?''', (rid,)).fetchone()
        if not row or row[2] < now or row[3] or row[4]:
            print('请求不存在、已过期或已经处理。')
            return 1
        action, raw, *_ = row
        print('即将批准的操作：', action)
        print(json.dumps(json.loads(raw), ensure_ascii=False, indent=2))
        if action == 'flash_stm32':
            text = 'FLASH'
            print('警告：此操作会覆盖 MCU 固件。请确认目标开发板、文件路径和 SHA256。')
        elif action == 'build_project':
            text = 'BUILD'
            print('警告：Makefile/CMake 构建脚本能够执行项目定义的代码。仅批准可信工程。')
        else:
            text = 'YES'
        typed = input(f'如确认批准，请输入 {text}：').strip()
        if typed != text:
            print('没有批准。')
            return 1
        cur = con.execute('''UPDATE approvals SET approved=1 WHERE id=?
                             AND approved=0 AND consumed=0 AND expires>=?''', (rid, int(time.time())))
        print('已批准。现在可以在聊天中重试原工具调用。' if cur.rowcount == 1 else '批准失败或已经过期。')
        return 0 if cur.rowcount == 1 else 1


if __name__ == '__main__':
    raise SystemExit(main())
