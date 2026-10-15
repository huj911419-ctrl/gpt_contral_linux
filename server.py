from pydantic import AnyHttpUrl
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from ubuntu_mcp_local_oauth import LocalOAuthProvider

"""Ubuntu MCP: monitoring, approved project work, and opt-in developer tools.

WARNING: terminal_run executes commands with this Linux user's permissions.
Keep OAuth enabled and developer shell locked unless deliberately required.
This project is experimental and has not undergone a professional audit.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from approval_store import authorize

BASE = Path(__file__).resolve().parent
CONFIG_FILE = BASE / 'config.json'
config = json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
PROJECT_ROOT = Path(config['project_root']).expanduser().resolve()
PUBLIC_HOST = config['public_host'].strip().lower()
MCP_PORT = int(config.get('port', 8765))

auth_provider = LocalOAuthProvider(PUBLIC_HOST, str(BASE / 'oauth_config.json'))
mcp = MCPServer(
    'Ubuntu Monitor & Developer',
    auth_server_provider=auth_provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl('https://' + PUBLIC_HOST),
        resource_server_url=AnyHttpUrl('https://' + PUBLIC_HOST + '/mcp'),
        validate_token_resource=True,
        required_scopes=['mcp'],
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=['mcp'], default_scopes=['mcp'],
        ),
    ),
)

@mcp.custom_route('/login', methods=['GET'])
async def ubuntu_oauth_login_page(request):
    return await auth_provider.login_page(request)

@mcp.custom_route('/login/callback', methods=['POST'])
async def ubuntu_oauth_login_callback(request):
    return await auth_provider.login_callback(request)

CODE_EXTENSIONS = {'.c', '.h', '.cpp', '.hpp', '.cc', '.py', '.md', '.txt', '.json', '.yaml', '.yml', '.toml', '.cmake', '.ioc', '.s', '.S', '.ld', '.sh', '.ini', '.cfg', '.mk'}
SPECIAL_CODE_NAMES = {'Makefile', 'CMakeLists.txt', 'Kconfig', 'Dockerfile'}
BLOCKED_WORDS = ('secret', 'password', 'credential', 'private', 'token', 'apikey', 'api_key', 'id_rsa', 'id_ed25519', 'authorized_keys')
MAX_READ_BYTES = 48_000


def restricted_path(user_path='.', *, file=False, directory=False):
    if not user_path or len(user_path) > 400:
        raise ValueError('路径不能为空或过长')
    raw = Path(user_path).expanduser()
    candidate = (raw if raw.is_absolute() else PROJECT_ROOT / raw).resolve()
    if not candidate.is_relative_to(PROJECT_ROOT):
        raise ValueError(f'仅允许访问项目根目录内文件：{PROJECT_ROOT}')
    rel = candidate.relative_to(PROJECT_ROOT)
    if any(part.startswith('.') for part in rel.parts):
        raise ValueError('不允许访问隐藏文件和隐藏目录')
    if file and not candidate.is_file():
        raise ValueError('文件不存在')
    if directory and not candidate.is_dir():
        raise ValueError('目录不存在')
    return candidate


def listable_file(path):
    return (safe_code_file(path) or (path.suffix.lower() in {'.hex', '.elf', '.bin'}
            and not any(word in path.name.lower() for word in BLOCKED_WORDS)))


def safe_code_file(path):
    if any(word in path.name.lower() for word in BLOCKED_WORDS):
        return False
    if any(part.startswith('.') for part in path.relative_to(PROJECT_ROOT).parts):
        return False
    return path.suffix in CODE_EXTENSIONS or path.name in SPECIAL_CODE_NAMES


def execute_fixed(argv, cwd=None, timeout=120):
    """Execute a fixed argv (never shell=True), keep last 12 KiB of log."""
    with tempfile.TemporaryFile(mode='w+b') as out:
        p = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            rc = 124
        out.seek(0, os.SEEK_END)
        size = out.tell()
        out.seek(max(0, size - 12_000))
        log = out.read().decode('utf-8', errors='replace')
    return f'退出码：{rc}\n日志末尾（最多12KB）：\n{log}'


def read_meminfo():
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        k, v = line.split(':', 1)
        values[k] = int(v.strip().split()[0])
    return values


@mcp.tool()
def get_system_info() -> str:
    """查看 Ubuntu 版本、内核和 CPU 逻辑核心数量（只读）。"""
    return (f"操作系统：{platform.freedesktop_os_release().get('PRETTY_NAME', 'Linux')}\n"
            f"内核版本：{platform.release()}\nCPU 逻辑核心数：{os.cpu_count()}")


@mcp.tool()
def get_memory() -> str:
    """查看总内存、已使用内存、可用内存（只读）。"""
    v = read_meminfo()
    total = v['MemTotal'] / (1024 * 1024)
    free = v['MemAvailable'] / (1024 * 1024)
    return f'总内存：{total:.2f} GiB\n已使用（估算）：{total-free:.2f} GiB\n可用内存：{free:.2f} GiB'


@mcp.tool()
def get_disk() -> str:
    """查看 Ubuntu 根分区磁盘使用情况（只读）。"""
    t, u, f = shutil.disk_usage('/')
    gb = 1024**3
    return f'总容量：{t/gb:.2f} GiB\n已使用：{u/gb:.2f} GiB\n剩余空间：{f/gb:.2f} GiB'


@mcp.tool()
def get_cpu_status() -> str:
    """查询 CPU 负载、核心数和 CPU 使用率估算（只读）。"""
    def times():
        vals = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:]))
        # guest/guest_nice are already included in user/nice.
        return sum(vals[:8]), vals[3] + (vals[4] if len(vals) > 4 else 0)
    t1, i1 = times()
    time.sleep(0.15)
    t2, i2 = times()
    usage = 100 * (1 - (i2-i1) / max(t2-t1, 1))
    return f'CPU 使用率（采样估算）：{usage:.1f}%\n逻辑核心数：{os.cpu_count()}\n1/5/15分钟负载：{os.getloadavg()}'


@mcp.tool()
def get_temperature() -> str:
    """从 Linux thermal/hwmon sysfs 读取可用温度传感器；传感器不一定代表 CPU（只读）。"""
    result = []
    for temp_file in sorted(Path('/sys/class/thermal').glob('thermal_zone*/temp')):
        try:
            cel = int(temp_file.read_text().strip()) / 1000
            sensor_type = (temp_file.parent / 'type').read_text().strip()
            if -30 < cel < 150:
                result.append(f'{sensor_type}: {cel:.1f}°C')
        except (OSError, ValueError):
            pass
    for temp_file in sorted(Path('/sys/class/hwmon').glob('hwmon*/temp*_input')):
        try:
            cel = int(temp_file.read_text().strip()) / 1000
            sensor_type = (temp_file.parent / 'name').read_text().strip()
            label_file = temp_file.with_name(temp_file.name.replace('_input', '_label'))
            label = label_file.read_text().strip() if label_file.is_file() else temp_file.stem
            if -30 < cel < 150:
                result.append(f'{sensor_type}/{label}: {cel:.1f}°C')
        except (OSError, ValueError):
            pass
    return '\n'.join(result[:40]) if result else '没有可读取的 thermal/hwmon 温度传感器。'


@mcp.tool()
def get_processes() -> str:
    """查看 CPU 和内存使用最高的进程（仅 PID、进程名、CPU%、内存%，不暴露命令行参数）。"""
    try:
        out1 = subprocess.run(['ps', '-eo', 'pid,comm,pcpu,pmem', '--sort=-pcpu'],
                              capture_output=True, text=True, timeout=5, check=True).stdout
        out2 = subprocess.run(['ps', '-eo', 'pid,comm,pcpu,pmem', '--sort=-pmem'],
                              capture_output=True, text=True, timeout=5, check=True).stdout
        return 'CPU 占用最高：\n'+'\n'.join(out1.splitlines()[:9])+ '\n\n内存占用最高：\n'+'\n'.join(out2.splitlines()[:9])
    except (OSError, subprocess.SubprocessError) as e:
        return f'无法读取进程：{e}'


@mcp.tool()
def get_dev_tools() -> str:
    """检查 GCC、Python、Make、CMake、Ninja、ARM 编译器和 STM32CubeProgrammer 是否已安装（只读）。"""
    cmds = {
        'GCC': ('gcc', '--version'), 'G++': ('g++', '--version'),
        'Python': ('python3', '--version'), 'Make': ('make', '--version'),
        'CMake': ('cmake', '--version'), 'Ninja': ('ninja', '--version'),
        'ARM GCC': ('arm-none-eabi-gcc', '--version'),
        'STM32CubeProgrammer CLI': ('STM32_Programmer_CLI', '--version'),
    }
    rows = []
    for name, cmd in cmds.items():
        if name == 'STM32CubeProgrammer CLI':
            try:
                # Detection only: do not invoke a programmer or connect to a board.
                rows.append(f'{name}：已找到 {" ".join(programmer_command())}')
            except ValueError:
                rows.append(f'{name}：未找到；可配置 stm32_programmer_cli')
            continue
        executable = shutil.which(cmd[0])
        if not executable:
            rows.append(f'{name}：未在 PATH 中找到')
            continue
        try:
            r = subprocess.run([executable, cmd[1]], capture_output=True, text=True, timeout=3)
            version = (r.stdout + r.stderr).splitlines()
            rows.append(f'{name}：{version[0][:160] if version else "已安装"}')
        except (OSError, subprocess.SubprocessError):
            rows.append(f'{name}：已安装（无法获取版本）')
    return '\n'.join(rows)


@mcp.tool()
def list_project_files(path: str = '.', request_id: str = '') -> str:
    """浏览允许的开发项目目录。需要在 Ubuntu 本机批准，不能访问项目目录以外。"""
    try:
        p = restricted_path(path, directory=True)
        ok, msg = authorize('list_project_files', {'path': str(p)}, request_id)
        if not ok:
            return msg
        lines = []
        for child in sorted(p.iterdir(), key=lambda p: p.name.lower())[:100]:
            try:
                if child.name.startswith('.'):
                    continue
                resolved = child.resolve()
                if not resolved.is_relative_to(PROJECT_ROOT):
                    continue
                if child.is_file() and not listable_file(resolved):
                    continue
                lines.append(('[目录] ' if child.is_dir() else '[文件] ') + child.name)
            except (OSError, ValueError):
                continue
        return f'路径：{p}\n' + ('\n'.join(lines) if lines else '（目录为空或没有可显示的代码文件）')
    except (OSError, ValueError) as e:
        return f'访问被拒绝：{e}'


@mcp.tool()
def read_project_file(path: str, request_id: str = '') -> str:
    """读取项目中的文本代码文件，最大48KB；每次需要 Ubuntu 本机批准。"""
    try:
        p = restricted_path(path, file=True)
        if not safe_code_file(p):
            return '文件类型或名称不允许读取。'
        if p.stat().st_size > MAX_READ_BYTES:
            return f'文件大于 {MAX_READ_BYTES} 字节；不予读取。'
        ok, msg = authorize('read_project_file', {'path': str(p)}, request_id)
        if not ok:
            return msg
        return f'文件：{p}\n'+p.read_text(encoding='utf-8', errors='replace')
    except (OSError, ValueError) as e:
        return f'访问被拒绝：{e}'


@mcp.tool()
def search_project_code(query: str, path: str = '.', request_id: str = '') -> str:
    """在项目根目录内按纯文本搜索代码，最多扫描300个文件；需本机批准。"""
    try:
        if len(query) < 2 or len(query) > 100 or '\n' in query:
            return '搜索内容需为2～100个字符的单行文本。'
        p = restricted_path(path, directory=True)
        ok, msg = authorize('search_project_code', {'path': str(p), 'query': query}, request_id)
        if not ok:
            return msg
        found, scanned = [], 0
        for f in p.rglob('*'):
            if scanned >= 300 or len(found) >= 40:
                break
            try:
                f = restricted_path(str(f), file=True)
                if not safe_code_file(f) or f.stat().st_size > 200_000:
                    continue
                scanned += 1
                for lineno, line in enumerate(f.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                    if query.casefold() in line.casefold():
                        found.append(f'{f.relative_to(PROJECT_ROOT)}:{lineno}: {line[:160]}')
                        if len(found) >= 40:
                            break
            except (OSError, ValueError):
                continue
        return f'扫描文件：{scanned}\n' + ('\n'.join(found) if found else '无匹配结果')
    except (OSError, ValueError) as e:
        return f'访问被拒绝：{e}'


def build_command(project):
    candidates = [project/'build'/'Safe', project/'build'/'Debug', project/'build'/'Release', project/'build', project]
    for d in candidates:
        if not d.exists() or not d.resolve().is_relative_to(PROJECT_ROOT):
            continue
        if (d/'CMakeCache.txt').is_file():
            return ['cmake', '--build', str(d), '--parallel', '2'], project
        if (d/'build.ninja').is_file():
            return ['ninja', '-C', str(d), '-j', '2'], project
        if (d/'Makefile').is_file() or (d/'makefile').is_file():
            return ['make', '-C', str(d), '-j', '2'], project
    raise ValueError('找不到已经配置好的 CMake / Ninja / Make 构建目录，请先在本机配置工程。')


@mcp.tool()
def build_project(project_path: str, request_id: str = '') -> str:
    """编译限定目录下的已有 Make/CMake/Ninja 工程。仅在 Ubuntu 本机批准后执行一次，不接受任意命令。"""
    try:
        project = restricted_path(project_path, directory=True)
        command, cwd = build_command(project)
        if not shutil.which(command[0]):
            return f'未安装编译工具：{command[0]}'
        args = {'project': str(project), 'argv': command}
        ok, msg = authorize('build_project', args, request_id)
        if not ok:
            return msg
        return f'已授权编译：{project}\n'+execute_fixed(command, cwd=cwd, timeout=180)
    except (OSError, ValueError) as e:
        return f'构建失败：{e}'


def programmer_command():
    explicit = config.get('stm32_programmer_cli', '').strip()
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if p.is_file() and os.access(p, os.X_OK):
            return [str(p)]
        raise ValueError('配置的 STM32CubeProgrammer 路径不存在或不可执行')
    exe = shutil.which('STM32_Programmer_CLI')
    if exe:
        return [exe]
    common = [
        Path('/opt/st/stm32cubeprogrammer/bin/STM32_Programmer_CLI'),
        Path('/opt/st/STM32CubeProgrammer/bin/STM32_Programmer_CLI'),
        Path.home()/'STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI',
    ]
    for p in common:
        if p.is_file() and os.access(p, os.X_OK):
            return [str(p)]
    if shutil.which('cube'):
        return [shutil.which('cube'), 'programmer']
    raise ValueError('没有找到 STM32CubeProgrammer CLI。请在 config.json 里设置 stm32_programmer_cli 的绝对路径。')


@mcp.tool()
def flash_stm32(firmware_path: str, request_id: str = '') -> str:
    """通过 SWD 烧录项目中的 .hex 固件；必须在 Ubuntu 本机核对固件 SHA256 并输入 FLASH 批准，绝不自动确认。"""
    try:
        firmware = restricted_path(firmware_path, file=True)
        if firmware.suffix.lower() != '.hex' or firmware.stat().st_size > 16_000_000:
            return '只允许烧录项目目录内不超过16MB的 .hex 固件。'
        with firmware.open('rb') as source:
            firmware_bytes = source.read(16_000_001)
        if len(firmware_bytes) > 16_000_000:
            return '固件超过16MB，拒绝烧录。'
        sha = hashlib.sha256(firmware_bytes).hexdigest()
        cli = programmer_command()
        args = {'firmware': str(firmware), 'sha256': sha, 'programmer': cli,
                'connection': 'SWD 1000kHz', 'verify': True}
        ok, msg = authorize('flash_stm32', args, request_id)
        if not ok:
            return msg
        # Flash the exact approved bytes, even if the original path changes later.
        with tempfile.TemporaryDirectory(prefix='ubuntu-mcp-flash-') as staging:
            snapshot = Path(staging) / 'approved.hex'
            snapshot.write_bytes(firmware_bytes)
            snapshot.chmod(0o600)
            command = cli + ['-c', 'port=SWD', 'freq=1000', '-w', str(snapshot), '-v']
            return f'本机已授权烧录：{firmware}，SHA256={sha}\n'+execute_fixed(command, timeout=180)
    except (OSError, ValueError) as e:
        return f'烧录未执行：{e}'



# Opt-in, OAuth-verified, time-gated remote developer tools.
from remote_dev_tools import register_tools as register_remote_dev_tools
register_remote_dev_tools(mcp)

if __name__ == '__main__':
    allowed_hosts = ['127.0.0.1:*', 'localhost:*', '[::1]:*']
    if PUBLIC_HOST:
        if any(c in PUBLIC_HOST for c in ('/', ':', ' ')):
            raise ValueError('public_host 只能填写域名，不允许带协议/端口/路径')
        allowed_hosts += [PUBLIC_HOST, PUBLIC_HOST + ':*']
    mcp.run(
        transport='streamable-http', host='127.0.0.1', port=MCP_PORT,
        json_response=True, stateless_http=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=['http://127.0.0.1:*', 'http://localhost:*',
                             'http://[::1]:*', 'https://chatgpt.com'],
        ),
    )
