# GPT Control Linux · Ubuntu MCP Agent

> 让 ChatGPT 通过 **MCP + OAuth + Tailscale Funnel** 访问自己的 Ubuntu，查询状态、读取与修改开发文件、运行普通用户终端命令，并可按需编译和烧录 STM32 项目。

[中文说明](#安装指南) · [安全说明](SECURITY.md) · [MIT License](LICENSE)

## 项目简介

这是从个人 Ubuntu 开发环境整理出来的实验性开源项目，主要针对学习 Linux、Python、C/C++ 和嵌入式开发的用户。

```text
ChatGPT 网页 / 支持 MCP 的客户端
              │  HTTPS + OAuth
              ▼
 Tailscale Funnel（固定的 *.ts.net 域名）
              │
              ▼
 Ubuntu MCP Server（127.0.0.1:8766）
              │
              ├── Linux 状态监控
              ├── 项目文件读取 / 编辑 / 搜索
              ├── Bash 命令（本地授权开启后）
              ├── CMake / Make / Ninja 编译
              └── STM32CubeProgrammer 烧录（独立本机审批）
```

**安全警告：** `terminal_run` 可在远程执行任意 Bash，所拥有的权限等同于运行 MCP 的 Linux 用户。此仓库代码未经独立安全审计，**不适用于生产环境或放有敏感资料的个人主力电脑**。建议使用独立 Linux 用户、开发机或虚拟机。默认高权限终端处于锁定状态，切勿在公开网络中取消 OAuth 或给它免密 sudo。

## 功能（共 18 个 MCP 工具）

| 类型 | 工具 | 功能 |
|---|---|---|
| 只读 | `get_system_info`, `get_memory`, `get_disk` | 操作系统、内存、磁盘 |
| 只读 | `get_cpu_status`, `get_temperature`, `get_processes`, `get_dev_tools` | CPU、传感器、进程、开发环境 |
| 独立审批 | `list_project_files`, `read_project_file`, `search_project_code`, `build_project`, `flash_stm32` | 项目文件、构建、烧录；单次审批 |
| 开发会话 | `dev_access_status`, `terminal_run`, `dev_list`, `dev_read`, `dev_write`, `dev_search` | 本机解锁后调用；源文件写入带 SHA256 校验与备份 |

## 安装指南

需要 Ubuntu / Linux、Python 3.11+、Git、支持 MCP 的客户端，以及 Tailscale 账号。公开域名由 Tailscale Funnel 提供，不必购买域名。**不同 ChatGPT 套餐和工作区对自定义 MCP 的支持可能不同。**

### 1. 安装代码和依赖

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/huj911419-ctrl/gpt_contral_linux.git ~/mcp-ubuntu
cd ~/mcp-ubuntu
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
mkdir -p ~/Development
```

如系统自带 Python 较旧，请另外安装受支持的版本。

### 2. 安装 Tailscale 并启用 Funnel

参考 [Tailscale 官方 Linux 安装文档](https://tailscale.com/download/linux) 安装并登录：

```bash
sudo tailscale up
tailscale status
```

在 Tailscale 管理后台根据提示启用 **Funnel** 和 HTTPS，然后获得本机 DNS 名（`tailscale status --json` 里的 `Self.DNSName`），例如：

```text
my-ubuntu.my-tailnet.ts.net
```

**这是示例，不是作者的真实设备地址。** 有些系统需要先执行一次：

```bash
sudo tailscale set --operator="$USER"
```

### 3. 创建本机配置和 OAuth 密码

```bash
cd ~/mcp-ubuntu
python3 scripts/setup_local.py --host my-ubuntu.my-tailnet.ts.net --project-root ~/Development --port 8766
```

替换成**你自己的** Tailscale DNS 名。向导会让你输入 OAuth 用户名和密码，密码不显示、不写入仓库；生成文件 `config.json` 和 `oauth_config.json`，只保存在本机并被 `.gitignore` 忽略。

### 4. 启动 MCP，再启动 Funnel

先在一个终端运行：

```bash
cd ~/mcp-ubuntu
.venv/bin/python server.py
```

再从另一终端运行：

```bash
tailscale funnel --bg --yes 8766
tailscale funnel status
```

公网 MCP 地址为：

```text
https://my-ubuntu.my-tailnet.ts.net/mcp
```

匿名访问 `/mcp` 应被拒绝（通常为 HTTP 401）。可用 `curl` 检查 OAuth metadata：

```bash
curl -i https://my-ubuntu.my-tailnet.ts.net/.well-known/oauth-authorization-server
```

此处仍须替换示例域名。不要通过浏览器或聊天公开密码、Client Secret 或终端密钥文件。

### 5. 连接 ChatGPT 自定义 MCP

在 ChatGPT 支持的自定义 MCP 添加页面输入 `https://my-ubuntu.my-tailnet.ts.net/mcp`，授权方式选择 **OAuth**，按照页面提示登录本机 OAuth 账户。

服务器支持 OAuth 2.0 authorization-code + PKCE、动态客户端注册（DCR）。如果你的 ChatGPT 页面只能选择「自定义 OAuth 客户端」，先复制页面上提供的 **回调 URL**，然后在 Ubuntu 执行：

```bash
cd ~/mcp-ubuntu
python3 scripts/register_client.py --redirect-uri 'https://chatgpt.com/connector/oauth/YOUR_CALLBACK'
```

程序只显示 Client ID；Client Secret 保存在 `~/mcp-ubuntu/.mcp_private/chatgpt_client_*.json`（文件权限 600）。**仅在你的本地 Ubuntu 上读取它，填入 ChatGPT，切勿上传 GitHub、粘贴到聊天或截图公开。** Token endpoint authentication method 选择 `client_secret_post`；scope 为 `mcp`。

不同客户端可能对 OAuth discovery / DCR 的支持略有差别。授权后测试 `get_system_info` 即可确认连接。

## 开发权限：默认锁定

建议只在需要时开启短期会话：

```bash
cd ~/mcp-ubuntu
python3 dev_access.py unlock --minutes 20
# 输入 ENABLE SHELL 才会开启
python3 dev_access.py status
# 不使用时立即锁定：
python3 dev_access.py lock
```

为兼容特定个人实验需求，代码还包含 `python3 dev_access.py always` 长期开放模式，但**强烈不建议在公网服务中启用**，即使配置 OAuth 也仍可能发生凭据泄露、越权工具调用、恶意内容诱导等安全问题。终端以普通用户执行，无自动 sudo/root 提权。

烧录工具 `flash_stm32` 仍需独立的本机核对批准。其它需要批准的工具可以使用：

```bash
python3 approve.py list
python3 approve.py approve <REQUEST_ID>
```

请先核对构建/烧录目标及 SHA256 再确认。

## 自动启动（可选）

下面使用 systemd **用户服务**，通常在你登录 Ubuntu 桌面后自动启动：

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/ubuntu-mcp.service <<'EOF'
[Unit]
Description=Ubuntu MCP Server (OAuth)
After=network-online.target
[Service]
Type=simple
WorkingDirectory=%h/mcp-ubuntu
ExecStart=%h/mcp-ubuntu/.venv/bin/python -u %h/mcp-ubuntu/server.py
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now ubuntu-mcp.service
```

不要让一个手动运行中的 MCP 和 systemd 服务同时占用同一端口。Tailscale `tailscaled` 应由系统服务管理；Funnel 后台规则可通过 `tailscale funnel status` 核对。重启后检查：

```bash
systemctl --user is-active ubuntu-mcp.service
systemctl is-active tailscaled
tailscale funnel status
```

这里用户服务一般依赖登录；如果需要登录之前运行，请自行评估 `loginctl enable-linger` 的安全影响。**OAuth access/refresh token 在内存里，MCP 进程重启后可能需要重新授权**。

## 开源发布与检查

```bash
python3 scripts/check_release.py
python3 -m unittest discover -s tests -v
```

本仓库**不包含**个人 OAuth 密码、Client Secret、私有 SQLite、真实设备域名、日志、GitHub Token 或 SSH 私钥。不要将自己运行中的 `~/mcp-ubuntu` 目录不经检查直接上传。

## License

MIT License，详见 [LICENSE](LICENSE)。仅代表项目代码的许可，不代表相关第三方库、Tailscale 或 ChatGPT 的授权条款。
