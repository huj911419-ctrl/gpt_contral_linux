# Security / 安全注意事项

**Experimental software. Not professionally audited. Do not use this as a production remote administration platform.**

本项目暴露一个通过 OAuth 保护的 MCP 接口。如果启用 `terminal_run`，获得授权的客户端就能以 MCP 服务的 Linux 用户身份运行任意 Bash 命令，包括读取或删除该用户可访问的文件。

- 首次安装时，开发终端默认 **锁定**。使用 `python3 dev_access.py unlock --minutes 20` 本机授权。永久解锁 `always` 选项风险很高，不建议在普通公网部署中使用。
- 不要使用 root 用户运行 MCP；不要给运行用户配置无限制的免密 sudo。
- OAuth 实现供单用户实验使用：客户端注册保存到本地 SQLite；access/refresh token 只在内存中，服务重启后可能需要重新登录。它不提供生产环境级别的账户管理、审计、入侵检测或细粒度授权。
- 公网隧道 URL 并不是秘密；**OAuth、账户密码、本地许可开关都不能省略**。
- 避免暴露 ssh 私钥、浏览器资料、云凭据和任何不希望远程读取的个人信息。更推荐专用 Linux 用户、隔离的虚拟机或专门的开发设备。
- `flash_stm32` 在实际写入硬件前要求本机批准，请确认目标设备和固件 SHA256。
- 如怀疑账户泄露，停用 Funnel、锁定开发工具、撤销 OAuth 客户端并轮换所有可能外泄的凭据。

## Do not commit / 禁止提交

`config.json`、`oauth_config.json`、`.mcp_private/`、`.venv/`、SQLite、OAuth Client Secret、终端审计日志和个人备份不允许进入代码仓库。即使 `.gitignore` 存在，也应在第一次 push 前运行 `python3 scripts/check_release.py` 并检查 `git ls-files`。

## Reporting

If you discover a vulnerability, do not publish credentials, exploitation details, or a live management URL in a public issue. Contact the maintainer privately through a channel they provide.
