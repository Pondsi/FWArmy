# FWArmy 三平台完整使用手册（0.5.1）

> 适用：Windows x64、macOS（Apple Silicon / Intel）、Linux x64。
> FWArmy 是 WArmy 的**可选中转服务器**：撮合在线状态、转发不透明密文；不存消息、不解密内容。它可以和 WArmy 主应用装在同一台机器，也可以放在常开的另一台电脑/云主机。
> 安装与签名边界见 [INSTALL-3-PLATFORMS.md](INSTALL-3-PLATFORMS.md)；本文讲“装好之后怎么用、会遇到什么”。

## 1. 先决定服务器放在哪里

| 场景 | 建议 |
|---|---|
| 只在同一台电脑用 | 默认 `127.0.0.1:8787` 即可；不要做端口映射。 |
| 局域网内多台设备 | 服务器绑 `0.0.0.0`，客户端填局域网 IP；防火墙放行 TCP 8787。 |
| 公网/异地使用 | 服务器放在有公网 IP 的云主机或家里路由器可端口转发的机器；放行 TCP 8787；客户端填域名/IP + 端口；**必须核对 TLS 指纹**。 |
| 没有公网 IP | 可用云主机做公网入口；或两台 FWArmy 做「扩网」一跳（不是打洞替代品）；NAT-PMP/STUN 只在扩网页做证据探测。 |

FWArmy 默认监听 `0.0.0.0:8787`，端口被占用会自动 +1；实际端口在 `data/instance.json` 和管理页日志里。公网部署建议显式固定端口：`--port=8787`。

管理页**只接受本机回环**（127.0.0.1 / ::1），即使业务面绑 `0.0.0.0` 也不会把管理面开放到公网；不要把管理端口单独映射出去。

## 2. 三平台安装与首次启动

### 2.1 Windows x64

**安装（推荐一行）**

```powershell
irm https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.ps1 | iex
```

- 装到 `%LOCALAPPDATA%\FWArmy`，创建开始菜单快捷方式；不需要管理员权限。
- 安装器校验 `SHA256SUMS`；升级不覆盖 `data\`。
- 如果弹 SmartScreen：更多信息 → 仍要运行。
- 如果 Windows 11 的 **Smart App Control** 直接拦截：Windows 安全中心 → 应用和浏览器控制 → Smart App Control，关闭后重试；企业/学校电脑可能由 IT 策略强制拦截，需要管理员放行。

**便携包**：下载 `FWArmy-0.5.1-win-x64.zip`，解压后双击 `FWArmy.exe` 或 `start.bat`。zip 内也有 `install.ps1`，但一键安装请用发布页根目录的脚本。

**首次启动**

1. 开始菜单搜索 FWArmy，或双击安装目录的 `FWArmy.exe`。
2. 程序在后台启动并自动打开浏览器管理页，通常是 `https://127.0.0.1:8787/`。
3. 自签证书会提示“不安全/证书无效”：点“高级 → 继续访问”。这是本机自签，不是公网证书；不要在这个提示上输入任何密码。
4. 没有自动打开浏览器时，手动访问 `https://127.0.0.1:8787/`；如果 TLS 被关闭，则用 `http://127.0.0.1:8787/`。

**首次配置**

1. 管理页 →「凭据」→「生成凭据」→ 填名称（如“家里的 WArmy”）→ 可选限额 → 生成。
2. **明文只显示一次**，复制到 WArmy 客户端；点“我已保存”。服务器只存 sha256，忘了只能删除重建。
3. 顶部“TLS 指纹”复制下来，客户端连接时核对。
4. 需要公网时：Windows 防火墙 → 高级设置 → 入站规则 → 新建端口规则 TCP 8787；路由器做端口转发到这台电脑的 8787；云主机在安全组放行 TCP 8787。

**日常命令**

```bat
FWArmy.exe                      :: 启动并打开管理页
FWArmy.exe table                :: 控制台表格（凭据统计）
FWArmy.exe stop                 :: 停止
FWArmy.exe update               :: 检查更新
FWArmy.exe update --yes         :: 下载并重启
fwarmy-headless.bat             :: 后台启动，不开浏览器
fwarmy-console.bat              :: 每 2 秒刷新的控制台表格
```

安装目录、数据目录、日志：`%LOCALAPPDATA%\FWArmy\data\server.log`。便携包则是 exe 旁的 `data\`。

### 2.2 macOS（Apple Silicon / Intel）

**安装（推荐一行）**

```bash
curl -fsSL https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.sh | sh
```

- Apple Silicon 装 arm64 包，Intel 装 x64 包；安装器自动识别。
- 装到 `~/Applications/FWArmy`，生成可双击的 `FWArmy.command`；不需要 sudo。
- macOS 二进制是 **ad-hoc 签名**，没有 Apple Developer ID/公证。用 `curl` 安装不带 quarantine，双击可启动。

**首次启动**

1. 双击 `~/Applications/FWArmy/FWArmy.command`（会打开一个终端窗口并后台启动）。
2. 浏览器打开 `https://127.0.0.1:8787/`；自签证书提示“此连接非私人连接” → 显示详情 → 访问此网站。
3. 也可在终端运行 `~/Applications/FWArmy/FWArmy --open`。

**如果被 Gatekeeper 拦**

- 用浏览器下载压缩包再解压的，文件会带 quarantine；先运行：
  ```bash
  xattr -dr com.apple.quarantine ~/Applications/FWArmy
  ```
- macOS 15 起右键“打开”的快捷放行已取消；到“系统设置 → 隐私与安全性”点“仍要打开”。部分 26.x 版本可能需要上面的 `xattr` 命令。
- “App is damaged”通常也是 quarantine/签名问题：先 `xattr`，再确认下载的是 arm64/x64 对应包。
- 想彻底做到“浏览器下载双击零警告”，需要买 Apple Developer ID（99 美元/年）并公证；当前版本没有做。

**公网/防火墙**

- 首次监听时 macOS 可能弹“是否允许 FWArmy 接受传入网络连接” → 允许。
- 端口检查：`lsof -nP -iTCP:8787 -sTCP:LISTEN`。
- 需要常开时，可自己写 LaunchAgent（`~/Library/LaunchAgents`）或把 `FWArmy --no-open` 放进 `launchd`；程序本身**不注册**开机自启。

**日常命令**

```bash
~/Applications/FWArmy/FWArmy --version
~/Applications/FWArmy/FWArmy --open
~/Applications/FWArmy/FWArmy table
~/Applications/FWArmy/FWArmy stop
~/Applications/FWArmy/FWArmy update
```

数据目录：`~/Applications/FWArmy/data/`；日志 `data/server.log`。

### 2.3 Linux x64

**安装（推荐一行）**

```bash
curl -fsSL https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.sh | sh
```

- 装到 `~/.local/share/fwarmy`，生成 `~/.local/bin/fwarmy` 软链和 `~/.local/share/applications/fwarmy.desktop`。
- 不需要 root；升级不覆盖 `data/`。
- 当前只提供 x86_64；ARM Linux 会明确报“不支持的架构”，不会装错包。

**首次启动**

1. 应用菜单搜索 FWArmy，或运行 `~/.local/bin/fwarmy --open`。
2. 浏览器打开 `https://127.0.0.1:8787/`；自签证书提示 → 高级 → 继续。
3. 没有 `xdg-open` 的服务器/容器里，手动在能访问该端口的机器上打开管理页；管理面仍只接受回环，所以建议 SSH 端口转发：
   ```bash
   ssh -L 8787:127.0.0.1:8787 user@server
   # 本机浏览器打开 https://127.0.0.1:8787/
   ```
4. 公网放行：
   ```bash
   sudo ufw allow 8787/tcp          # Ubuntu/Debian
   sudo firewall-cmd --add-port=8787/tcp --permanent && sudo firewall-cmd --reload  # firewalld
   ```
   云主机还要在安全组放行。

**systemd 用户服务（可选，常开）**

```ini
# ~/.config/systemd/user/fwarmy.service
[Unit]
Description=FWArmy relay
After=network-online.target

[Service]
ExecStart=%h/.local/share/fwarmy/FWArmy --server --no-open
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now fwarmy
loginctl enable-linger "$USER"   # 未登录也保持用户服务
```

注意：systemd 启动的是 `--server` 模式；管理页请 SSH 隧道访问。更新后服务会被新进程接管，systemd 看到的是原进程退出，按你的 `Restart` 策略决定是否再拉起；用 `--server` 直跑时新进程会自己监听同一端口。

**日常命令**

```bash
~/.local/bin/fwarmy --open
~/.local/bin/fwarmy table
~/.local/bin/fwarmy stop
~/.local/bin/fwarmy update
```

数据目录：`~/.local/share/fwarmy/data/`；日志 `data/server.log`。

## 3. 连接 WArmy 客户端

在 WArmy 主应用里添加 FWArmy 服务器：

1. 地址：
   - 本机：`https://127.0.0.1:8787`
   - 局域网：`https://192.168.x.x:8787`
   - 公网：`https://你的域名或公网IP:8787`
2. 凭据：粘贴管理页生成的明文。
3. TLS：
   - 默认“自签 + 指纹固定”：把管理页“TLS 指纹”与客户端显示的指纹逐位核对，一致才信任；不一致不要连。
   - 如果用正式证书（管理页 TLS → 用户证书），客户端按系统 CA 校验证书链和域名；此时地址必须用证书里的域名。
   - 不要在公网用“关闭 TLS/允许非回环明文”；那会让凭据和信封以明文过网。
4. 连接后看管理页：在线数、请求数、队列应为 0/正常增长；`/api/health` 可无凭据读取，用于判断服务是否活着。

常见失败：

| 现象 | 原因 | 处理 |
|---|---|---|
| 401 | 凭据错/被停用/删除 | 管理页重新建凭据；确认没有多复制空格 |
| 426 tls-required | 公网来源用 http | 改用 https；或只在回环/VPN 内用明文 |
| TLS 指纹不匹配 | 连错机器/证书重建/中间人 | 核对管理页指纹；重建证书后客户端要重新信任 |
| 域名证书失败 | 用户证书链/域名不匹配 | 用正确域名；检查 fullchain/key；或改回自签+指纹 |
| 连上但收不到消息 | 收件人离线/队列满/扩网失败 | 看管理页队列、日志、扩网页统计；离线消息不留存 |

## 4. 管理页四个标签

| 标签 | 用途 |
|---|---|
| **总览** | 运行时长、在线/队列、今日/月/年/累计、每凭据统计、全局限额、TLS、消息安全、安全边界。 |
| **扩网** | “我连接别人”的出网地址与统计；“别人连接我”的接入凭据；公网可达性（NAT-PMP/STUN）。 |
| **日志** | 最近 200 行运行日志；不含消息明文/凭据明文。 |
| **更新** | 当前/最新版本、检查更新、下载并重启、自动策略、检查间隔、发布说明、最近检查/安装记录。 |

### 4.1 凭据与限额

- 可建多个凭据；每个可改名、改速度/日/月/年流量、停用/启用、删除。
- 留空 = 继承全局默认；分钟次数/流量必须 >0；其他额度填 0 = 不限。
- 日/月/年按服务器本机时区；字节口径是 UTF-8 信封长度，不含 HTTP 头。
- 删除凭据后历史用量仍计入总统计；明文不落盘。

### 4.2 扩网 / 被扩网

- **扩网（我连接别人）**：填对方地址 + 对方生成的“被扩网凭据”；不写端口默认 59599；支持 `域名:端口` 和 IPv6 `[::1]:59599`。
- 添加后先“识别指纹”，与对方管理页核对，再“信任”；未信任前不会发送凭据。
- **被扩网（别人连接我）**：点“生成接入凭据”，明文只显示一次；对方填你的公网地址 + 端口 + 这个凭据。
- 只做一跳；`route` 出现本机 instanceId 会拒绝，避免环路。消息只在本机内存队列 30 秒；扩网只转发，不落盘。
- 统计分“出网/入网”，失败会如实返回给发送方；不会静默重试。

### 4.3 公网可达性

- NAT-PMP 只读探针：只问路由器是否支持，不改状态。
- “申请端口映射”会修改路由器状态，必须显式点击；租期到期自动失效。
- STUN 只探测公网映射，不内置公共 STUN 服务器；不保证一定能打洞。
- `verdict=confirmed-inbound` 只来自真实外部实例连进来过；没有证据时页面不会说“已打通”。

## 5. 自动更新完整流程

### 5.1 三种策略

| 策略 | 行为 |
|---|---|
| `off` | 不自动检查；仍可在管理页手动“检查更新”。 |
| `check`（默认） | 启动 60 秒后检查，之后每 `intervalHours`（默认 6 小时）检查；发现新版只提示。 |
| `install` | 在 `check` 基础上，发现新版且本机内存队列为空时，自动下载、校验、替换、重启。队列非空会延后 60 秒重试。 |

管理页「更新」可切换策略和间隔（1–168 小时）。CLI 等价：

```bash
FWArmy update                     # 检查并打印
FWArmy update --yes               # 检查后安装并重启
FWArmy update --yes --force       # 允许同版本重装/队列非空时强制
FWArmy update --auto=install      # 开自动安装
FWArmy update --auto=check --interval=12
FWArmy update --status
```

### 5.2 更新器实际做了什么

1. 请求 `https://api.github.com/repos/Pondsi/FWArmy/releases/latest`，只接受稳定 Release。
2. 按平台选资产：`*-win-x64.zip`、`*-macos-arm64.tar.gz`、`*-macos-x64.tar.gz`、`*-linux-x64.tar.gz`。
3. 下载到 `data/updates/<版本>/`；校验 GitHub 资产 `sha256`，缺失时回退 Release 的 `SHA256SUMS`。
4. 解压（Windows 用系统 `tar.exe`，失败回退 PowerShell `Expand-Archive`；macOS/Linux 用 `tar -xzf`）。
5. 找到新二进制，运行 `--version` 确认能执行且版本匹配（测试环境另有跳过开关）。
6. 复制到当前程序旁的 `FWArmy.new`/`FWArmy.exe.new`。
7. 关闭监听、落盘 stats/expand/security，把当前程序改名为 `FWArmy.old-<时间戳>`，把 `.new` 改名为当前程序，带原 `--port/--host/--data/--no-open` 重启。
8. 新进程启动 15 秒后清理 `.old-*`；如果新版本起不来，可以把最新的 `.old-*` 改回原名回滚。

更新只替换程序文件，不动 `data/`。自动更新不会在队列有消息时强行重启；手动更新会提示，确认后可强制。

### 5.3 平台特有风险

- **Windows**：未签名新 exe 可能被 Smart App Control / WDAC 企业策略拦；更新会在“新二进制不能运行”处失败，当前程序不动。需要关闭 Smart App Control、加 WDAC 允许规则，或使用签名版本。
- **macOS**：新二进制来自 tar.gz，无 quarantine + ad-hoc 签名；如果安装目录不可写（例如放在只读卷），替换会失败；把程序装在 `~/Applications` 或可写目录。
- **Linux**：需要当前用户对程序目录有写权限；systemd 用户服务更新后由新进程接管，若你的 unit 设置 `Restart=always`，原进程退出时 systemd 可能也尝试拉起，建议用 `Restart=on-failure` 或更新时先 `systemctl --user stop` 再手动更新。
- **GitHub API** 未登录约 60 次/小时；检查失败只显示错误，不影响中转服务。

### 5.4 从 0.5.0 升级

0.5.0 没有更新器；需要手动跑一次 0.5.1 安装器。之后 0.5.1 及以后可自动更新到后续版本。

## 6. 启停、日志、备份与卸载

### 6.1 启停

- Windows：开始菜单/`FWArmy.exe`；`FWArmy stop`；`fwarmy-headless.bat` 后台。
- macOS：双击 `FWArmy.command`；`FWArmy stop`；可配 LaunchAgent。
- Linux：`.desktop`/`fwarmy --open`；`fwarmy stop`；可配 systemd 用户服务。
- 程序**不内置**开机自启；需要常开请自行用任务计划程序/launchd/systemd，并明确这是你的选择。

### 6.2 日志

`data/server.log`；每行 `ISO时间 级别 事件`；超过 5 MB 下次启动轮转 `server.log.1`。不记录消息明文、信封内容、凭据明文、请求 query。

### 6.3 备份与迁移

要备份就复制整个 `data/`：

- `credentials.json`（凭据 sha256/名称/限额）
- `config.json`（全局限额/TLS）
- `stats.json`（统计）
- `expand.json`（扩网/身份/出网凭据密文）
- `security.json`（消息 ID 哈希/黑名单/来源公钥）
- `secret.key`（本机加密密钥，0600；丢了 expand 的出网凭据/身份私钥解不开）
- `tls/`（自签证书与私钥）
- `update.json`（更新设置/最近状态）

迁移到另一台机器：装同平台/同架构程序 → 停旧服务 → 复制整个 `data/` → 启动。注意路径/权限；不要把 `data/` 上传到公开仓库或网盘。丢失 `data/` = 凭据全部失效、统计清零。

### 6.4 卸载

- Windows：`FWArmy stop`，删除 `%LOCALAPPDATA%\FWArmy` 和开始菜单快捷方式。
- macOS：`FWArmy stop`，删除 `~/Applications/FWArmy`；如配了 LaunchAgent 一并删除。
- Linux：`fwarmy stop`，删除 `~/.local/share/fwarmy`、`~/.local/bin/fwarmy` 和 `.desktop`；如配了 systemd 用户服务先 `disable --now`。
- 卸载不会删除别的目录；`data/` 若还要留档，先复制走。

## 7. 故障排查表

| 平台 | 现象 | 常见原因 | 处理 |
|---|---|---|---|
| 通用 | 管理页打不开 | 服务没起/端口漂移/防火墙/浏览器拦 https | 看 `data/server.log` 和 `data/instance.json` 实际端口；用 `FWArmy status`；自签提示选继续 |
| 通用 | 端口被占用 | 已有 FWArmy/其它程序 | 程序会自动 +1；公网请显式 `--port`；`lsof`/`netstat` 查占用 |
| 通用 | 客户端 401 | 凭据错/停用/删除 | 管理页重建；确认复制完整 |
| 通用 | TLS 指纹不匹配 | 连错实例/重建证书 | 核对管理页指纹；重建后重新信任 |
| 通用 | 公网连不上 | 防火墙/安全组/端口转发/运营商 NAT | 逐层放行 TCP；用外部网络测；没有公网 IP 用云主机或扩网 |
| 通用 | 更新失败 | GitHub 限流/网络/哈希/权限/系统策略 | 管理页看错误；手动重试；检查目录写权限；Windows 看 Smart App Control/WDAC |
| Windows | SmartScreen | 未签名浏览器下载 | 更多信息 → 仍要运行；或用 `irm` 安装 |
| Windows | Smart App Control 直接拦 | 未签名/企业策略 | 关闭 Smart App Control 或加允许规则；企业机找 IT |
| Windows | 双击没反应 | 被杀毒/策略隔离 | 看 Windows 安全中心保护历史；加排除/允许 |
| macOS | “无法打开/已损坏” | quarantine/未公证 | `xattr -dr com.apple.quarantine ~/Applications/FWArmy`；系统设置放行 |
| macOS | 双击 `.command` 没反应 | 无执行权限/quarantine | `chmod +x`；`xattr`；或在终端运行二进制看报错 |
| macOS | 监听弹窗被拒 | 防火墙 | 系统设置 → 网络 → 防火墙 → 允许 FWArmy 传入 |
| Linux | `xdg-open` 不存在 | 无桌面环境 | 手动浏览器/SSH 隧道；管理面只回环 |
| Linux | 更新失败 | 目录只读/用户服务策略 | 装到用户可写目录；先停 systemd 再更新 |
| Linux | 端口不通 | ufw/firewalld/安全组 | 放行 TCP 8787；`ss -ltnp` 看监听 |
| 全部 | 消息丢失 | 队列只存 30 秒/重启 | 这是设计：FWArmy 不存消息；重要消息由 WArmy 客户端负责重试/持久化 |

## 8. 安全边界与最坏情况

- 管理面只回环、Host 必须回环名、拒绝跨站 JSON 以外写操作；同一台机器上的其它本地进程仍可调用管理接口——不要把服务器放在多人共用机器上。
- 业务面必须 `Authorization: Bearer`；心跳/取信/下线还要 Ed25519 签名；服务器看不到消息明文。
- TLS 默认自签 + 指纹固定；公网不要关闭 TLS 或允许非回环明文。
- 服务器能看到元数据（谁在线、何时、信封大小），能拒服务/丢包/替换公钥；最后一条靠客户端带外核对指纹防住。
- 自动更新信任 GitHub Release + SHA256；如果 GitHub 账号/发布流程被攻破，更新器会下载恶意版本。发布账号要开 2FA；对高安全场景可改为手动更新或加签名校验（后续可做）。
- 最坏情况：拿到整机文件系统（含 `secret.key`）的人可解密扩网出网凭据、身份私钥；拿到管理面访问权的本机用户可改限额/停服/建凭据。做好磁盘加密、系统账号隔离和备份。

## 9. 上线前检查清单

- [ ] 端口固定（公网建议 8787），防火墙/安全组/端口转发已放行 TCP。
- [ ] 管理页能从本机打开；TLS 指纹已记录。
- [ ] 已生成至少一个业务凭据，明文已保存到 WArmy 客户端并点“我已保存”。
- [ ] WArmy 客户端用 https + 指纹固定连接成功，在线数正常。
- [ ] 公网测试：用另一网络连一次；确认不是只在局域网可用。
- [ ] 扩网/被扩网（如用）：指纹已核对并信任，测试消息成功。
- [ ] 更新策略确认（默认只检查；要自动安装再切 `install`）。
- [ ] `data/` 已备份；知道 `secret.key` 不能丢。
- [ ] 日志无凭据/消息明文；不要把管理端口映射公网。
