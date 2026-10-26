# FWArmy 中转服务器（独立程序）

> 名字说明：产品名 **FWArmy**；用户也常写成 **FWAmry**、目录/命令里写成 **fwarmy**，都指这一个程序。
> **独立项目**：本目录默认在 WArmy 仓库之外（`大龙虾互动区/FWArmy`），不和 WArmy 的源码/产物混放；
> WArmy 只在集成门禁里通过 `../FWArmy`（可用 `FWARMY_DIR` 覆盖）读取它。
> 它和 WArmy 主应用**分开安装、分开运行**：服务器可以放在一台常开的电脑/云主机上，主应用只把它当“可选服务器”填地址和凭据。
> 目录旧名是 `relay-server/`，第 64 轮起统一改名 `fwarmy/`；协议和加密没有变。

验证：`node verify-expand.mjs`（41 条）+ `node verify-binary.mjs <单文件>`（34 条）+ `node verify-update.mjs`（14 条）。

Release：https://github.com/Pondsi/FWArmy/releases/tag/v0.5.1

## 0. 三平台直接安装（0.5.1）

单文件自带运行时，**不装 Node、不要管理员权限、不需要付费证书**。安装器会先校验 `SHA256SUMS`，不会覆盖已有的 `data/`。

| 平台 | 一行安装 | 安装后启动 |
|---|---|---|
| Windows x64 | `irm https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.ps1 \| iex` | 开始菜单搜索 **FWArmy**（或双击安装目录里的 `FWArmy.exe`） |
| macOS arm64 / Intel | `curl -fsSL https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.sh \| sh` | 双击 `~/Applications/FWArmy/FWArmy.command` |
| Linux x64 | `curl -fsSL https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.sh \| sh` | 应用菜单搜索 **FWArmy**（或 `~/.local/bin/fwarmy --open`） |

直接下载便携包也可以：`FWArmy-0.5.1-win-x64.zip`、`FWArmy-0.5.1-macos-arm64.tar.gz`、`FWArmy-0.5.1-macos-x64.tar.gz`、`FWArmy-0.5.1-linux-x64.tar.gz`；解压后运行对应启动脚本。

**关于系统拦截（重要）**：用上面的 `irm` / `curl` 一行命令安装，文件不会带 macOS quarantine 或 Windows MOTW，安装后双击可直接启动。  
如果先从**浏览器**下载压缩包再解压，macOS Gatekeeper 和 Windows SmartScreen 可能各拦一次：

- macOS：用 `xattr -dr com.apple.quarantine ~/Applications/FWArmy`，或在“系统设置 → 隐私与安全性”里允许；macOS 15 起右键“打开”的快捷放行已被取消，部分 26.x 版本需要走终端命令。
- Windows：SmartScreen 选“更多信息 → 仍要运行”；Windows 11 的 Smart App Control 开启时可能直接拦未签名程序，需要在“Windows 安全中心 → 应用和浏览器控制”里关闭后重试。
- 要“浏览器下载后首次双击零警告”，只能 macOS 买 Apple Developer ID（99 美元/年）并公证，Windows 走 Microsoft Store（唯一保证）或签名+声誉（首次仍可能警告）。这与 Node/Java/Go 无关，是操作系统策略。详见 [docs/INSTALL-3-PLATFORMS.md](docs/INSTALL-3-PLATFORMS.md)。

三平台产物由 GitHub Actions 在 Windows、macOS 26 arm64、macOS 26 Intel、Ubuntu 真机上分别构建并跑完 `verify-expand` 41 条 + `verify-binary` 34 条 + 自动更新门禁后才上传；不是“声称支持”，是每个平台真跑过。

### 自动更新（0.5.1 起）

- 管理页新增 **更新** 标签：当前/最新版本、检查更新、下载并重启、自动策略（关闭 / 检查并提示 / 自动下载并重启）、检查间隔（1–168 小时）。
- 默认是 **检查并提示**；要无人值守更新，在管理页把策略切到「自动下载并重启」。
- 更新源是 GitHub Release 的 latest；只下载当前平台产物，校验 GitHub 资产 sha256（缺失时回退 `SHA256SUMS`）后才替换。下载/校验失败不会动当前程序。
- 重启会清空内存队列（消息 TTL 30 秒）。队列非空时，自动安装会延后 60 秒重试；手动「下载并重启」会提示并允许强制。
- CLI：`FWArmy update`（检查）、`FWArmy update --yes`（安装并重启）、`FWArmy update --auto=install`、`FWArmy update --status`。
- 更新只替换程序，保留 `data/`；旧文件 `.old-*` 会在新进程启动 15 秒后清理。新版本起不来时，可把最新的 `.old-*` 改名回 `FWArmy`/`FWArmy.exe` 回滚。
- **0.5.0 没有更新器**：从 0.5.0 升到 0.5.1 需要手动跑一次安装器；从 0.5.1 起可自动更新到后续版本。
- 检查 GitHub API 有频率限制（未登录约 60 次/小时）；默认 6 小时一次，手动检查失败会在页面显示原因，不影响服务。


FWArmy 只做**撮合与转发**：帮两个客户端找到彼此、转发不透明密文；**不存消息、不解析内容**。
消息只在内存队列停留最多 30 秒；磁盘上只有凭据哈希、配置、统计和运行日志。

完整的三平台操作流程、联网/TLS/防火墙/扩网/更新/故障排查见 [docs/USAGE-3-PLATFORMS.md](docs/USAGE-3-PLATFORMS.md)。

---

## 1. 三种运行方式（先看这一节）

| 方式 | 适合 | 需要什么 | 界面 |
|---|---|---|---|
| `FWArmy.exe` / `FWArmy`（单文件） | 日常使用、给不装 Node 的机器 | 无。单文件自带 Node 运行时 | 启动后自动打开系统默认浏览器里的管理页 |
| `fwarmy-headless.bat` / `fwarmy-headless.sh` | 后台常开、省资源 | Windows 用单文件；macOS/Linux 用单文件或 Node ≥20 | 无窗口；管理页仍可用浏览器打开 |
| `node server.mjs` / `node ctl.mjs` | 开发、调试、审代码 | Node.js ≥ 20 | 同上 |

**“界面”是自包含的浏览器管理页**（HTML/CSS/JS 全部内嵌在程序里，不加载任何外部字体/脚本/CDN），不是 Electron 窗口。
这样做的好处：单文件不需要再带一份 Chromium，体积小、启动快、三平台行为一致；代价是管理页外观取决于本机浏览器。

---

## 2. Windows：安装即用

### 2.1 直接安装（推荐）

```powershell
irm https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.ps1 | iex
```

- 装到 `%LOCALAPPDATA%\FWArmy`，并创建开始菜单快捷方式；不需要管理员权限。
- 安装器会下载 `FWArmy-0.5.1-win-x64.zip`、核对 `SHA256SUMS`，再解压；升级时**不会覆盖** `data\`。
- 用 `irm` 安装不会给文件打 MOTW，安装后双击不触发 SmartScreen；如果从浏览器下载 zip，可能触发“更多信息 → 仍要运行”。

### 2.2 便携包 / 自行构建

仓库**不提交**约 90 MB 的二进制；在 `fwarmy/` 下构建一次，得到 `dist/FWArmy.exe`：

```bat
cd fwarmy
node build-sea.mjs
```

构建完的 `dist/` 就是一个便携目录：

```
dist\
  FWArmy.exe              ← 双击即用（自带 Node，不需要装 Node）
  start.bat               ← 双击启动并打开管理页
  stop.bat                ← 停止
  fwarmy-headless.bat     ← 后台无界面启动（不开浏览器，写 data\server.log）
  fwarmy-console.bat      ← 控制台表格：状态 / 凭据 / 日·月·年统计
  install.ps1             ← 安装到 %LOCALAPPDATA% 的脚本
  assets\logo.svg
  README.md
  data\                   ← 首次运行自动创建（凭据哈希/配置/统计/日志）
```

实际验证过的命令（Windows 11 + Node v24.20.0）：

```bat
dist\FWArmy.exe --version
dist\FWArmy.exe                         :: 启动 + 自动打开 http://127.0.0.1:8787/
dist\FWArmy.exe table                   :: 控制台表格
dist\FWArmy.exe stop
```

- **不需要安装程序、不需要管理员权限、不需要 Node**；把 `dist\` 整个目录复制到别的 Windows 机器即可。
- 未做代码签名，浏览器下载后首次运行可能出现 SmartScreen「未知发布者」；确认来源后选「更多信息 → 仍要运行」。Windows 11 的 Smart App Control 若开启，可能直接拦未签名程序。
- 默认数据目录是 **exe 旁边的 `data\`**（便携）；也可以用 `--data=目录` 或环境变量 `FWARMY_DATA` 指定。
- **首次启动不自动生成凭据**（0.5.0 起）：打开管理页点“新建凭据”，明文只显示一次；保存到 WArmy 客户端后点“我已保存”。

> 单文件在**目标系统上构建**：Windows 上产出 `.exe`，macOS 上产出 Mach-O，Linux 上产出 ELF。仓库的 GitHub Actions 已经在四个真实 runner（Windows / macOS 26 arm64 / macOS 26 Intel / Ubuntu）上分别构建并验收，预编译产物见 Releases。

---

## 3. macOS / Linux

### 3.1 直接安装（推荐）

```bash
curl -fsSL https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.sh | sh
```

- macOS 装到 `~/Applications/FWArmy`，生成可双击的 `FWArmy.command`；Intel / Apple Silicon 都支持。
- Linux x64 装到 `~/.local/share/fwarmy`，生成 `~/.local/bin/fwarmy` 和 `~/.local/share/applications/fwarmy.desktop`，应用菜单里可直接点。
- 安装器会核对 `SHA256SUMS`；升级不覆盖 `data/`；不需要 `sudo`。
- macOS 构建产物已做 **ad-hoc 签名**（Apple Silicon 要求所有原生代码至少 ad-hoc 签名），但**没有 Apple Developer ID / 公证**。用 `curl` 安装不带 quarantine，双击可启动；从浏览器下载则可能被 Gatekeeper 拦，见下面 3.4。

### 3.2 从源码直接跑 / 自行构建

```bash
cd fwarmy
node server.mjs --host=0.0.0.0 --port=8787 --open
# 或：node ctl.mjs start --open
node ctl.mjs table
node ctl.mjs stop

./build-sea.sh          # 等价于 node build-sea.mjs，自动处理 macOS ad-hoc 签名
# 产物：dist/FWArmy（Linux/macOS）或 dist/FWArmy.exe（Windows）
```

- macOS：构建脚本会先 `codesign --remove-signature`，注入后 `codesign --sign -`（ad-hoc）。
- Linux：产物是普通 ELF 可执行文件；安装后的 `.desktop` 负责菜单入口，不需要 `.deb`/AppImage。
- 两个平台都提供 `start.sh` / `stop.sh` / `fwarmy-headless.sh` / `fwarmy-console.sh`；`start.sh` 会在后台启动单文件并用系统默认浏览器打开管理页。
- **macOS arm64、macOS x64、Linux x64 都已在 GitHub Actions 真机上跑完 41 + 34 条验收**（见 `.github/workflows/build.yml`），不再只是“构建脚本写了但没跑”。

### 3.3 构建期依赖（运行期零依赖）

`build-sea.mjs` 会通过 `npx` 临时下载两个**构建工具**（版本固定）：

- `esbuild@0.25.10`：把 ESM 打成单文件 CJS；
- `postject@1.0.0-alpha.6`：把 SEA blob 注入当前 Node 可执行文件。

构建需要联网；**构建出来的程序运行时不联网下载任何东西，也不依赖 node_modules**。

### 3.4 签名与系统拦截（三平台都适用）

| 平台 | 无付费证书能做到 | 做不到 |
|---|---|---|
| macOS | `curl`/Homebrew 安装后双击；ad-hoc 签名满足 Apple Silicon；`xattr` 可清浏览器隔离 | 浏览器下载的未公证程序首次双击零警告；需要 Apple Developer ID + 公证 |
| Windows | `irm`/curl/Scoop 安装后双击；无 MOTW 时不触发 SmartScreen | 浏览器下载未签名 exe 零警告；Smart App Control 开启时可能直接拦；需要 Store 或签名+声誉 |
| Linux | tar.gz + `.desktop` / AppImage 双击；无强制签名 | 没有 OS 级“发布者保证”；杀毒/发行版策略仍可能拦 |

- **“浏览器下载 → 首次双击零警告”不是语言问题**：Java 的 jpackage、Go、Node SEA 产出的都是普通未签名可执行文件，走的还是同一套 Gatekeeper/SmartScreen 规则。
- 如果你以后要消费级零警告：macOS 买 Apple Developer ID（99 美元/年，公证免费）；Windows 走 Microsoft Store（微软重签名，唯一保证）或 Artifact Signing/OV 证书（约 9.99 美元/月起，首次仍可能警告）。签名是构建后的附加步骤，不影响现在的三平台包。

---

## 4. 管理页（本机打开即用，无登录）

启动后打开 `https://127.0.0.1:8787/`（TLS 关闭时是 `http://`；端口被占用会自动 +1，实际端口见 `data/instance.json`）。页面上可以：

- **总览**：运行时长、在线数、队列、当前速度（最近 60 秒）、峰值/分钟、今日/本月/今年/累计的请求数与上下行字节、未授权尝试。
- **更新**：当前/最新版本、检查更新、下载并重启、自动策略与检查间隔、发布说明、最近检查/安装记录。
- **凭据**：新建（名称 + 可选限额）、改名、改速度、停用/启用、删除（删除需再输入一次凭据名称）。
- **设置**：全局默认的请求速度、流量速度、日/月/年字节上限、单信封上限、队列上限、在线 TTL、接客开关。
- **日志**：最近 200 行运行日志（不含消息明文/凭据明文）。
- 探测公网 IP、关闭服务器。

管理页**只接受本机回环地址**，即使业务面绑 `0.0.0.0`，管理面也不会对公网开放。

---

## 5. 凭据与限额

### 5.1 新建与首次凭据

**0.5.0 起首次启动不自动生成凭据**：打开管理页，点“新建凭据”，生成后明文只显示一次。保存到 WArmy 客户端后点“我已保存”。

- 旧版本留下的 `data/first-credential.enc`（或更早的 `.txt`）仍会在启动时识别，管理页顶部显示一次；确认后删除。
- 数据目录里没有凭据时，业务面会一直返回 401，直到你手动建一个。
- **日志不会写凭据明文**。要重新查看旧版待保存凭据只能用管理页或 `FWArmy cred-default`（显式命令）。
- 凭据在磁盘上只存 `sha256(token)`；丢失明文只能删除后重建。

### 5.2 每个凭据可设置

| 字段 | 含义 | 留空 | 填 0 |
|---|---|---|---|
| `ratePerMin` | 每分钟请求数（令牌桶，允许一分钟内的突发） | 继承全局 | 不限制 |
| `bytesPerMin` | 每分钟信封字节数（控制“速度/带宽”） | 继承全局 | 不限制 |
| `dailyBytes` | 每日用量上限（上行+下行信封字节） | 继承全局 | 不限制 |
| `monthlyBytes` | 每月用量上限 | 继承全局 | 不限制 |
| `yearlyBytes` | 每年用量上限 | 继承全局 | 不限制 |
| `disabled` | 停用后该凭据立即 401 | — | — |

- 日/月/年按**服务器本机时区**切分；字节口径 = 信封字符串长度（上行入队 + 下行取走），**不含 HTTP 头/连接开销**。
- 旧版本的全局限额字段继续有效；旧凭据上遗留的 `ratePerMin`/`dailyBytes` 会迁移成该凭据的覆盖值，不再被丢掉。
- 删除凭据后，它的历史用量仍计入“总统计”（便于对账），但不再出现在凭据列表里。

### 5.3 命令行等价操作

```bash
node ctl.mjs cred-new "家里的电脑" --rate=60 --bytes-rate=2 --daily=50 --monthly=1024 --yearly=10240
#   --rate 次/分；--bytes-rate / --daily / --monthly / --yearly 单位 MB；0=不限
node ctl.mjs cred-list
node ctl.mjs cred-update <id或哈希前缀> --name="新名字" --rate=30 --disable
node ctl.mjs cred-enable <id>
node ctl.mjs cred-delete <id> --yes
```

单文件版本把 `node ctl.mjs` 换成 `FWArmy.exe` 即可。

### 5.4 扩网 / 被扩网（多个 FWArmy 互联）

管理页顶部现在是 **总览 | 扩网 | 日志** 三个标签。扩网页分两块，各自有和总览同款的卡片与统计表。

**扩网（我连接别人）**

- 填「地址（IP 或域名）」+「对方的被扩网凭据」即可添加。
- 不写端口默认 **59599**；写 `example.com:60000` 就指定 60000；IPv6 用 `[::1]:59599`。
- 本机 `/api/relay` **送不到**（收件人离线 / 队列满）时，按添加顺序把同一个不透明信封转给这些 FWArmy；第一个返回成功的即为结果，全部失败则把失败明细如实回给原发送方。
- 每个地址可「测试」（调用对方的 `/api/expand/ping`）、停用/启用、移除；移除不移除历史统计。

**被扩网（别人连接我）**

- 点「一键生成凭据」生成 `fwnexp_…`；**明文只显示这一次**，遗失请重新生成（旧凭据立即失效）。
- 对方填写：`你的域名或公网 IP:端口` + 这个凭据。管理页会显示本机**实际监听端口**；如果本机不是 59599（默认 8787），必须让对方显式写上 `:端口`，因为对方不填端口时会按 59599 连接。
- 对方调用 `POST /api/expand/relay`（`Authorization: Bearer <凭据>`，body `{to,envelope,source,route}`）；本机尝试投递，**无论成功失败都把结果返回**，并记入「被扩网」统计。
- 不会把消息再转给本机自己的扩网地址（只做一跳，避免环路）；`route` 里出现本机 instanceId 会拒绝。

**安全与存储**：被扩网凭据只存 sha256；扩网凭据需要用来调用对方，所以保存在本机 `expand.json`（请只在本机使用，不要外传）。信封仍然只在内存队列停留 30 秒，不落盘；日志不写消息明文/凭据明文。统计写入 `expand.json`（`stats.inbound` / `stats.outbound` / `perOutbound` / `perSource`）。

**接口**（管理面只允许本机回环）：`GET /api/admin/expand`、`POST /api/admin/expand-inbound`、`/expand-outbound`、`/expand-update`、`/expand-remove`、`/expand-test`；业务面新增 `POST /api/expand/relay`、`GET /api/expand/ping`。

---

## 6. 无界面（headless）与控制台

### 6.1 Windows

```bat
fwarmy-headless.bat     :: 用 PowerShell 隐藏窗口启动 FWArmy.exe --no-open
fwarmy-console.bat      :: 控制台表格，每 2 秒刷新；Ctrl+C 退出
```

- headless 不打开浏览器、不显示窗口；服务日志写到 `data\server.log`。
- 控制台表格自动按中英文字符宽度对齐；包含状态、每个凭据的今日/本月/今年/累计、速度、峰值、限额。
- 控制台**不会**打印凭据明文；首次凭据请用管理页或 `FWArmy cred-default`。

### 6.2 macOS / Linux

```bash
./fwarmy-headless.sh
./fwarmy-console.sh
```

### 6.3 日志

- 位置：`data/server.log`；单文件超过 5 MB 在下次启动时轮转为 `server.log.1`。
- 每行格式：`ISO时间 级别  事件`，级别固定 5 列宽；终端和文件内容一致。
- **不记录**：消息明文、信封内容、凭据明文、请求 query（query 里有 did/签名）。
- 会记录：启动/停止、端口、数据目录、每条 HTTP 请求的方法/路径/状态码/耗时/凭据哈希前 8 位。

---

## 7. 统计口径与文件

`data/stats.json`（原子写入，损坏时改名为 `stats.corrupt-<时间戳>` 并按空表启动，不挡服务）：

- `credentials.<id>.total`：累计请求、上行/下行字节、转发、投递、拒绝、离线；
- `days` / `months` / `years`：按本机时区的分桶（保留约 400 天 / 36 月 / 10 年）；
- `peakPerMin` / `peakAt`：该凭据的每分钟请求峰值；
- 最近 60 秒速度是**内存窗口**，重启后从 0 开始（历史峰值保留）；
- 顶层 `unauthorized`：没有有效凭据的尝试次数（不归属任何凭据）。

`data/credentials.json` 只存 `sha256(token)`、名称、限额、停用状态、创建/最近使用时间；**不存明文 token**（首次引导文件除外，确认后删除）。
`data/config.json` 存全局默认；`data/update.json` 存更新策略/最近检查/安装记录；`data/updates/` 暂存下载的更新包；`data/instance.json` / `server.pid` 用于单实例与 `stop` 识别；`data/.initialized` 防止删光凭据后重启又自动生成。

删除整个 `data/` = 恢复出厂：所有凭据失效、统计清零。

---

## 8. 安全边界（无登录 ≠ 无边界）

| 边界 | 挡什么 |
|---|---|
| 只接受回环地址（127.0.0.1 / ::1 / ::ffff:127.0.0.1） | 公网/局域网直接访问管理面 |
| `Host` 必须是 `127.0.0.1` / `localhost` / `[::1]` | DNS rebinding |
| Origin 为空或同源；`Sec-Fetch-Site: cross-site` 拒绝 | 浏览器里的恶意页面借刀 POST |
| 管理写操作必须 `application/json` | 简单表单跨站 POST |
| 业务面必须 `Authorization: Bearer <凭据>` | 未授权业务访问 |
| 心跳/取信/下线必须 Ed25519 签名 | 拿一个凭据替别人上线、取信、踢下线 |

**最坏情况**：同一台机器上的其它本地进程/本地用户可以直接调用管理接口（生成/停用/删除凭据、改限额、关服务器）。这是“普通本地软件、打开即用”的代价；不要把服务器放在多人共用机器上，也不要把管理端口映射到公网。

服务器看不到明文；它能做的是拒服务、丢包、看元数据、替换公钥——最后一条靠客户端**带外核对身份指纹**防住。详见 `docs/SERVER-RELAY.md`。

---

## 9. 数据目录与兼容

- 默认：单文件 → exe 同目录 `data/`；源码 → `fwarmy/data/`。
- 覆盖：`--data=目录` 或环境变量 `FWARMY_DATA`；旧环境变量 `WARMY_RELAY_DATA` 仍兼容（测试会用）。
- 旧目录 `relay-server/` 已改名 `fwarmy/`；如果旧版留下 `relay-server/data/`，把里面的 `credentials.json`/`config.json` 复制到新 `data/` 即可继续用（哈希格式没变）。
- 健康检查：`GET /api/health` 返回 `{"server":"fwarmy-relay","product":"FWArmy",...}`；`ctl stop` 用它确认端口上真的是 FWArmy，PID 被复用时拒绝误杀。

---

## 10. 开发与验证

```bash
node server.mjs --port=8799 --host=127.0.0.1 --data=/tmp/fwarmy-dev --no-open
node ctl.mjs table --data=/tmp/fwarmy-dev
node ctl.mjs start --port=8799 --data=/tmp/fwarmy-dev
node ctl.mjs stop --data=/tmp/fwarmy-dev
```

仓库门禁：

```bash
node packages/app-shell/scripts/verify-r58-zhongji.mjs
node packages/app-shell/scripts/verify-r59-wangluo.mjs
node packages/app-shell/scripts/verify-r60-nm-server.mjs
node packages/app-shell/scripts/verify-r64-fwarmy.mjs
node fwarmy/verify-expand.mjs        # 扩网/被扩网：进程内两台服务器的全链路（41 条）

# 单文件黑盒验收（先 node build-sea.mjs）
node fwarmy/verify-binary.mjs fwarmy/dist/FWArmy.exe   # Windows
node fwarmy/verify-binary.mjs fwarmy/dist/FWArmy       # macOS/Linux

# 打包（CI 也是同一条命令）
node packaging/package.mjs --platform=win-x64

# 自动更新门禁（mock 更新源，不访问 GitHub）
node fwarmy/verify-update.mjs fwarmy/dist/FWArmy.exe fwarmy/out/FWArmy-0.5.1-win-x64.zip
```

三平台 CI：`.github/workflows/build.yml`（Windows / macOS 26 arm64 / macOS 26 Intel / Ubuntu）。每个 job 都先跑源码 41 条，再跑单文件 34 条，再做安装器冒烟和自动更新门禁；macOS 额外 `codesign --verify`。发布前用下载到的四个产物复核 `SHA256SUMS`。

协议细节：`docs/SERVER-RELAY.md`。第 63 轮及更早的交接文档里的 `relay-server/` 路径已同步改为 `fwarmy/`。
