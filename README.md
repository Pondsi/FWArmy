# FWArmy 中转服务器（独立程序）

> 名字说明：产品名 **FWArmy**；用户也常写成 **FWAmry**、目录/命令里写成 **fwarmy**，都指这一个程序。
> WArmy 只在集成门禁里通过 `../FWArmy`（可用 `FWARMY_DIR` 覆盖）读取它。
> 它和 WArmy 主应用**分开安装、分开运行**：服务器可以放在一台常开的电脑/云主机上，主应用只把它当“可选服务器”填地址和凭据。

FWArmy 只做**撮合与转发**：帮两个客户端找到彼此、转发不透明密文；**不存消息、不解析内容**。
消息只在内存队列停留最多 30 秒；磁盘上只有凭据哈希、配置、统计和运行日志。

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

仓库**不提交** 90 MB 的二进制；在 `fwarmy/` 下构建一次，得到 `dist/FWArmy.exe`：

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
  README.md
  data\                   ← 首次运行自动创建（凭据哈希/配置/统计/日志）
```

实际验证过的命令（本机 Windows 10/11 + Node v24.20.0）：

```bat
dist\FWArmy.exe --version
dist\FWArmy.exe                         :: 启动 + 自动打开 http://127.0.0.1:8787/
dist\FWArmy.exe table                   :: 控制台表格
dist\FWArmy.exe stop
```

- **不需要安装程序、不需要管理员权限、不需要 Node**；把 `dist\` 整个目录复制到别的 Windows 机器即可。
- 未做代码签名，首次运行可能出现 SmartScreen「未知发布者」；确认来源后选「更多信息 → 仍要运行」。
- 默认数据目录是 **exe 旁边的 `data\`**（便携）；也可以用 `--data=目录` 或环境变量 `FWARMY_DATA` 指定。
- 首次启动会**自动生成一个安全凭据**（默认名称「默认凭据」），明文在管理页顶部显示一次；保存到 WArmy 客户端后点「我已保存」，服务器会删除明文引导文件 `data\first-credential.txt`。

> 单文件只在**目标系统上构建**：Windows 上产出 `.exe`，macOS 上产出 Mach-O，Linux 上产出 ELF。SEA 不能可靠跨平台注入，所以仓库不提供“Windows 上构建三平台”的假承诺。

---

## 3. macOS / Linux

### 3.1 从源码直接跑（最快，需要 Node ≥ 20）

```bash
cd fwarmy
node server.mjs --host=0.0.0.0 --port=8787 --open
# 或：node ctl.mjs start --open
node ctl.mjs table
node ctl.mjs stop
```

### 3.2 构建单文件（在目标系统上执行）

```bash
cd fwarmy
./build-sea.sh          # 等价于 node build-sea.mjs，自动处理 macOS ad-hoc 签名
# 产物：dist/FWArmy（Linux/macOS）或 dist/FWArmy.exe（Windows）
```

- macOS：构建脚本会先 `codesign --remove-signature`，注入后 `codesign --sign -`（ad-hoc）。**没有做 Apple 公证/开发者签名**；从网络下载后可能需要右键「打开」或在「系统设置 → 隐私与安全性」里放行，也可能需要 `xattr -d com.apple.quarantine dist/FWArmy`。README 不声称“macOS 安装包已可用”。
- Linux：产物是普通 ELF 可执行文件；`chmod +x dist/FWArmy` 后运行。没有打 `.deb`/AppImage；需要的话可自行用 `fpm`/`appimagetool` 包一层。
- 两个平台都提供 `start.sh` / `stop.sh` / `fwarmy-headless.sh` / `fwarmy-console.sh`；`start.sh` 会在后台启动单文件并用系统默认浏览器打开管理页。
- **未在本机实际验证 macOS/Linux 产物**（本轮只在 Windows 上构建并跑通）。构建脚本和平台分支已给出，需要在对应系统上复跑；这是当前明确的风险项。

### 3.3 构建期依赖（运行期零依赖）

`build-sea.mjs` 会通过 `npx` 临时下载两个**构建工具**（版本固定）：

- `esbuild@0.25.10`：把 ESM 打成单文件 CJS；
- `postject@1.0.0-alpha.6`：把 SEA blob 注入当前 Node 可执行文件。

构建需要联网；**构建出来的程序运行时不联网下载任何东西，也不依赖 node_modules**。

---

## 4. 管理页（本机打开即用，无登录）

启动后打开 `http://127.0.0.1:8787/`（端口被占用会自动 +1，实际端口见 `data/instance.json`）。页面上可以：

- **总览**：运行时长、在线数、队列、当前速度（最近 60 秒）、峰值/分钟、今日/本月/今年/累计的请求数与上下行字节、未授权尝试。
- **凭据**：新建（名称 + 可选限额）、改名、改速度、停用/启用、删除（删除需再输入一次凭据名称）。
- **设置**：全局默认的请求速度、流量速度、日/月/年字节上限、单信封上限、队列上限、在线 TTL、接客开关。
- **日志**：最近 200 行运行日志（不含消息明文/凭据明文）。
- 探测公网 IP、关闭服务器。

管理页**只接受本机回环地址**，即使业务面绑 `0.0.0.0`，管理面也不会对公网开放。

---

## 5. 凭据与限额

### 5.1 自动生成

首次启动（数据目录里没有 `.initialized` 且没有任何凭据）会自动生成：

- 名称：`默认凭据`
- 明文：`data/first-credential.txt`（权限尽量设为 0600；Windows 上由 ACL 决定）
- 管理页顶部会显示一次；点「我已保存」后删除该文件。
- **日志不会写凭据明文**。要重新查看明文只能用管理页或 `FWArmy cred-default`（显式命令）。

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
`data/config.json` 存全局默认；`data/instance.json` / `server.pid` 用于单实例与 `stop` 识别；`data/.initialized` 防止删光凭据后重启又自动生成。

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

---

## 9. 数据目录与兼容

- 默认：单文件 → exe 同目录 `data/`；源码 → `fwarmy/data/`。
- 覆盖：`--data=目录` 或环境变量 `FWARMY_DATA`；旧环境变量 `WARMY_RELAY_DATA` 仍兼容（测试会用）。
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
```



---

[LICENSE](./LICENSE) · [SPONSORS.md](./SPONSORS.md) · [说明.md](./说明.md)
