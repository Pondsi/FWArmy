# FWArmy 三平台交付说明（0.5.1）

> 目的：回答“FWArmy 改用 Java 是不是更好”“能不能不买 Apple Developer ID 就三平台双击运行”，
> 并记录这一轮实际交付方式、验收证据、系统拦截边界和后续可选步骤。

## 1. 结论

**没有改用 Java。** 现有 Node 实现已经能产出三平台自带运行时的单文件；真正缺的是 macOS/Linux 的**真实构建与验收**，不是语言。

- Java + `jpackage` 不能交叉编译：Windows/macOS/Linux 每个平台都必须在自己的系统上构建（[jpackage 手册](https://man.archlinux.org/man/extra/jdk21-openjdk/jpackage-openjdk21.1.en)）。
- Java 自带 JRE 也只是“该平台的 JRE”，并不能让一个包在三平台通用。
- 现有服务端 2,621 行 + CLI 513 行，已覆盖 TLS 自签/指纹固定、Ed25519 来源签名、STUN/NAT-PMP、限额、扩网、AES-GCM 凭据存储，并有 41 条源码门禁；重写成 Java 约 4,000 行，协议风险最大、周期最长。
- Java 产物约 50–60 MB/平台；现有 Node SEA 约 90–127 MB；Go 约 12–15 MB。Java 只比 Node 小一点，输 Go 很多，但三条路都要面对同样的 macOS/Windows 签名规则。

**采用的方案**：保留 Node，GitHub Actions 在四个真实 runner（Windows / macOS 26 arm64 / macOS 26 Intel / Ubuntu）上分别构建单文件，跑源码 41 条 + 单文件 34 条 + 安装器冒烟，再发布。零重写、风险最低。

## 2. 交付物

| 平台 | 产物 | 安装后启动方式 | 运行时 |
|---|---|---|---|
| Windows x64 | `FWArmy-0.5.1-win-x64.zip` | 开始菜单 FWArmy / 双击 `FWArmy.exe` | 自带 Node |
| macOS Apple Silicon | `FWArmy-0.5.1-macos-arm64.tar.gz` | 双击 `FWArmy.command` | 自带 Node，ad-hoc 签名 |
| macOS Intel | `FWArmy-0.5.1-macos-x64.tar.gz` | 双击 `FWArmy.command` | 自带 Node，ad-hoc 签名 |
| Linux x64 | `FWArmy-0.5.1-linux-x64.tar.gz` | 应用菜单 FWArmy / `~/.local/bin/fwarmy --open` | 自带 Node |

另外发布：`install.sh`、`install.ps1`、`SHA256SUMS`。

### 一行安装

```sh
# macOS / Linux
curl -fsSL https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.sh | sh
```

```powershell
# Windows PowerShell
irm https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.ps1 | iex
```

安装器行为：

- 下载对应平台包 + `SHA256SUMS`，校验失败即停止。
- Windows 装到 `%LOCALAPPDATA%\FWArmy` 并建开始菜单快捷方式；macOS 装到 `~/Applications/FWArmy`；Linux 装到 `~/.local/share/fwarmy`。
- 不请求管理员/root，不注册系统服务，不自动启动，不覆盖已有 `data/`。
- 升级时只替换程序文件，保留凭据/统计/日志。

## 3. “不买证书能不能双击”的真话

分两种“双击”：

| 场景 | macOS | Windows | Linux | 付费证书 |
|---|---|---|---|---|
| 浏览器下载 → 首次双击零警告 | 必须 Developer ID + 公证 | 只有 Microsoft Store 能保证 | 不需要 | macOS 要；Windows 看渠道 |
| 一行命令装好 → 之后双击 | 可以：curl 安装 + ad-hoc 签名 | 可以：irm/curl 安装，避开 MOTW；Smart App Control 可能拦 | 可以：tar.gz + `.desktop` | 不需要 |
| 浏览器下载 → 手动放行一次 | 系统设置 → 仍要打开，或 `xattr` | 更多信息 → 仍要运行 | 不需要 | 不需要 |

关键机制：

- **macOS Gatekeeper 只检查带 `com.apple.quarantine` 的文件**；Safari/Chrome 下载会打标记，`curl`/`scp` 不会（[Unit 42](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)、[Eclectic Light](https://eclecticlight.co/2021/12/11/explainer-quarantine/)）。
- Apple Silicon 上所有原生代码必须至少 ad-hoc 签名，否则内核拒绝执行；ad-hoc 不等于公证（[Eclectic Light](https://eclecticlight.co/2020/08/22/apple-silicon-macs-will-require-signed-code/)）。`build-sea.mjs` 在 macOS 上已执行 `codesign --sign -`。
- macOS 15 移除了右键“打开”的快捷放行（[Michael Tsai](https://mjtsai.com/blog/2024/07/05/sequoia-removes-gatekeeper-contextual-menu-override/)）；部分 macOS 26.x 版本“仍要打开”也不稳定，最后只能 `xattr -dr com.apple.quarantine`。
- **Windows SmartScreen** 看签名、MOTW、文件/发布者声誉；未签名浏览器下载首次会弹“Windows 保护了你的电脑”。`Invoke-WebRequest`/`curl` 通常不加 MOTW，所以脚本安装能避开（[Microsoft 文档](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)）。
- Windows 11 的 **Smart App Control** 会直接拦未签名程序，跟 MOTW 无关；这时只能关闭它、走 Store，或使用有效签名。
- 即使买 OV/EV 证书，首次下载仍可能警告；EV 已不再即时免警告。Microsoft Store 是唯一“永不警告”的保证；Artifact Signing（原 Trusted Signing）约 9.99 美元/月，声誉要积累。
- Linux 没有 Gatekeeper/SmartScreen 等价物；tar.gz + `.desktop` 或 AppImage 即可，但发行版/杀毒策略仍可能拦。
- **Java 不改变以上任何一条**：jpackage 的 `.app/.dmg/.msi/.deb` 同样是未签名可执行文件，并且不能交叉编译。

### 无证书方案（本次采用）

- macOS：`curl` 安装，不产生 quarantine；构建时 ad-hoc 签名；安装后 `FWArmy.command` 可双击。浏览器下载时安装器会尝试 `xattr -dr`。
- Windows：`irm` 安装，zip 不带 MOTW，解压后的 exe 双击不触发 SmartScreen；README 写明 Smart App Control 的例外。
- Linux：tar.gz + 生成 `.desktop` 菜单项；不需要签名。
- 结果：**装一次，之后三平台都能双击启动**，不需要付费证书。
- 不能保证：任何人从浏览器下载压缩包后首次双击零警告。那需要 macOS Developer ID + 公证；Windows 需要 Store 或签名 + 声誉。

### 如果以后要“浏览器下载零警告”

| 平台 | 方案 | 成本 | 备注 |
|---|---|---|---|
| macOS | Apple Developer Program + `codesign` + `notarytool` + `stapler` | 99 美元/年 | 公证服务本身免费；需要 Apple 账号和证书 |
| Windows | Microsoft Store（MSIX） | Store 账号费用 | 唯一保证零警告；服务器形态需要适配 MSIX/更新 |
| Windows | Artifact Signing / OV 证书 | 约 9.99 美元/月起 / 数百美元/年 | 首次仍可能警告，声誉累积后消失；EV 不再即时 bypass |
| Windows | 自签名证书 | 0 | 等同未签名，无帮助 |
| Linux | 无 | 0 | 已满足 |

签名是构建后的附加步骤，不影响现有包；CI 里加 `signtool`/`codesign` 即可。

## 4. 本轮代码改动

- `package.json`：0.4.0 → 0.5.1，与服务端 `VERSION` 对齐。
- `build-sea.mjs`：
  - SEA 资源增加 `logo.svg`（此前单文件运行 `/assets/logo.svg` 可能 500）。
  - 便携目录按平台拷入安装脚本、`FWArmy.command`（macOS）、`FWArmy.desktop`（Linux）、`assets/logo.svg`；`.sh`/`.command` 设可执行位。
- `install.sh`：macOS/Linux 下载、SHA256 校验、安装、macOS `xattr` 清理、Linux `.desktop`/软链、升级保留 `data/`。
- `install.ps1`：Windows 下载、SHA256 校验、解压、开始菜单快捷方式、升级保留 `data/`。脚本用**纯 ASCII 文案、无 BOM**，保证 Windows PowerShell 5.1 的 `-File` 和 `irm | iex` 都能解析；发布资产 `Content-Type` 设为 `text/plain`，避免 `irm` 返回 byte[]。
- `FWArmy.command`：macOS 双击后台启动并打开管理页。
- `FWArmy.desktop`：Linux 桌面项模板（安装器会写绝对路径版本）。
- `ctl.mjs`：`stop` 先调管理面 `/api/admin/shutdown`，三平台都能优雅落盘并 exit(0)；Windows 的 SIGTERM 强杀路径只作为回退；新增 `update` 命令。
- `verify-binary.mjs`：34 条单文件黑盒验收（含更新状态/设置/管理页标签）。
- `verify-update.mjs`：14 条 mock 更新门禁（检查、错误哈希、下载/解压/替换/重启、设置）。
- **自动更新**：管理页「更新」标签与 `/api/admin/update*`；检查 GitHub latest、平台资产选择、SHA256/SHA256SUMS 校验、原子替换、带原参数重启、队列非空保护、失败回滚与 `.old` 清理。
- `docs/USAGE-3-PLATFORMS.md`：三平台完整操作流程、联网/TLS/防火墙/扩网/更新/排错。
- `packaging/package.mjs`：只收程序文件，绝不收 `data/`；生成平台目录、zip/tar.gz、SHA256。
- `.github/workflows/build.yml`：四平台构建 + 41 条 + 34 条 + 安装器冒烟 + 14 条更新门禁 + 上传 artifact。
- `README.md`：新增三平台安装、自动更新、系统拦截真话、CI 验收说明；修正“首次自动生成凭据”的旧描述。

## 5. 单文件验收（verify-binary.mjs，34 条）

- **启动/界面**：`--version`、健康检查、管理页、内嵌 logo、「更新」标签容器。
- **凭据/业务**：首次凭据 pending=false、新建凭据、无凭据 401、Ed25519 A/B 注册、在线查询、心跳、批量在线。
- **转发/安全**：A→B 入队、同 messageId 第二次允许（max 2）、第三次 409、B 取到 2 个信封、取走后不重复、bye 后离线、Host 非回环 403、跨站 Origin 403、表单 POST 403。
- **TLS**：管理面 64 位证书指纹、同端口 TLS 握手、指纹匹配。
- **扩网/CLI**：生成被扩网凭据、`/api/expand/ping`、CLI `table`、管理面 shutdown、第二次启动、CLI `stop`、停后端口不响应。
- **更新**：`/api/admin/update` 状态、`update-config` 保存、管理页「更新」标签存在。

自动更新另有独立门禁 `verify-update.mjs`（14 条）：mock 更新源识别、错误 SHA256 拒绝且服务不退、正确 SHA256 下载/解压/替换/重启、重启后版本与 `lastInstall`、`.new` 清理、设置保存。

## 6. 验收记录

本机（Windows 11 + Node v24.20.0）：

- 源码 `verify-expand.mjs`：41 ok / 0 FAIL。
- 0.5.0 Windows 单文件曾通过 31/0；0.5.1 新构建的未签名 exe 被本机 **WDAC/Device Guard** 拦（CodeIntegrity 3033），所以 Windows 单文件/更新门禁以 CI 为准，不把本机环境限制写成产品通过。
- `install.ps1` 本地 artifact 安装、升级保留 `data/` 在 0.5.0/0.5.1 脚本上通过；0.5.1 发布资产 `irm` 的下载/校验逻辑已由 CI 安装器冒烟覆盖。

WSL（Ubuntu 26.04 + Node v24.20.0，真实 Linux 内核）：

- 0.5.1：`verify-expand` 41/0；`verify-binary` 34/0；`verify-update` 14/0（错误哈希拒绝、替换、重启、状态保留）。
- `install.sh` 本地 artifact 安装、`.desktop`/软链、升级保留 `data/` 通过。
- 发布页 `curl .../v0.5.1/install.sh | sh` 全新安装复测通过；装好后 `FWArmy update` 对真实 GitHub 检查到最新 0.5.1，判定“已是最新”。

GitHub Actions 最终结果：

- 工作流：https://github.com/Pondsi/FWArmy/actions/runs/40280822789
- tag v0.5.1 触发的第二次：https://github.com/Pondsi/FWArmy/actions/runs/40285407698
- Windows / macOS 26 arm64 / macOS 26 Intel / Ubuntu 四个 runner 全部成功。
- 每个平台：41 + 34 + 14 条 + 安装器冒烟；macOS 额外 `codesign --verify --strict` 通过（未公证时 `spctl` 预期拒绝，只记录不作为失败）。
- 单文件本体：Windows 93,754,880 B；Linux 126,749,888 B；macOS x64 124,305,920 B；macOS arm64 121,227,328 B。
- Release 资产：
  - `FWArmy-0.5.1-win-x64.zip` 8cf28adb…
  - `FWArmy-0.5.1-linux-x64.tar.gz` efad824e…
  - `FWArmy-0.5.1-macos-x64.tar.gz` f15b6275…
  - `FWArmy-0.5.1-macos-arm64.tar.gz` 8b34fc3a…
  - 完整哈希见 Release 页 `SHA256SUMS`。

## 7. 已知限制

1. **macOS 未公证**：浏览器下载的包会被 Gatekeeper 拦；用 curl 安装或 `xattr` 放行。要消费级零警告需付费 Developer ID。
2. **Windows 未签名**：浏览器下载会 SmartScreen；Smart App Control 开启时可能直接拦。要零警告需 Store 或签名+声誉。
3. **Linux 只提供 x64**：arm64 Linux 需要再加一个 CI runner/构建矩阵；目前会明确报“不支持的架构”，不会装错包。
4. **没有 AppImage**：Linux 用 tar.gz + `.desktop`；AppImage 可在后续加，体积约 127 MB，且部分发行版缺 libfuse2。
5. **macOS 双击是 `.command`（会弹终端）**：不是原生 `.app` 包。要做 `.app` 需要把数据目录改为 `~/Library/Application Support/FWArmy`，并处理 bundle 只读；本轮未做。
6. **自动更新不是默认无人值守**：默认只检查提示；要自动安装需在管理页切换。首次从 0.5.0 到 0.5.1 仍需手动安装一次。Windows 的 Smart App Control/WDAC 可能拦住未签名新版本，更新会安全失败并保留旧版本。
7. **没有系统服务/开机自启**：这是有意的，避免“程序自己启动”；需要常开可用计划任务/launchd/systemd，用户自行配置。systemd 用户服务与自更新同时使用时，建议 `Restart=on-failure`，避免旧进程退出时被重复拉起。
8. **CI 的 macOS 验收是 headless**：跑了二进制、TLS、管理页、安装器、codesign；没有模拟 Finder 双击的 GUI 点击。真实双击行为靠 ad-hoc 签名 + 无 quarantine 的机制保证，并已在文档写明。

## 8. 最坏情况

- 用户从浏览器下载 macOS 包并直接双击：被 Gatekeeper 拦，需要 `xattr` 或系统设置放行；不是“打不开”，是“需要一次手动允许”。
- 用户 Windows 11 开着 Smart App Control：未签名 exe 被直接拦；需要关闭 Smart App Control 或等签名版本。
- 用户把管理端口映射到公网：管理面只接受回环，仍然拒绝；但业务面会暴露，需自行做防火墙/反代。
- 用户删掉安装目录：凭据/统计一起丢；`data/` 没有云端备份。
- 用户只升级 exe、不跑安装器：旧脚本/旧桌面项可能残留；重新跑安装器即可对齐。

## 9. 参考

- [Node.js SEA 文档](https://nodejs.org/api/single-executable-applications.html)
- [jpackage 手册（不能交叉编译）](https://man.archlinux.org/man/extra/jdk21-openjdk/jpackage-openjdk21.1.en)
- [Microsoft SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [Unit 42: Gatekeeper 只检查 quarantine](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
- [Eclectic Light: Quarantine 解释](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [Apple Silicon 要求签名](https://eclecticlight.co/2020/08/22/apple-silicon-macs-will-require-signed-code/)
- [macOS Sequoia 移除右键打开](https://mjtsai.com/blog/2024/07/05/sequoia-removes-gatekeeper-contextual-menu-override/)
- [Homebrew 移除 cask --no-quarantine](https://github.com/Homebrew/brew/issues/20755)
