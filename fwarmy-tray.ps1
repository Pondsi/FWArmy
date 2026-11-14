# FWArmy 系统托盘（Windows）：logo 图标、双击打开管理页、右键菜单（打开/退出）。
# 由主进程启动（powershell -WindowStyle Hidden -File fwarmy-tray.ps1 -Port N -Pid N -Data dir）；
# 主进程退出后本脚本自动退出；无交互桌面（CI/服务会话）时静默退出，不影响主进程。
param(
  [int]$Port = 8787,
  [int]$MainPid = 0,
  [string]$Data = ''
)
# R141：主进程 pid 参数名不用 $Pid——与 PowerShell 内置只读变量 $PID 冲突，脚本一启动就退出，托盘图标从未显示过。
$ErrorActionPreference = 'SilentlyContinue'

# R146：托盘状态写入数据目录（管理页据此显示诊断信息：正常/溢出区提示/无交互会话/失败原因）
$script:TrayDataDir = $Data   # 事件闭包内 $Data 不可见——用脚本作用域变量
function Write-TrayState([string]$status, [string]$err = '') {
  try {
    $obj = @{ status = $status; pid = $PID; at = (Get-Date).ToUniversalTime().ToString('o'); error = $err }
    $obj | ConvertTo-Json -Compress | Set-Content (Join-Path $script:TrayDataDir 'tray-state.json') -Encoding UTF8
  } catch { }
}

# 无交互桌面（Session 0 / 非交互服务）→ 静默退出；状态告知管理页
if (-not [Environment]::UserInteractive) { Write-TrayState 'no-interactive-session' '无交互桌面会话（Session 0/服务方式）——托盘图标无法显示，请改在 RDP 登录的桌面会话中运行'; exit 0 }

# 单实例：同脚本已有托盘进程则退出
$self = $MyInvocation.MyCommand.Path
$dup = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  Where-Object { $_.CommandLine -like "*$self*" -and $_.ProcessId -ne $PID }
if ($dup) { Write-TrayState 'duplicate' '已有托盘进程，本实例退出'; exit 0 }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# 最新入口端口（端口页可能改过入口）：instance.json 优先，参数兜底
function Get-EntryPort {
  if ($Data) {
    $inst = Join-Path $Data 'instance.json'
    if (Test-Path $inst) {
      try {
        $j = Get-Content $inst -Raw | ConvertFrom-Json
        if ($j.port -gt 0) { return [int]$j.port }
      } catch { }
    }
  }
  return $Port
}
function Open-AdminPage {
  try { Start-Process ('http://127.0.0.1:' + (Get-EntryPort) + '/') } catch { }
}
function Exit-FWArmy {
  try {
    Invoke-RestMethod -Uri ('http://127.0.0.1:' + (Get-EntryPort) + '/api/admin/shutdown') -Method Post -Body '{}' -ContentType 'application/json' -TimeoutSec 5
  } catch { }
  $script:tray.Visible = $false
  [System.Windows.Forms.Application]::Exit()
}

try {
  $ico = $null
  $icoPath = Join-Path $PSScriptRoot 'assets\fwarmy.ico'
  if (Test-Path $icoPath) { $ico = New-Object System.Drawing.Icon($icoPath) }
  if (-not $ico -and $MainPid -gt 0) {
    try { $ico = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -Id $MainPid).Path) } catch { }
  }
  if (-not $ico) { $ico = [System.Drawing.SystemIcons]::Application }

  $menu = New-Object System.Windows.Forms.ContextMenuStrip
  $open = New-Object System.Windows.Forms.ToolStripMenuItem('打开管理页')
  $quit = New-Object System.Windows.Forms.ToolStripMenuItem('退出 FWArmy')
  $open.Add_Click({ Open-AdminPage })
  $quit.Add_Click({ Exit-FWArmy })
  $menu.Items.Add($open) | Out-Null
  $menu.Items.Add($quit) | Out-Null

  $script:tray = New-Object System.Windows.Forms.NotifyIcon
  $script:tray.Icon = $ico
  $script:tray.Text = 'FWArmy 中继服务器'
  $script:tray.ContextMenuStrip = $menu
  $script:tray.add_DoubleClick({ Open-AdminPage })
  $script:tray.Visible = $true
  # R146：图标已注册——Windows 7+ 新图标默认进「溢出区」（任务栏 ^ 箭头），管理页据此提示
  Write-TrayState 'ok' '图标已注册到通知区域；Windows 7+ 新图标默认折叠在任务栏「^」溢出区，请展开查看'

  # 主进程消失 → 托盘自动退出（防残留图标）
  $timer = New-Object System.Windows.Forms.Timer
  $timer.Interval = 2000
  $timer.add_Tick({
    if ($MainPid -gt 0) {
      try { $null = Get-Process -Id $MainPid -ErrorAction Stop } catch {
        $timer.Stop()
        Write-TrayState 'stopped' '主进程已退出，托盘随之退出'
        $script:tray.Visible = $false
        [System.Windows.Forms.Application]::Exit()
      }
    }
  })
  $timer.Start()
  [System.Windows.Forms.Application]::Run()
} catch {
  try { $script:tray.Visible = $false } catch { }
  Write-TrayState 'error' ('托盘启动失败：' + ($_.Exception.Message | Out-String).Trim())
  exit 1
}
