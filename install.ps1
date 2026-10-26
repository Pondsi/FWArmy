# FWArmy 无证书安装器（Windows x64）
#
#   irm https://github.com/Pondsi/FWArmy/releases/download/v0.5.0/install.ps1 | iex
#
# 做四件事：下载单文件 zip、校验 SHA256、解压到 %LOCALAPPDATA%\FWArmy、建开始菜单快捷方式。
# 不请求管理员权限，不启动服务，不覆盖已有的 data\（凭据/统计/日志）。
#
# 可用环境变量：
#   FWARMY_VERSION        指定版本（默认 0.5.0）
#   FWARMY_BASE           指定下载源（默认 GitHub Release；本地测试可传目录）
#   FWARMY_SKIP_SHORTCUT  设为 1 时不建开始菜单快捷方式（测试用）
$ErrorActionPreference = 'Stop'

$Version = if ($env:FWARMY_VERSION) { $env:FWARMY_VERSION } else { '0.5.0' }
$Repo = if ($env:FWARMY_REPO) { $env:FWARMY_REPO } else { 'Pondsi/FWArmy' }
$Base = if ($env:FWARMY_BASE) { $env:FWARMY_BASE } else { "https://github.com/$Repo/releases/download/v$Version" }
$Asset = "FWArmy-$Version-win-x64.zip"

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

function Fail([string]$Message) {
  Write-Host "FWArmy 安装失败：$Message" -ForegroundColor Red
  exit 1
}

function Fetch([string]$Name, [string]$Dest) {
  if ($Base -match '^https?://') {
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Name" -OutFile $Dest
  } elseif ($Base -match '^file://') {
    $dir = ([Uri]$Base).LocalPath
    Copy-Item -Force (Join-Path $dir $Name) $Dest
  } else {
    Copy-Item -Force (Join-Path $Base $Name) $Dest
  }
}

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ('fwarmy-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
try {
  Write-Host "下载 $Asset ..."
  Fetch 'SHA256SUMS' (Join-Path $Tmp 'SHA256SUMS')
  Fetch $Asset (Join-Path $Tmp $Asset)

  $zip = Join-Path $Tmp $Asset
  $sumLine = $null
  foreach ($l in Get-Content (Join-Path $Tmp 'SHA256SUMS')) {
    $parts = @($l -split '\s+' | Where-Object { $_ })
    if ($parts.Count -ge 2 -and $parts[1] -eq $Asset) { $sumLine = $parts; break }
  }
  if (-not $sumLine) { Fail "SHA256SUMS 里没有 $Asset" }
  $want = $sumLine[0].ToLowerInvariant()
  $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
  if ($got -ne $want) { Fail "SHA256 校验失败（期望 $want，实际 $got）" }

  Expand-Archive -Path $zip -DestinationPath $Tmp -Force
  $src = Get-ChildItem $Tmp -Directory -Filter 'FWArmy-*' | Select-Object -First 1
  if (-not $src) { Fail '压缩包里没有 FWArmy-* 目录' }

  $root = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [Environment]::GetFolderPath('LocalApplicationData') }
  $InstallDir = Join-Path $root 'FWArmy'
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

  foreach ($item in Get-ChildItem $src.FullName -Force) {
    if ($item.Name -eq 'data') { continue }
    $dest = Join-Path $InstallDir $item.Name
    if ($item.PSIsContainer) {
      if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
      Copy-Item -Recurse -Force $item.FullName $dest
    } else {
      Copy-Item -Force $item.FullName $dest
    }
  }

  if ($env:FWARMY_SKIP_SHORTCUT -ne '1') {
    try {
      $startMenu = [Environment]::GetFolderPath('Programs')
      $lnk = Join-Path $startMenu 'FWArmy.lnk'
      $ws = New-Object -ComObject WScript.Shell
      $sc = $ws.CreateShortcut($lnk)
      $sc.TargetPath = Join-Path $InstallDir 'FWArmy.exe'
      $sc.WorkingDirectory = $InstallDir
      $sc.IconLocation = (Join-Path $InstallDir 'FWArmy.exe') + ',0'
      $sc.Description = 'FWArmy relay server'
      $sc.Save()
    } catch {
      Write-Host "提示：开始菜单快捷方式创建失败（$($_.Exception.Message)）；可直接运行 $InstallDir\FWArmy.exe" -ForegroundColor Yellow
    }
  }

  $v = & (Join-Path $InstallDir 'FWArmy.exe') --version
  if (-not ($v -match 'FWArmy')) { Fail '装好的程序无法执行（可能被 Smart App Control 拦截）' }

  Write-Host ''
  Write-Host "FWArmy $Version 已安装到：$InstallDir" -ForegroundColor Green
  Write-Host "启动：开始菜单搜索 FWArmy，或双击 $InstallDir\FWArmy.exe"
  Write-Host "数据目录：$InstallDir\data（升级不会删除其中凭据/统计/日志）"
  Write-Host '如果出现 SmartScreen：更多信息 → 仍要运行。'
  Write-Host '如果 Windows 11 的 Smart App Control 直接拦截：Windows 安全中心 → 应用和浏览器控制 → Smart App Control；关闭后重试。'
  Write-Host '卸载：删除安装目录和开始菜单快捷方式即可；不会留下系统服务。'
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
