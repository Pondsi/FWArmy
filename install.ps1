# FWArmy installer for Windows x64 (no code-signing certificate required)
#
#   irm https://github.com/Pondsi/FWArmy/releases/download/v0.5.1/install.ps1 | iex
#
# Downloads the single-file zip, verifies SHA256SUMS, extracts to %LOCALAPPDATA%\FWArmy,
# and creates a Start Menu shortcut. No admin rights, no auto-start, and never deletes data\.
#
# Environment variables:
#   FWARMY_VERSION        override version (default 0.5.1)
#   FWARMY_BASE           override download base (a URL or a local directory; for tests)
#   FWARMY_SKIP_SHORTCUT  set to 1 to skip the Start Menu shortcut (for tests)
$ErrorActionPreference = 'Stop'

$Version = if ($env:FWARMY_VERSION) { $env:FWARMY_VERSION } else { '0.5.1' }
$Repo = if ($env:FWARMY_REPO) { $env:FWARMY_REPO } else { 'Pondsi/FWArmy' }
$Base = if ($env:FWARMY_BASE) { $env:FWARMY_BASE } else { "https://github.com/$Repo/releases/download/v$Version" }
$Asset = "FWArmy-$Version-win-x64.zip"

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

function Fail([string]$Message) {
  Write-Host "FWArmy install failed: $Message" -ForegroundColor Red
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
  Write-Host "Downloading $Asset ..."
  Fetch 'SHA256SUMS' (Join-Path $Tmp 'SHA256SUMS')
  Fetch $Asset (Join-Path $Tmp $Asset)

  $zip = Join-Path $Tmp $Asset
  $sumLine = $null
  foreach ($l in Get-Content (Join-Path $Tmp 'SHA256SUMS')) {
    $parts = @($l -split '\s+' | Where-Object { $_ })
    if ($parts.Count -ge 2 -and $parts[1] -eq $Asset) { $sumLine = $parts; break }
  }
  if (-not $sumLine) { Fail "SHA256SUMS has no entry for $Asset" }
  $want = $sumLine[0].ToLowerInvariant()
  $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
  if ($got -ne $want) { Fail "SHA256 mismatch (expected $want, got $got)" }

  Expand-Archive -Path $zip -DestinationPath $Tmp -Force
  $src = Get-ChildItem $Tmp -Directory -Filter 'FWArmy-*' | Select-Object -First 1
  if (-not $src) { Fail 'archive has no FWArmy-* directory' }

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
      Write-Host "Note: could not create the Start Menu shortcut ($($_.Exception.Message)); run $InstallDir\FWArmy.exe directly." -ForegroundColor Yellow
    }
  }

  $v = & (Join-Path $InstallDir 'FWArmy.exe') --version
  if (-not ($v -match 'FWArmy')) { Fail 'installed binary cannot run (Smart App Control may have blocked it)' }

  Write-Host ''
  Write-Host "FWArmy $Version installed to: $InstallDir" -ForegroundColor Green
  Write-Host "Start: search FWArmy in the Start Menu, or double-click $InstallDir\FWArmy.exe"
  Write-Host "Data: $InstallDir\data (upgrades keep credentials, stats and logs)"
  Write-Host 'If SmartScreen appears: More info -> Run anyway.'
  Write-Host 'If Windows 11 Smart App Control blocks it: Windows Security -> App & browser control -> Smart App Control; turn it off and retry.'
  Write-Host 'Uninstall: delete the install folder and the Start Menu shortcut. No system service is left behind.'
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
