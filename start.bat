@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "FWArmy.exe" (
  start "" "FWArmy.exe" %*
) else (
  node ctl.mjs start --open %*
)
