@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "FWArmy.exe" (
  "FWArmy.exe" stop %*
) else (
  node ctl.mjs stop %*
)
pause
