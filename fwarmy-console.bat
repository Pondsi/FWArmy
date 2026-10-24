@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo FWArmy console - status / credentials / daily-monthly-yearly stats (Ctrl+C to exit)
if exist "FWArmy.exe" (
  "FWArmy.exe" console --watch
) else (
  node ctl.mjs console --watch
)
pause
