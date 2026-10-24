@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
if exist "FWArmy.exe" (
  powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process -FilePath '%~dp0FWArmy.exe' -ArgumentList '--no-open' -WindowStyle Hidden"
  echo FWArmy started headless. No browser, log: data\server.log
  echo Admin: http://127.0.0.1:8787/ - if busy see data\instance.json
  echo Console view: fwarmy-console.bat
) else (
  node ctl.mjs start --no-open
)
endlocal
