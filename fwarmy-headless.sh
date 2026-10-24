#!/usr/bin/env sh
cd "$(dirname "$0")" || exit 1
if [ -x ./FWArmy ]; then
  nohup ./FWArmy --no-open >/dev/null 2>&1 &
  echo "FWArmy 已在后台启动（无界面）；日志 data/server.log"
  echo "管理页 http://127.0.0.1:8787/（若换端口见 data/instance.json）"
else
  node ctl.mjs start --no-open
fi
