#!/usr/bin/env sh
cd "$(dirname "$0")" || exit 1
if [ -x ./FWArmy ]; then
  nohup ./FWArmy "$@" >/dev/null 2>&1 &
  echo "FWArmy 已在后台启动；管理页 http://127.0.0.1:8787/（首次可能换端口，见 data/instance.json）"
else
  node ctl.mjs start --open "$@"
fi
