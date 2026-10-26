#!/bin/sh
# macOS 双击入口：后台启动 FWArmy 并打开管理页；数据在程序旁边的 data/。
cd "$(dirname "$0")" || exit 1
if [ ! -x ./FWArmy ]; then
  echo "FWArmy 不存在或没有执行权限：$(pwd)/FWArmy" >&2
  echo "如果在浏览器下载后被 Gatekeeper 拦，请运行：xattr -dr com.apple.quarantine \"$(pwd)\"" >&2
  exit 1
fi
nohup ./FWArmy --open >/dev/null 2>&1 &
echo "FWArmy 已启动，管理页会在浏览器打开。"
echo "停止：$(pwd)/FWArmy stop"
