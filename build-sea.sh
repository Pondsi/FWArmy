#!/usr/bin/env sh
# 在 macOS / Linux 上构建单文件 FWArmy（必须在目标系统上运行；SEA 不能跨平台注入）。
set -eu
cd "$(dirname "$0")"
node build-sea.mjs "$@"
