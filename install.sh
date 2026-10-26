#!/bin/sh
# FWArmy 无证书安装器（macOS / Linux）
#
#   curl -fsSL https://github.com/Pondsi/FWArmy/releases/download/v0.5.0/install.sh | sh
#
# 做四件事：下载本平台单文件、校验 SHA256、装到用户目录、生成可双击入口。
# 不请求管理员权限，不启动服务，不覆盖已有的 data/（凭据/统计/日志）。
#
# 可用环境变量：
#   FWARMY_VERSION  指定版本（默认 0.5.0）
#   FWARMY_HOME     指定安装目录
#   FWARMY_BASE     指定下载源（默认 GitHub Release；本地测试可传目录）
set -eu

VERSION="${FWARMY_VERSION:-0.5.0}"
REPO="${FWARMY_REPO:-Pondsi/FWArmy}"
BASE="${FWARMY_BASE:-https://github.com/$REPO/releases/download/v$VERSION}"

fail() { printf 'FWArmy 安装失败：%s\n' "$*" >&2; exit 1; }

OS=$(uname -s 2>/dev/null || echo unknown)
ARCH=$(uname -m 2>/dev/null || echo unknown)
case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64) PLATFORM=macos-arm64 ;;
      x86_64) PLATFORM=macos-x64 ;;
      *) fail "不支持的 macOS 架构：$ARCH（目前提供 arm64 / x86_64）" ;;
    esac
    INSTALL_DIR="${FWARMY_HOME:-$HOME/Applications/FWArmy}"
    ;;
  Linux)
    case "$ARCH" in
      x86_64|amd64) PLATFORM=linux-x64 ;;
      *) fail "不支持的 Linux 架构：$ARCH（目前提供 x86_64）" ;;
    esac
    INSTALL_DIR="${FWARMY_HOME:-$HOME/.local/share/fwarmy}"
    ;;
  *)
    fail "只支持 macOS / Linux；Windows 请用 install.ps1"
    ;;
esac

ASSET="FWArmy-$VERSION-$PLATFORM.tar.gz"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/fwarmy-install.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fetch() {
  name=$1
  dest=$2
  case "$BASE" in
    http://*|https://*|file://*)
      command -v curl >/dev/null 2>&1 || fail "需要 curl"
      curl -fsSL "$BASE/$name" -o "$dest" || fail "下载失败：$BASE/$name"
      ;;
    *)
      [ -f "$BASE/$name" ] || fail "找不到本地文件：$BASE/$name"
      cp "$BASE/$name" "$dest"
      ;;
  esac
}

printf '下载 %s ...\n' "$ASSET"
fetch "SHA256SUMS" "$TMP/SHA256SUMS"
fetch "$ASSET" "$TMP/$ASSET"

WANT=$(awk -v a="$ASSET" '$2 == a { print $1; exit }' "$TMP/SHA256SUMS")
[ -n "$WANT" ] || fail "SHA256SUMS 里没有 $ASSET"
if command -v sha256sum >/dev/null 2>&1; then
  GOT=$(sha256sum "$TMP/$ASSET" | awk '{ print $1 }')
else
  GOT=$(shasum -a 256 "$TMP/$ASSET" | awk '{ print $1 }')
fi
[ "$GOT" = "$WANT" ] || fail "SHA256 校验失败（期望 $WANT，实际 $GOT）"

tar -xzf "$TMP/$ASSET" -C "$TMP" || fail "解压失败"
SRC=''
for d in "$TMP"/FWArmy-*/; do
  if [ -d "$d" ]; then SRC="$d"; break; fi
done
[ -n "$SRC" ] || fail "压缩包里没有 FWArmy-* 目录"

mkdir -p "$INSTALL_DIR"
for f in "$SRC"/*; do
  [ -e "$f" ] || continue
  name=$(basename "$f")
  [ "$name" = "data" ] && continue
  rm -rf "$INSTALL_DIR/$name"
  cp -R "$f" "$INSTALL_DIR/$name"
done

chmod +x "$INSTALL_DIR/FWArmy" 2>/dev/null || true
for f in "$INSTALL_DIR"/*.sh "$INSTALL_DIR"/*.command; do
  [ -e "$f" ] && chmod +x "$f" 2>/dev/null || true
done

if [ "$OS" = "Darwin" ]; then
  # 用 curl 安装本来就没有 quarantine；这里只处理用户先浏览器下载再运行安装器的情况。
  xattr -dr com.apple.quarantine "$INSTALL_DIR" 2>/dev/null || true
else
  mkdir -p "$HOME/.local/bin"
  ln -sf "$INSTALL_DIR/FWArmy" "$HOME/.local/bin/fwarmy"
  mkdir -p "$HOME/.local/share/applications"
  cat > "$HOME/.local/share/applications/fwarmy.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=FWArmy
Comment=FWArmy relay server
Exec="$INSTALL_DIR/FWArmy" --open
Icon="$INSTALL_DIR/assets/logo.svg"
Terminal=false
Categories=Network;Utility;
StartupNotify=false
EOF
  chmod 644 "$HOME/.local/share/applications/fwarmy.desktop" 2>/dev/null || true
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
fi

"$INSTALL_DIR/FWArmy" --version >/dev/null 2>&1 || fail "装好的程序无法执行（可能被系统策略拦截）"

printf '\nFWArmy %s 已安装到：%s\n' "$VERSION" "$INSTALL_DIR"
if [ "$OS" = "Darwin" ]; then
  printf '启动：双击 %s/FWArmy.command（或在终端运行 %s/FWArmy --open）\n' "$INSTALL_DIR" "$INSTALL_DIR"
  printf '如果是从浏览器下载后手动运行安装器，仍可能被 Gatekeeper 拦；本安装器已尝试去除 quarantine。\n'
else
  printf '启动：应用菜单搜索 FWArmy，或运行 %s/.local/bin/fwarmy --open\n' "$HOME"
fi
printf '数据目录：%s/data（升级不会删除其中凭据/统计/日志）\n' "$INSTALL_DIR"
printf '卸载：删除安装目录和桌面项即可；不会留下系统服务。\n'
