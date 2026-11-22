#!/bin/sh
# 把预编译二进制与 LuCI 文件打成 ipk。
#   用法: package-ipk.sh <arch> <bindir> <version> <outdir>
set -eu

ARCH="$1"
BINDIR="$2"
VERSION="$3"
OUTDIR="$4"

HERE=$(cd "$(dirname "$0")/.." && pwd)
PKG=deskgw
PKGREL=$(sed -n 's/^PKG_RELEASE:=//p' "$HERE/openwrt/Makefile" | head -1)
[ -n "${PKGREL:-}" ] || PKGREL=1
PKGVER="${VERSION}-${PKGREL}"

mkdir -p "$OUTDIR"
OUTDIR=$(cd "$OUTDIR" && pwd)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/data"
CTRL="$STAGE/control"

mkdir -p "$ROOT"
cp -a "$HERE/openwrt/files/." "$ROOT/"
mkdir -p "$ROOT/www/luci-static/resources/view/deskgw"
cp "$HERE/openwrt/htdocs/luci-static/resources/view/deskgw/overview.js" \
	"$ROOT/www/luci-static/resources/view/deskgw/overview.js"

mkdir -p "$ROOT/usr/bin"
cp "$BINDIR/deskgw" "$ROOT/usr/bin/deskgw"
[ -x "$ROOT/usr/bin/deskgw" ] || {
	echo "error: $BINDIR/deskgw 不存在或不可执行" >&2
	exit 1
}

find "$ROOT" -type d -exec chmod 0755 {} +
find "$ROOT" -type f -exec chmod 0644 {} +
chmod 0755 "$ROOT/usr/bin/deskgw"
for f in "$ROOT"/etc/init.d/* "$ROOT"/usr/libexec/deskgw/* "$ROOT"/etc/uci-defaults/*; do
	[ -f "$f" ] && chmod 0755 "$f"
done

SIZE=$(du -sk "$ROOT" | awk '{print $1}')
mkdir -p "$CTRL"
cat > "$CTRL/control" <<EOF
Package: $PKG
Version: $PKGVER
Depends: luci-base
Provides:
Source: https://github.com/mylucien/deskgw
SourceName: $PKG
License: MIT
Section: luci
Architecture: $ARCH
Installed-Size: $SIZE
Maintainer: mylucien
Description: OpenWrt Web 远程桌面网关
 单一 Go 静态二进制，提供 HTTPS 管理界面、用户与主机授权、审计日志。
EOF
echo "2.0" > "$STAGE/debian-binary"

( cd "$CTRL" && tar -czf "$STAGE/control.tar.gz" --owner=0 --group=0 --numeric-owner ./control )
( cd "$ROOT" && tar -czf "$STAGE/data.tar.gz" --owner=0 --group=0 --numeric-owner ./ )

IPK="$OUTDIR/${PKG}_${PKGVER}_${ARCH}.ipk"
rm -f "$IPK"
( cd "$STAGE" && ar -rc "$IPK" debian-binary control.tar.gz data.tar.gz )
echo "built $IPK ($(du -h "$IPK" | awk '{print $1}'))"
