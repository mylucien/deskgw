#!/bin/sh
# 输出指定证书的 SHA-256 指纹（小写，无冒号）。默认取 deskgw 的 HTTPS 证书；
# 传入 perf_cert 路径时输出性能模式的 QUIC 证书指纹（填被控端的 server_fp）。
# 用法: cert-fingerprint.sh [cert.pem]
set -u

CERT="${1:-}"
if [ -z "$CERT" ]; then
	CERT=$(uci -q get deskgw.main.cert 2>/dev/null || true)
fi
[ -n "$CERT" ] || CERT=/etc/deskgw/server.crt

if [ ! -s "$CERT" ]; then
	echo "证书不存在: $CERT" >&2
	exit 1
fi

if command -v openssl >/dev/null 2>&1; then
	openssl x509 -in "$CERT" -noout -fingerprint -sha256 2>/dev/null |
		sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z'
	exit $?
fi

# 无 openssl 时直接用 busybox 工具解析 PEM 正文。
BODY=$(awk '/BEGIN CERTIFICATE/{f=1;next} /END CERTIFICATE/{f=0} f' "$CERT" | tr -d '\r\n')
[ -n "$BODY" ] || { echo "无法解析证书正文" >&2; exit 1; }
TMP=$(mktemp)
if ! printf '%s' "$BODY" | base64 -d > "$TMP" 2>/dev/null || [ ! -s "$TMP" ]; then
	rm -f "$TMP"
	echo "无法解码证书正文" >&2
	exit 1
fi
FP=$(sha256sum "$TMP" | awk '{print $1}')
rm -f "$TMP"
case "$FP" in ''|*[^0-9a-fA-F]*) echo "无法计算证书指纹" >&2; exit 1 ;; esac
[ ${#FP} -eq 64 ] || { echo "指纹长度异常: $FP" >&2; exit 1; }
printf '%s\n' "$FP" | tr 'A-Z' 'a-z'
