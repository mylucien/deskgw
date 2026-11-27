#!/bin/sh
# 按 deskgw 的 UCI 配置设置性能模式所需的 UDP 缓冲区，并持久化到 /etc/sysctl.conf。
# 由 /etc/init.d/deskgw 在启动服务时调用，不直接暴露给 LuCI。
# 参数: $1 为缓冲大小（MiB），0 或空表示关闭优化并移除持久化配置。
set -u

SYSCTL_CONF=/etc/sysctl.conf
MARK_BEGIN='# deskgw perf UDP buffer (managed)'
MARK_END='# deskgw perf UDP buffer (end)'
MB="${1:-0}"

remove_managed() {
	[ -f "$SYSCTL_CONF" ] || return 0
	awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
		$0 == b { skip = 1; next }
		$0 == e { skip = 0; next }
		!skip { print }
	' "$SYSCTL_CONF" > "${SYSCTL_CONF}.deskgw.tmp" || return 1
	mv "${SYSCTL_CONF}.deskgw.tmp" "$SYSCTL_CONF"
}

case "$MB" in
	0|'')
		remove_managed
		exit 0
		;;
	*[!0-9]*)
		echo "无效的 UDP 缓冲大小: $MB" >&2
		exit 1
		;;
esac

[ "$MB" -gt 0 ] || { echo "UDP 缓冲大小必须大于 0" >&2; exit 1; }
BYTES=$((MB * 1048576))

if ! sysctl -w net.core.rmem_max="$BYTES" net.core.wmem_max="$BYTES" >/dev/null 2>&1; then
	echo "写入 UDP 缓冲参数失败（需要 root 权限？）" >&2
	exit 1
fi

remove_managed || exit 1
{
	echo "$MARK_BEGIN"
	echo "net.core.rmem_max=$BYTES"
	echo "net.core.wmem_max=$BYTES"
	echo "$MARK_END"
} >> "$SYSCTL_CONF"
