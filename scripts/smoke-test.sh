#!/bin/sh
# 解包 ipk 并真实启动 deskgw，验证静态链接、API 与证书指纹。
#   用法: smoke-test.sh <ipk>
set -eu

IPK=$1
case "$IPK" in
	/*) ;;
	*) IPK=$(cd "$(dirname "$IPK")" && pwd)/$(basename "$IPK") ;;
esac
WORK=$(mktemp -d)
trap 'kill ${PID:-} 2>/dev/null || true; rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "   ok"; }

echo "== 1. ipk 结构 =="
mkdir -p "$WORK/pkg" && cd "$WORK/pkg"
( cd "$WORK" && ar x "$IPK" )
[ -f "$WORK/debian-binary" ] || fail "缺少 debian-binary"
[ -f "$WORK/control.tar.gz" ] || fail "缺少 control.tar.gz"
[ -f "$WORK/data.tar.gz" ] || fail "缺少 data.tar.gz"
tar xzf "$WORK/control.tar.gz"
tar xzf "$WORK/data.tar.gz"
arch=$(sed -n 's/^Architecture: //p' control)
ver=$(sed -n 's/^Version: //p' control)
echo "   arch=$arch version=$ver"
[ -n "$arch" ] && [ -n "$ver" ] || fail "control 字段缺失"

echo "== 2. 文件清单 =="
for f in usr/bin/deskgw etc/config/deskgw etc/init.d/deskgw \
	etc/uci-defaults/95-deskgw usr/libexec/deskgw/cert-fingerprint.sh \
	www/luci-static/resources/view/deskgw/overview.js; do
	[ -f "$f" ] || fail "缺少 $f"
done
[ -x usr/bin/deskgw ] || fail "deskgw 不可执行"
ok

echo "== 3. 静态链接 =="
if readelf -l usr/bin/deskgw 2>/dev/null | grep -q INTERP; then
	fail "deskgw 是动态链接"
fi
ok

echo "== 4. 启动服务 =="
DATA="$WORK/data"
mkdir -p "$DATA"
export DESKGW_LISTEN=127.0.0.1:18443
export DESKGW_DATA_DIR="$DATA"
export DESKGW_DB="$DATA/data.db"
export DESKGW_CERT="$DATA/server.crt"
export DESKGW_KEY="$DATA/server.key"
export DESKGW_COOKIE_SECURE=false
export DESKGW_INITIAL_PASSWORD=smoke-test-pw
"$WORK/pkg/usr/bin/deskgw" > "$WORK/server.log" 2>&1 &
PID=$!

i=0
until curl -ksS -m 2 -c "$WORK/jar" https://127.0.0.1:18443/api/health > "$WORK/health.json" 2>/dev/null; do
	i=$((i + 1)); [ "$i" -lt 40 ] || { cat "$WORK/server.log" >&2; fail "服务未能在 20 秒内启动"; }
	sleep 0.5
done
grep -q '"status":"ok"' "$WORK/health.json" || fail "health 返回异常"
ok

echo "== 5. 证书指纹 =="
FP_LOG=$(sed -n 's/.*指纹: \([0-9a-f]*\).*/\1/p' "$WORK/server.log" | head -1)
FP_SH=$(sh "$WORK/pkg/usr/libexec/deskgw/cert-fingerprint.sh" "$DESKGW_CERT")
echo "   log=$FP_LOG"
echo "   sh =$FP_SH"
[ -n "$FP_LOG" ] && [ "$FP_LOG" = "$FP_SH" ] || fail "指纹脚本与日志不一致"
ok

echo "== 6. 认证与授权 =="
CSRF=$(awk '$6=="deskgw_csrf" {print $7}' "$WORK/jar")
[ -n "$CSRF" ] || fail "未收到 CSRF Cookie"
code=$(curl -ksS -o /dev/null -w '%{http_code}' -X POST https://127.0.0.1:18443/api/login \
	-H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
	-d '{"username":"admin","password":"wrong"}')
[ "$code" = "401" ] || fail "错误密码应返回 401，实际 $code"
code=$(curl -ksS -o "$WORK/login.json" -w '%{http_code}' -b "$WORK/jar" -c "$WORK/jar" \
	-X POST https://127.0.0.1:18443/api/login \
	-H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
	-d '{"username":"admin","password":"smoke-test-pw"}')
[ "$code" = "200" ] || { cat "$WORK/login.json" >&2; fail "登录失败: $code"; }
code=$(curl -ksS -o /dev/null -w '%{http_code}' -b "$WORK/jar" https://127.0.0.1:18443/api/me)
[ "$code" = "200" ] || fail "登录态校验失败: $code"
code=$(curl -ksS -o /dev/null -w '%{http_code}' \
	-X POST https://127.0.0.1:18443/api/admin/hosts \
	-H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -d '{}')
[ "$code" = "401" ] || fail "无登录态访问 admin 接口应返回 401，实际 $code"
ok

echo "== 7. 主机与用户 CRUD =="
api() { curl -ksS -b "$WORK/jar" -H 'Content-Type: application/json' \
	-H "X-CSRF-Token: $CSRF" "$@"; }
r=$(api -X POST https://127.0.0.1:18443/api/admin/hosts -d \
	'{"id":1001,"name":"smoke-host","address":"192.168.1.10","rdp_port":3389,"smb_port":445,"enabled":true,"modes":"rdp"}')
echo "$r" | grep -q '"ok":true' || { echo "$r" >&2; fail "创建主机失败"; }
r=$(api https://127.0.0.1:18443/api/hosts)
echo "$r" | grep -q 'smoke-host' || fail "主机列表未包含新增主机"
r=$(api -X POST https://127.0.0.1:18443/api/admin/users -d \
	'{"username":"smoke-user","password":"smoke-pw-123","role":"user","enabled":true,"max_sessions":1,"host_ids":[1001]}')
echo "$r" | grep -q '"ok":true' || { echo "$r" >&2; fail "创建用户失败"; }
r=$(api https://127.0.0.1:18443/api/admin/audit)
echo "$r" | grep -q 'host.create' || fail "审计日志缺少 host.create"
r=$(api -X DELETE https://127.0.0.1:18443/api/admin/users/2)
echo "$r" | grep -q '"ok":true' || fail "删除用户失败"
r=$(api -X DELETE https://127.0.0.1:18443/api/admin/hosts/1001)
echo "$r" | grep -q '"ok":true' || fail "删除主机失败"
ok

echo "== 8. 静态页面 =="
body=$(curl -ksS -w '\n%{http_code}' https://127.0.0.1:18443/)
echo "$body" | tail -1 | grep -q '^200$' || { echo "$body" | head -c 500 >&2; fail "首页 HTTP 状态异常"; }
echo "$body" | grep -q '<div id="app"' || { echo "$body" | head -c 500 >&2; fail "首页不是前端 HTML"; }
ok

echo "== 9. RDP 隧道（票据 / WS / 地址隔离）=="
command -v python3 >/dev/null || fail "缺少 python3"
TUNNEL_TEST="$(cd "$(dirname "$0")" && pwd)/rdp-tunnel-test.py"
python3 "$TUNNEL_TEST" https://127.0.0.1:18443 smoke-test-pw || fail "RDP 隧道测试失败"
ok

echo "全部通过"
