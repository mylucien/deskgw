#!/usr/bin/env python3
"""RDP 隧道端到端测试：假 RDP 服务 + 原生 WS 客户端 + RDCleanPath 报文。

验证：
  1. 无票据的 WS 握手被拒绝（401）
  2. 票据一次性（第二次使用同一票据被拒绝）
  3. 浏览器传入的 destination 被忽略，网关连接数据库配置的主机地址

用法: rdp-tunnel-test.py <base_url> <admin_password>
"""
import base64
import http.cookiejar
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip('/')
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else 'smoke-test-pw'


def fail(msg):
    print('FAIL:', msg, file=sys.stderr)
    sys.exit(1)


# ---- DER 编解码（与 Go 端 RDCleanPath 对齐） ------------------------------
def der_len(n):
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xff)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def tlv(tag, val):
    return bytes([tag]) + der_len(len(val)) + val


def ctx(n, val):
    return tlv(0xa0 + n, val)


def der_int(v):
    if v == 0:
        return tlv(0x02, b'\x00')
    out = []
    while v:
        out.insert(0, v & 0xff)
        v >>= 8
    if out[0] & 0x80:
        out.insert(0, 0)
    return tlv(0x02, bytes(out))


def read_tlv(data, off=0):
    tag = data[off]
    first = data[off + 1]
    if first < 0x80:
        length, hdr = first, 2
    else:
        n = first & 0x7f
        length = int.from_bytes(data[off + 2:off + 2 + n], 'big')
        hdr = 2 + n
    start = off + hdr
    return tag, data[start:start + length], start + length


def build_request(destination, x224):
    body = ctx(0, der_int(3390)) + ctx(2, tlv(0x0c, destination.encode())) + ctx(6, tlv(0x04, x224))
    return tlv(0x30, body)


def response_server_addr(data):
    _, outer, _ = read_tlv(data)
    off = 0
    while off < len(outer):
        tag, val, off = read_tlv(outer, off)
        if (tag & 0x1f) == 9:
            _, s, _ = read_tlv(val)
            return s.decode()
    return None


# ---- TLS 自签证书 ---------------------------------------------------------
def make_cert(tmpdir):
    cert = os.path.join(tmpdir, 'rdp.crt')
    key = os.path.join(tmpdir, 'rdp.key')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', key, '-out', cert, '-days', '1',
                    '-subj', '/CN=deskgw-fake-rdp'], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)
    return cert, key


# ---- 假 RDP 服务端 --------------------------------------------------------
def fake_rdp(listener, sslctx, ready, stop):
    conn, _ = listener.accept()
    conn.settimeout(10)
    try:
        conn.recv(4096)                     # X.224 Connection Request
        x224_cc = bytes([3, 0, 0, 11]) + b'\xe0\x00\x00\x00\x00\x00\x00\x00'
        conn.sendall(x224_cc)              # X.224 Connection Confirm (TPKT)
        tls = sslctx.wrap_socket(conn, server_side=True)   # TLS 握手
        ready.set()
        stop.wait(15)
        tls.close()
    except Exception as e:
        print('fake-rdp error:', e, file=sys.stderr)


# ---- HTTPS 请求（带 Cookie / CSRF） --------------------------------------
ctx_ssl = ssl._create_unverified_context()
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx_ssl),
    urllib.request.HTTPCookieProcessor(jar),
)


def csrf():
    for c in jar:
        if c.name == 'deskgw_csrf':
            return c.value
    return ''


def api(path, method='GET', body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {'Content-Type': 'application/json', 'X-CSRF-Token': csrf()}
    req = urllib.request.Request(BASE + '/api' + path, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def session_cookie():
    for c in jar:
        if c.name == 'deskgw_session':
            return c.value
    return ''


# ---- 原生 WebSocket 客户端 ------------------------------------------------
def ws_connect(path, cookie, payload=None):
    hostport = BASE.split('://', 1)[1]
    key = base64.b64encode(os.urandom(16)).decode()
    s = socket.create_connection(('127.0.0.1', int(hostport.rsplit(':', 1)[1])), timeout=10)
    req = (f'GET {path} HTTP/1.1\r\nHost: {hostport}\r\n'
           f'Upgrade: websocket\r\nConnection: Upgrade\r\n'
           f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
           f'Cookie: deskgw_session={cookie}\r\n\r\n')
    s.sendall(req.encode())
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    header, _, rest = buf.partition(b'\r\n\r\n')
    status = int(header.split(b' ')[1])
    if status != 101 or payload is None:
        s.close()
        return status, None, s
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        frame = bytes([0x82, 0x80 | n])
    elif n < 65536:
        frame = bytes([0x82, 0x80 | 126]) + struct.pack('!H', n)
    else:
        frame = bytes([0x82, 0x80 | 127]) + struct.pack('!Q', n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    s.sendall(frame + mask + masked)
    # 读取一帧响应
    def exact(sock, count):
        out = b''
        while len(out) < count:
            c = sock.recv(count - len(out))
            if not c:
                break
            out += c
        return out
    h = exact(s, 2)
    if len(h) < 2:
        s.close()
        return status, None, s
    ln = h[1] & 0x7f
    if ln == 126:
        ln = struct.unpack('!H', exact(s, 2))[0]
    elif ln == 127:
        ln = struct.unpack('!Q', exact(s, 8))[0]
    return status, exact(s, ln), s


# ---- 主流程 ---------------------------------------------------------------
with tempfile.TemporaryDirectory() as tmp:
    # 先 GET 一次以取得 CSRF Cookie
    try:
        opener.open(BASE + '/', timeout=10).read()
    except Exception:
        pass
    # 登录取会话
    st, _ = api('/login', 'POST', {'username': 'admin', 'password': PASSWORD})
    if st != 200 or not session_cookie():
        fail('管理员登录失败')

    # 测试 1：无票据的 WS 握手应被拒绝
    st, _, s = ws_connect('/ws/rdp', session_cookie())
    s.close()
    if st == 101:
        fail('无票据 WS 不应升级成功')
    print('   ok  无票据 WS 被拒绝 (%d)' % st)

    cert, key = make_cert(tmp)
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sslctx.load_cert_chain(cert, key)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    rdp_port = listener.getsockname()[1]
    ready, stop = threading.Event(), threading.Event()
    t = threading.Thread(target=fake_rdp, args=(listener, sslctx, ready, stop), daemon=True)
    t.start()

    # 创建配置为数据库地址（127.0.0.1:假端口）的主机
    host_id = 91001
    st, r = api('/admin/hosts', 'POST', {
        'id': host_id, 'name': 'tunnel-test', 'address': '127.0.0.1',
        'rdp_port': rdp_port, 'smb_port': 445, 'enabled': True, 'modes': 'rdp'})
    if st != 200 or not r.get('ok'):
        fail('创建测试主机失败: %s' % r)

    # 签发票据
    st, r = api('/sessions', 'POST', {'host_id': host_id})
    if st != 200 or not r.get('ok'):
        fail('签发票据失败: %s' % r)
    ticket = r['data']['ticket']
    ws_path = r['data']['ws_path']

    # destination 故意指向伪造地址；网关必须忽略并连接数据库地址
    request = build_request('evil.example.invalid:3389', b'\x03\x00\x00\x0btest-x224')
    st, resp, s = ws_connect(ws_path, session_cookie(), request)
    if st != 101 or resp is None:
        fail('带票据 WS 握手失败: status=%d resp=%r' % (st, resp))
    if not ready.wait(10):
        fail('假 RDP 服务未被连接——网关可能连错地址')
    addr = response_server_addr(resp)
    expected = '127.0.0.1:%d' % rdp_port
    if addr != expected:
        fail('server_addr 不符: 期望 %s，实际 %s' % (expected, addr))
    print('   ok  浏览器 destination 被忽略，网关连接数据库地址 %s' % addr)
    stop.set()
    s.close()

    # 测试 2：票据一次性——再次使用应被拒绝
    st, _, s2 = ws_connect(ws_path, session_cookie(), request)
    s2.close()
    if st == 101:
        fail('票据应一次性，第二次使用却升级成功')
    print('   ok  票据一次性 (%d)' % st)

    # 清理
    api('/admin/hosts/%d' % host_id, 'DELETE')
    listener.close()
    print('RDP 隧道测试全部通过')
