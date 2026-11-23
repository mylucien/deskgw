#!/usr/bin/env python3
"""RDP 隧道端到端测试：假 RDP 服务 + 原生 WS 客户端。

网关只做 WS↔TCP 字节转发，X.224 与 TLS 都由浏览器侧完成。因此这里用
「原始帧 + 自己实现 TLS over WS」来验证网关确实没有参与协议：

  1. 无票据的 WS 握手被拒绝（401）
  2. X.224 字节原样透传，网关不追加/不包裹任何报文
  3. 浏览器可经隧道与目标机完成 TLS 握手（网关看不到明文）
  4. 浏览器传入的 destination 被忽略，网关只连接数据库里的地址
  5. 票据一次性；断开后会话记录被收尾

用法: rdp-tunnel-test.py <base_url> <admin_password>
"""
import base64
import hashlib
import http.cookiejar
import ipaddress
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip('/')
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else 'smoke-test-pw'

# 故意用非标准长度，若网关做了协议解析就不可能原样透传
X224_CR = bytes([3, 0, 0, 19]) + bytes(range(1, 16))
X224_CC = bytes([3, 0, 0, 11]) + bytes([6, 0xd0, 0, 0, 0x12, 0x34, 0])


def fail(msg):
    print('FAIL:', msg, file=sys.stderr)
    sys.exit(1)


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


# ---- 最小 WebSocket 客户端 ------------------------------------------------
def ws_open(path, cookie):
    hostport = BASE.split('://', 1)[1]
    key = base64.b64encode(os.urandom(16)).decode()
    raw = socket.create_connection(('127.0.0.1', int(hostport.rsplit(':', 1)[1])), timeout=15)
    s = ssl._create_unverified_context().wrap_socket(raw, server_hostname='127.0.0.1')
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
    if status != 101:
        print('   ws 握手状态 %d: %s' % (status, (rest or header)[:160].decode('utf-8', 'replace')))
        s.close()
        return status, None, b''
    return status, s, rest


def ws_send(s, data, opcode=0x2):
    mask = os.urandom(4)
    n = len(data)
    if n < 126:
        frame = bytes([0x80 | opcode, 0x80 | n])
    elif n < 65536:
        frame = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack('!H', n)
    else:
        frame = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack('!Q', n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    s.sendall(frame + mask + masked)


def exact(sock, count):
    out = b''
    while len(out) < count:
        c = sock.recv(count - len(out))
        if not c:
            raise IOError('连接在读到 %d/%d 字节时关闭' % (len(out), count))
        out += c
    return out


class WsReader:
    """把 WS 二进制帧还原成字节流；自动应答 ping、报告 close。"""

    def __init__(self, sock, leftover=b''):
        self.sock = sock
        self.buf = leftover

    def _frame(self):
        h = exact(self.sock, 2)
        opcode = h[0] & 0x0f
        ln = h[1] & 0x7f
        if ln == 126:
            ln = struct.unpack('!H', exact(self.sock, 2))[0]
        elif ln == 127:
            ln = struct.unpack('!Q', exact(self.sock, 8))[0]
        return opcode, exact(self.sock, ln) if ln else b''

    def read(self, n):
        while len(self.buf) < n:
            opcode, payload = self._frame()
            if opcode == 0x8:
                reason = payload[2:].decode('utf-8', 'replace') if len(payload) > 2 else ''
                raise IOError('网关关闭连接: %s' % (reason or '(无原因)'))
            if opcode == 0x9:
                ws_send(self.sock, payload, 0xA)
                continue
            if opcode in (0x1, 0x2, 0x0):
                self.buf += payload
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


class WsTls:
    """在 WS 二进制帧之上跑 TLS——正是浏览器 WASM 客户端的做法。"""

    def __init__(self, sock, reader, server_hostname):
        self.reader = reader
        self.inb, self.outb = ssl.MemoryBIO(), ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.obj = ctx.wrap_bio(self.inb, self.outb, server_hostname=server_hostname)
        self.sock = sock
        self.cert = None

    def _flush(self):
        data = self.outb.read()
        if data:
            ws_send(self.sock, data)

    def handshake(self):
        while True:
            try:
                self.obj.do_handshake()
                self._flush()
                break
            except ssl.SSLWantReadError:
                self._flush()
                self.inb.write(self.reader.read(4096))
        self.cert = self.obj.getpeercert(binary_form=True)

    def send(self, data):
        self.obj.write(data)
        self._flush()

    def recv(self, n):
        while True:
            try:
                return self.obj.read(n)
            except ssl.SSLWantReadError:
                self._flush()
                self.inb.write(self.reader.read(4096))


# ---- 假 RDP 服务端 --------------------------------------------------------
def local_private_ip():
    """本机在默认路由上使用的地址。

    host.Validate 拒绝回环地址（防止隧道指向网关自己），所以假 RDP 服务
    不能挂在 127.0.0.1 上；这里取运行器的私网 IPv4 并绑定到 0.0.0.0。
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(('8.8.8.8', 80))
        return probe.getsockname()[0]
    finally:
        probe.close()


def make_cert(tmpdir):
    cert = os.path.join(tmpdir, 'rdp.crt')
    key = os.path.join(tmpdir, 'rdp.key')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', key, '-out', cert, '-days', '1',
                    '-subj', '/CN=deskgw-fake-rdp'], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)
    return cert, key


def fingerprint(cert_path):
    der = subprocess.run(['openssl', 'x509', '-in', cert_path, '-outform', 'der'],
                         stdout=subprocess.PIPE, check=True).stdout
    return hashlib.sha256(der).hexdigest()


def fake_rdp(listener, sslctx, seen):
    """接受一次连接：校验 X.224 原文，再做 TLS 并回显。"""
    conn, _ = listener.accept()
    conn.settimeout(20)
    try:
        seen['x224'] = exact(conn, len(X224_CR))
        conn.sendall(X224_CC)
        tls = sslctx.wrap_socket(conn, server_side=True)
        seen['tls'] = tls.version()
        data = exact(tls, 4)
        tls.sendall(b'pong' + data)
        seen['payload'] = data
        seen['done'].set()
        time.sleep(0.3)
        tls.close()
    except Exception as e:                       # noqa: BLE001 - 测试脚本
        seen['error'] = repr(e)
        seen['done'].set()


# ---- 主流程 ---------------------------------------------------------------
with tempfile.TemporaryDirectory() as tmp:
    try:
        opener.open(BASE + '/', timeout=10).read()
    except Exception:
        pass
    st, _ = api('/login', 'POST', {'username': 'admin', 'password': PASSWORD})
    if st != 200 or not session_cookie():
        fail('管理员登录失败')

    # 测试 1：无票据的 WS 握手应被拒绝
    st, s, _ = ws_open('/ws/rdp', session_cookie())
    if s is not None:
        s.close()
    if st == 101:
        fail('无票据 WS 不应升级成功')
    print('   ok  无票据 WS 被拒绝 (%d)' % st)

    cert, key = make_cert(tmp)
    expect_fp = fingerprint(cert)
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sslctx.load_cert_chain(cert, key)
    rdp_ip = local_private_ip()
    if not ipaddress.ip_address(rdp_ip).is_private:
        fail('测试环境没有私网 IPv4 地址（当前 %s），无法创建主机' % rdp_ip)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', 0))
    listener.listen(1)
    rdp_port = listener.getsockname()[1]
    seen = {'done': threading.Event()}
    threading.Thread(target=fake_rdp, args=(listener, sslctx, seen), daemon=True).start()

    # 主机地址来自数据库，ID 由服务端分配
    st, r = api('/admin/hosts', 'POST', {
        'name': 'tunnel-test', 'address': rdp_ip,
        'rdp_port': rdp_port, 'smb_port': 445, 'enabled': True, 'modes': 'rdp'})
    if st != 200 or not r.get('ok'):
        fail('创建测试主机失败: %s' % r)
    host_id = r['data']['id']
    print('   ok  新建主机自动分配 ID = %s' % host_id)

    st, r = api('/sessions', 'POST', {'host_id': host_id})
    if st != 200 or not r.get('ok'):
        fail('签发票据失败: %s' % r)
    ws_path = r['data']['ws_path']
    session_id = r['data']['session_id']

    # 测试 2：字节原样透传。destination 故意指向伪造地址，网关必须忽略。
    st, s, rest = ws_open(ws_path + '&destination=evil.example.invalid%3A3389', session_cookie())
    if st != 101 or s is None:
        fail('带票据 WS 握手失败: status=%d' % st)
    rw = WsReader(s, rest)
    ws_send(s, X224_CR)
    got = rw.read(len(X224_CC))
    if got != X224_CC:
        fail('回程字节被改写: 期望 %r，实际 %r' % (X224_CC, got))
    if not seen['done'].wait(5):
        fail('假 RDP 服务未被连接——网关可能连错地址')
    if seen.get('error'):
        fail('假 RDP 服务异常: %s' % seen['error'])
    if seen.get('x224') != X224_CR:
        fail('去程字节被改写: 期望 %r，实际 %r' % (X224_CR, seen.get('x224')))
    print('   ok  双向字节原样透传，destination 被忽略（连到 %s:%d）' % (rdp_ip, rdp_port))

    # 测试 3：TLS 由两端完成，网关只转发记录
    tls = WsTls(s, rw, 'deskgw-fake-rdp')
    tls.handshake()
    fp = hashlib.sha256(tls.cert).hexdigest()
    if fp != expect_fp:
        fail('隧道内 TLS 证书指纹不符: 期望 %s，实际 %s' % (expect_fp, fp))
    print('   ok  经隧道完成 TLS 握手（%s，指纹 %s…）' % (seen.get('tls', '?'), fp[:16]))

    tls.send(b'ping')
    echo = tls.recv(16)
    if echo != b'pongping':
        fail('TLS 内数据回显不符: %r' % echo)
    print('   ok  TLS 应用数据往返正常')
    s.close()

    # 测试 4：票据一次性
    st, s2, _ = ws_open(ws_path, session_cookie())
    if s2 is not None:
        s2.close()
    if st == 101:
        fail('票据应一次性，第二次使用却升级成功')
    print('   ok  票据一次性 (%d)' % st)

    # 测试 5：断开后会话记录被收尾
    deadline = time.time() + 8
    state = None
    while time.time() < deadline:
        st, r = api('/admin/sessions')
        if st == 200:
            for row in (r.get('data') or {}).get('sessions') or []:
                if row.get('id') == session_id:
                    state = row.get('state')
            if state not in (None, 'pending', 'active'):
                break
        time.sleep(0.3)
    if state != 'closed':
        fail('断开后会话状态应为 closed，实际 %r' % state)
    print('   ok  会话已收尾 (state=%s)' % state)

    api('/admin/hosts/%d' % host_id, 'DELETE')
    listener.close()
    print('RDP 隧道测试全部通过')
