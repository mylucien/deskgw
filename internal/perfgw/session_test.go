package perfgw

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// replyNoise 造一条被控端的握手回答：`{2: noise}`。
func replyNoise(msg []byte) []byte {
	var w cbWriter
	w.mapN(1)
	w.uint(2)
	w.bytes(msg)
	return w.b
}

// replyVerdict 造一条只带决定的握手回答：`{3: 密封的决定}`。
func replyVerdict(sealed []byte) []byte {
	var w cbWriter
	w.mapN(1)
	w.uint(3)
	w.bytes(sealed)
	return w.b
}

// TestSessionHeader 锁住 9 字节会话头：会话号 u64 小端、通道号一个字节。
func TestSessionHeader(t *testing.T) {
	h := sessionHeader(0x0102030405060708, laneVideo0)
	want := "080706050403020102"
	if got := hex.EncodeToString(h); got != want {
		t.Fatalf("会话头不对\n得到 %s\n期望 %s", got, want)
	}
	id, lane, err := decodeSessionHeader(h)
	if err != nil || id != 0x0102030405060708 || lane != laneVideo0 {
		t.Fatalf("解回来不对: %d %d %v", id, lane, err)
	}

	// 通道号越界要拒绝：被控端升级后可能加新通道，上层据此丢弃这条流。
	bad := sessionHeader(1, laneCount)
	if _, _, err := decodeSessionHeader(bad); err == nil {
		t.Fatal("通道号越界应当报错")
	}
	// 会话号与通道号对不上，也要拒绝。
	if err := readSessionHeader(bytes.NewReader(sessionHeader(2, laneControl)), 1, laneControl); err == nil {
		t.Fatal("别的会话的流应当拒绝")
	}
}

// TestEncodeIncoming 与 airhand-proto 编出来的字节逐字节对齐。
func TestEncodeIncoming(t *testing.T) {
	got, err := encodeIncoming(0x1122334455667788,
		sessionPeer{name: "PC", ip: net.ParseIP("192.168.1.5")},
		&net.UDPAddr{IP: net.ParseIP("192.168.1.10"), Port: 51234},
		[]byte{0xaa, 0xbb, 0xcc})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vecIncoming {
		t.Fatalf("Incoming 不对\n得到 %x\n期望 %s", got, vecIncoming)
	}

	got, err = encodeIncoming(1,
		sessionPeer{name: "", ip: net.ParseIP("2001:db8::1")},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 4433},
		nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vecIncomingV6 {
		t.Fatalf("IPv6 的 Incoming 不对\n得到 %x\n期望 %s", got, vecIncomingV6)
	}
}

// TestSeal 用黄金向量锁住密封单元：密文 | 16 字节标签 | 8 字节计数。
func TestSeal(t *testing.T) {
	hash := hexBytes(t, vecIKHash)
	got := seal(deriveKey(hash, hexBytes(t, vecIKI2R), labelControl), 0, []byte{0xa0})
	if hex.EncodeToString(got) != vecIKConfirmSealed {
		t.Fatalf("Confirm 的密封单元不对\n得到 %x\n期望 %s", got, vecIKConfirmSealed)
	}

	// 往返一次，顺便确认计数写在末尾（8 字节小端）。
	sealed := seal(deriveKey(hash, hexBytes(t, vecIKR2I), labelControl), 7, []byte("hello"))
	if got := binary.LittleEndian.Uint64(sealed[len(sealed)-8:]); got != 7 {
		t.Fatalf("末尾的计数应当是 7，得到 %d", got)
	}
	plain, err := openSealed(deriveKey(hash, hexBytes(t, vecIKR2I), labelControl), sealed)
	if err != nil || string(plain) != "hello" {
		t.Fatalf("解回来不对: %q %v", plain, err)
	}
	// 换一把密钥（另一个方向）必须解不开。
	if _, err := openSealed(deriveKey(hash, hexBytes(t, vecIKI2R), labelControl), sealed); err == nil {
		t.Fatal("另一个方向的密钥不该解得开")
	}
}

// scriptedStream 冒充被控端开的控制流：先给会话头，再给预先准备好的几帧。
func scriptedStream(sessionID uint64, frames ...[]byte) func() (io.Reader, func(), error) {
	var buf bytes.Buffer
	buf.Write(sessionHeader(sessionID, laneControl))
	for _, f := range frames {
		_ = writeFrame(&buf, f)
	}
	return func() (io.Reader, func(), error) {
		return bytes.NewReader(buf.Bytes()), func() {}, nil
	}
}

// TestStartSessionIK 用真实的黄金向量走一遍 IK：被控端只回一条消息，里面既有
// 第 2 条握手消息，也有加密的决定。走完要发出逐字节正确的 Confirm。
func TestStartSessionIK(t *testing.T) {
	static := x25519Priv(t, vecCtrlStaticPriv)
	peerPub := x25519Pub(t, vecHostStaticPub)
	hs := newHandshake(static, peerPub, defaultIntro())
	hs.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))

	const sid = 0x1122334455667788
	var sig, ctrl bytes.Buffer
	// 被控端的回答：第 2 条消息 + 决定（密文由 Rust 侧用同一套密钥生成）。
	var reply []byte
	{
		var w cbWriter
		w.mapN(2)
		w.uint(2)
		w.bytes(hexBytes(t, vecIKMsg2))
		w.uint(3)
		w.bytes(hexBytes(t, vecIKVerdictSealed))
		reply = w.b
	}

	keys, err := startSession(sid, hs,
		sessionPeer{name: "PC", ip: net.ParseIP("192.168.1.5")},
		&net.UDPAddr{IP: net.ParseIP("192.168.1.10"), Port: 51234},
		sessionWire{
			signal:  func(p []byte) error { return writeFrame(&sig, p) },
			ctrlOut: &ctrl,
			accept:  scriptedStream(sid, reply),
		})
	if err != nil {
		t.Fatalf("握手失败: %v", err)
	}
	if keys.safety != vecIKSafety {
		t.Fatalf("安全码不对: %s", keys.safety)
	}

	// 信令流上应当正好一条 Incoming。init 是 HandshakeInit（外面还包着 CBOR），
	// 里面那条 Noise 消息要逐字节等于向量。
	probe := newHandshake(static, peerPub, defaultIntro())
	probe.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))
	init, err := probe.start()
	if err != nil {
		t.Fatal(err)
	}
	wantIncoming, err := encodeIncoming(sid,
		sessionPeer{name: "PC", ip: net.ParseIP("192.168.1.5")},
		&net.UDPAddr{IP: net.ParseIP("192.168.1.10"), Port: 51234}, init)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig.Bytes(), appendFrame(wantIncoming)) {
		t.Fatalf("Incoming 不对\n得到 %x\n期望 %x", sig.Bytes(), appendFrame(wantIncoming))
	}
	// 里面的那条 Noise 消息就是向量里的第 1 条。
	if !bytes.Contains(init, hexBytes(t, vecIKMsg1)) {
		t.Fatalf("HandshakeInit 里的消息不对: %x", init)
	}

	// 控制流上：9 字节会话头 + 逐字节正确的 Confirm。
	want := append(append([]byte{}, sessionHeader(sid, laneControl)...), appendFrame(hexBytes(t, vecIKConfirmSealed))...)
	if !bytes.Equal(ctrl.Bytes(), want) {
		t.Fatalf("控制流不对\n得到 %x\n期望 %x", ctrl.Bytes(), want)
	}
}

// TestStartSessionXX 第一次连接（还没有被控端公钥）走 XX：第 1 条在 Incoming 里，
// 第 3 条要逐字节对上，决定之后再回。
func TestStartSessionXX(t *testing.T) {
	static := x25519Priv(t, vecCtrlStaticPriv)
	hs := newHandshake(static, nil, defaultIntro())
	hs.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))

	// XX 的决定要等第 3 条之后才用密钥加密，所以先单独跑一遍同样的握手算出密钥，
	// 用它造一个真被控端形状的密封决定。（两次的临时密钥都固定，密钥一定相同。）
	sealed := func() []byte {
		probe := newHandshake(static, nil, defaultIntro())
		probe.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))
		if _, err := probe.start(); err != nil {
			t.Fatal(err)
		}
		if _, err := probe.reply(replyNoise(hexBytes(t, vecXXMsg2))); err != nil {
			t.Fatal(err)
		}
		hh := probe.noise.handshakeHash()
		i2r, r2i, err := probe.noise.finish()
		if err != nil {
			t.Fatal(err)
		}
		return seal(deriveSessionKeys(hh, i2r, r2i).control[1], 0, []byte{0x81, 0x01})
	}()

	const sid = 7
	var sig, ctrl bytes.Buffer
	keys, err := startSession(sid, hs,
		sessionPeer{name: "PC", ip: net.ParseIP("192.168.1.5")},
		&net.UDPAddr{IP: net.ParseIP("192.168.1.10"), Port: 51234},
		sessionWire{
			signal:  func(p []byte) error { return writeFrame(&sig, p) },
			ctrlOut: &ctrl,
			accept:  scriptedStream(sid, replyNoise(hexBytes(t, vecXXMsg2)), replyVerdict(sealed)),
		})
	if err != nil {
		t.Fatalf("握手失败: %v", err)
	}
	if keys.safety != vecXXSafety {
		t.Fatalf("安全码不对: %s", keys.safety)
	}

	// 控制流：会话头 + HandshakeFinish（第 3 条）+ Confirm。
	finish := ctrl.Bytes()[sessionHeaderLen:]
	body, err := readFrame(bytes.NewReader(finish), maxControlMsg)
	if err != nil {
		t.Fatalf("读 HandshakeFinish: %v", err)
	}
	var w cbWriter
	w.array(1)
	w.bytes(hexBytes(t, vecXXMsg3))
	if !bytes.Equal(body, w.b) {
		t.Fatalf("第 3 条消息不对\n得到 %x\n期望 %x", body, w.b)
	}
	rest := finish[4+len(body):]
	confirm, err := readFrame(bytes.NewReader(rest), maxControlMsg)
	if err != nil {
		t.Fatalf("读 Confirm: %v", err)
	}
	wantConfirm := seal(keys.control[0], 0, confirmMessage())
	if !bytes.Equal(confirm, wantConfirm) {
		t.Fatalf("Confirm 不对\n得到 %x\n期望 %x", confirm, wantConfirm)
	}
}

// TestIdentity 控制端密钥要能生成、重读，公钥是 64 位小写十六进制。
func TestIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perf_identity")
	key, err := loadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("生成: %v", err)
	}
	pub := identityPublic(key)
	if len(pub) != 64 {
		t.Fatalf("公钥应当是 64 位十六进制，得到 %q", pub)
	}
	if _, err := hex.DecodeString(pub); err != nil {
		t.Fatalf("公钥不是十六进制: %v", err)
	}
	// 权限 0600：被控端的信任根，别的用户不能读。Windows 上 os.WriteFile 的
	// 权限参数不生效，只在类 Unix 上检查。
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != identityFileMode {
			t.Fatalf("权限应当是 %o，得到 %o", identityFileMode, mode)
		}
	}
	again, err := loadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("重读: %v", err)
	}
	if identityPublic(again) != pub {
		t.Fatal("重读出来的不是同一把密钥")
	}

	// 坏文件要报错而不是悄悄换一把新的：换了就等于所有被控端都连不上，
	// 报错至少能让管理员去翻备份。
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("not hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateIdentity(bad); err == nil {
		t.Fatal("坏密钥文件应当报错")
	}
}

// appendFrame 给一段负载加上长度前缀，方便直接跟流上的字节比。
func appendFrame(payload []byte) []byte {
	var buf bytes.Buffer
	_ = writeFrame(&buf, payload)
	return buf.Bytes()
}
