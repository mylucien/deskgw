package perfgw

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("向量不是十六进制: %v", err)
	}
	return b
}

func x25519Priv(t *testing.T, s string) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(hexBytes(t, s))
	if err != nil {
		t.Fatalf("私钥不合法: %v", err)
	}
	return k
}

func x25519Pub(t *testing.T, s string) *ecdh.PublicKey {
	t.Helper()
	k, err := ecdh.X25519().NewPublicKey(hexBytes(t, s))
	if err != nil {
		t.Fatalf("公钥不合法: %v", err)
	}
	return k
}

// 固定私钥必须能推出向量里的公钥，否则说明向量本身抄错了，后面的对比都没意义。
func TestVectorKeys(t *testing.T) {
	for _, c := range []struct{ name, priv, pub string }{
		{"控制端", vecCtrlStaticPriv, vecCtrlStaticPub},
		{"被控端", vecHostStaticPriv, vecHostStaticPub},
	} {
		got := hex.EncodeToString(x25519Priv(t, c.priv).PublicKey().Bytes())
		if got != c.pub {
			t.Fatalf("%s的公钥对不上: 得到 %s，期望 %s", c.name, got, c.pub)
		}
	}
}

// XX 是第一次连（Pattern::First）：三条消息，最后一条带被控端介绍。
func TestNoiseXXInitiator(t *testing.T) {
	if got := hex.EncodeToString(airhandPrologue(1)); got != vecXXPrologue {
		t.Fatalf("prologue 不对: 得到 %s，期望 %s", got, vecXXPrologue)
	}

	h := newNoiseXX(x25519Priv(t, vecCtrlStaticPriv), airhandPrologue(1))
	h.setEphemeral(x25519Priv(t, vecCtrlEphPriv))

	m1, err := h.writeMessage1(nil)
	if err != nil {
		t.Fatalf("第 1 条消息: %v", err)
	}
	if want := hexBytes(t, vecXXMsg1); !bytes.Equal(m1, want) {
		t.Fatalf("第 1 条消息不对\n得到 %x\n期望 %x", m1, want)
	}

	payload, err := h.readMessage2(hexBytes(t, vecXXMsg2))
	if err != nil {
		t.Fatalf("第 2 条消息: %v", err)
	}
	if len(payload) != 0 {
		t.Fatalf("第 2 条的负载应为空，得到 %x", payload)
	}
	if got := hex.EncodeToString(h.peerStatic()); got != vecHostStaticPub {
		t.Fatalf("学到被控端公钥不对: 得到 %s，期望 %s", got, vecHostStaticPub)
	}

	m3, err := h.writeMessage3(vecIntro)
	if err != nil {
		t.Fatalf("第 3 条消息: %v", err)
	}
	if want := hexBytes(t, vecXXMsg3); !bytes.Equal(m3, want) {
		t.Fatalf("第 3 条消息不对\n得到 %x\n期望 %x", m3, want)
	}

	hh := h.handshakeHash()
	if got := hex.EncodeToString(hh); got != vecXXHash {
		t.Fatalf("握手哈希不对: 得到 %s，期望 %s", got, vecXXHash)
	}
	if got := safetyCode(hh); got != vecXXSafety {
		t.Fatalf("安全码不对: 得到 %s，期望 %s", got, vecXXSafety)
	}

	i2r, r2i, err := h.finish()
	if err != nil {
		t.Fatalf("取密钥: %v", err)
	}
	if got := hex.EncodeToString(i2r); got != vecXXI2R {
		t.Fatalf("控制端→被控端的密钥不对: 得到 %s，期望 %s", got, vecXXI2R)
	}
	if got := hex.EncodeToString(r2i); got != vecXXR2I {
		t.Fatalf("被控端→控制端的密钥不对: 得到 %s，期望 %s", got, vecXXR2I)
	}
	// 取过一次就不能再取。
	if _, _, err := h.finish(); err == nil {
		t.Fatal("重复取密钥应当失败")
	}
}

// IK 是被控端公钥已知时用的（Pattern::Known）：两条消息，第一条就带介绍。
func TestNoiseIKInitiator(t *testing.T) {
	if got := hex.EncodeToString(airhandPrologue(0)); got != vecIKPrologue {
		t.Fatalf("prologue 不对: 得到 %s，期望 %s", got, vecIKPrologue)
	}

	h := newNoiseIK(x25519Priv(t, vecCtrlStaticPriv),
		x25519Pub(t, vecHostStaticPub), airhandPrologue(0))
	h.setEphemeral(x25519Priv(t, vecCtrlEphPriv))

	m1, err := h.writeMessage1(nil)
	if err != nil {
		t.Fatalf("第 1 条消息: %v", err)
	}
	if want := hexBytes(t, vecIKMsg1); !bytes.Equal(m1, want) {
		t.Fatalf("第 1 条消息不对\n得到 %x\n期望 %x", m1, want)
	}

	payload, err := h.readMessage2(hexBytes(t, vecIKMsg2))
	if err != nil {
		t.Fatalf("第 2 条消息: %v", err)
	}
	if len(payload) != 0 {
		t.Fatalf("第 2 条的负载应为空，得到 %x", payload)
	}

	hh := h.handshakeHash()
	if got := hex.EncodeToString(hh); got != vecIKHash {
		t.Fatalf("握手哈希不对: 得到 %s，期望 %s", got, vecIKHash)
	}
	if got := safetyCode(hh); got != vecIKSafety {
		t.Fatalf("安全码不对: 得到 %s，期望 %s", got, vecIKSafety)
	}

	i2r, r2i, err := h.finish()
	if err != nil {
		t.Fatalf("取密钥: %v", err)
	}
	if got := hex.EncodeToString(i2r); got != vecIKI2R {
		t.Fatalf("控制端→被控端的密钥不对: 得到 %s，期望 %s", got, vecIKI2R)
	}
	if got := hex.EncodeToString(r2i); got != vecIKR2I {
		t.Fatalf("被控端→控制端的密钥不对: 得到 %s，期望 %s", got, vecIKR2I)
	}
}

// 被控端在局域网里不可信，改一个字节就必须解不开。
func TestNoiseRejectsTampered(t *testing.T) {
	h := newNoiseXX(x25519Priv(t, vecCtrlStaticPriv), airhandPrologue(1))
	h.setEphemeral(x25519Priv(t, vecCtrlEphPriv))
	if _, err := h.writeMessage1(nil); err != nil {
		t.Fatalf("第 1 条消息: %v", err)
	}

	bad := append([]byte(nil), hexBytes(t, vecXXMsg2)...)
	bad[len(bad)-1] ^= 0xff
	if _, err := h.readMessage2(bad); err == nil {
		t.Fatal("改过的第 2 条消息不该解得开")
	}

	// 截断同样要拒绝。
	short := hexBytes(t, vecXXMsg2)
	if _, err := h.readMessage2(short[:len(short)-1]); err == nil {
		t.Fatal("截断的消息不该解得开")
	}
}

// 调用顺序错了要立刻报错，不能拿半截状态继续算。
func TestNoiseCallOrder(t *testing.T) {
	h := newNoiseIK(x25519Priv(t, vecCtrlStaticPriv),
		x25519Pub(t, vecHostStaticPub), airhandPrologue(0))
	if _, err := h.readMessage2(hexBytes(t, vecIKMsg2)); err == nil {
		t.Fatal("还没发第 1 条就去解第 2 条，应当失败")
	}
	if _, err := h.writeMessage3(nil); err == nil {
		t.Fatal("IK 没有第 3 条消息")
	}
	if _, _, err := h.finish(); err == nil {
		t.Fatal("握手没走完就取密钥，应当失败")
	}

	// IK 缺了对端公钥就没法算 es，应当拒绝。
	noPeer := newNoiseIK(x25519Priv(t, vecCtrlStaticPriv), nil, airhandPrologue(0))
	if _, err := noPeer.writeMessage1(nil); err == nil {
		t.Fatal("没有对端公钥不该能发起 IK")
	}
}

// 安全码是 6 位十进制，格式固定成 123-456。
func TestSafetyCodeFormat(t *testing.T) {
	for _, h := range []string{vecXXHash, vecIKHash} {
		got := safetyCode(hexBytes(t, h))
		if len(got) != 7 || got[3] != '-' {
			t.Fatalf("安全码格式不对: %q", got)
		}
	}
}

// 每条通道的密钥都不同：标签错了会把两条通道的密钥派生成一样，必须挡住。
func TestDeriveKeyLabels(t *testing.T) {
	hh := hexBytes(t, vecXXHash)
	raw := hexBytes(t, vecXXI2R)
	seen := map[string]string{}
	for _, label := range []string{labelControl, labelVideo, videoLabel(1), labelBulk, labelFiles, labelAudio, labelDatagram} {
		k := deriveKey(hh, raw, label)
		hexed := hex.EncodeToString(k[:])
		if prev, ok := seen[hexed]; ok {
			t.Fatalf("通道 %q 与 %q 派生出了同一把密钥", label, prev)
		}
		seen[hexed] = label
	}
	// 第 0 路画面不带编号。
	if videoLabel(0) != labelVideo {
		t.Fatalf("第 0 路画面的标签应为 %q，得到 %q", labelVideo, videoLabel(0))
	}
}
