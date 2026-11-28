package perfgw

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// sealForTest 按线上格式造一个密封单元：密文 | 16 字节标签 | 8 字节计数。
func sealForTest(t *testing.T, key [keyLen]byte, counter uint64, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("AES: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM: %v", err)
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	out := gcm.Seal(nil, nonce[:], plain, nil)
	return append(out, nonce[4:]...)
}

// wrapReply 按线上格式造一条 HandshakeReply：只写存在的字段。
func wrapReply(noise, verdict []byte) []byte {
	var w cbWriter
	n := 0
	if noise != nil {
		n++
	}
	if verdict != nil {
		n++
	}
	w.mapN(n)
	if noise != nil {
		w.uint(2)
		w.bytes(noise)
	}
	if verdict != nil {
		w.uint(3)
		w.bytes(verdict)
	}
	return w.b
}

func defaultIntro() controllerIntro {
	return controllerIntro{name: "deskgw", os: "OpenWrt", settings: defaultQuality()}
}

// handshakeInitNoise 解开 HandshakeInit，校验模式码并取出 Noise 第 1 条消息。
func handshakeInitNoise(t *testing.T, b []byte, wantPattern uint64) []byte {
	t.Helper()
	r := &cbReader{b: b}
	n, err := r.mapLen()
	if err != nil || n != 2 {
		t.Fatalf("HandshakeInit 应当是两项映射: %v", err)
	}
	key, _ := r.uint()
	if key != 0 {
		t.Fatalf("第一项应当是模式码，得到键 %d", key)
	}
	pattern, _ := r.uint()
	if pattern != wantPattern {
		t.Fatalf("模式码应当是 %d，得到 %d", wantPattern, pattern)
	}
	key, _ = r.uint()
	if key != 2 {
		t.Fatalf("第二项应当是 Noise 消息，得到键 %d", key)
	}
	noise, err := r.bytes()
	if err != nil {
		t.Fatalf("Noise 消息读不出来: %v", err)
	}
	if !r.done() {
		t.Fatal("HandshakeInit 后面还有多余字节")
	}
	return noise
}

// 介绍必须与 Rust 侧写出同样的字节：手写的 CBOR 编码器最容易在这里错。
func TestControllerIntroEncode(t *testing.T) {
	got := hex.EncodeToString(defaultIntro().encode())
	if got != vecIntro {
		t.Fatalf("介绍的编码不对\n得到 %s\n期望 %s", got, vecIntro)
	}

	// 两个尾部开关都打开时数组变长。
	full := defaultIntro()
	full.audio = true
	full.privacy = true
	full.settings.drawCursor = true
	full.view = []streamView{{display: 0}, {display: 1}}
	b := full.encode()
	r := &cbReader{b: b}
	n, err := r.array()
	if err != nil {
		t.Fatalf("介绍应当是数组: %v", err)
	}
	if n != 7 {
		t.Fatalf("两个开关都打开时应当是 7 项，得到 %d", n)
	}
}

func TestDecodeHandshakeReply(t *testing.T) {
	for _, c := range []struct {
		name string
		hex  string
		want func(t *testing.T, r handshakeReply)
	}{
		{"只有 noise", "a10243060708", func(t *testing.T, r handshakeReply) {
			if !bytes.Equal(r.noise, []byte{6, 7, 8}) {
				t.Fatalf("noise 不对: %x", r.noise)
			}
			if r.errCode != nil || r.verdict != nil {
				t.Fatal("不该有错误或决定")
			}
		}},
		{"只有错误", "a10001", func(t *testing.T, r handshakeReply) {
			if r.errCode == nil || *r.errCode != 1 {
				t.Fatalf("错误码不对: %v", r.errCode)
			}
		}},
		{"只有决定", "a10342090a", func(t *testing.T, r handshakeReply) {
			if !bytes.Equal(r.verdict, []byte{9, 10}) {
				t.Fatalf("决定不对: %x", r.verdict)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, err := decodeHandshakeReply(hexBytes(t, c.hex))
			if err != nil {
				t.Fatalf("解码: %v", err)
			}
			c.want(t, r)
		})
	}
}

// 被控端升级后加的字段要跳过，不能因此拒绝整条回复。
func TestDecodeHandshakeReplySkipsUnknown(t *testing.T) {
	// {2: bytes(2), 7: 1}
	r, err := decodeHandshakeReply(hexBytes(t, "a2024206070701"))
	if err != nil {
		t.Fatalf("解码: %v", err)
	}
	if !bytes.Equal(r.noise, []byte{6, 7}) {
		t.Fatalf("noise 不对: %x", r.noise)
	}
}

func TestDecodeHostVerdict(t *testing.T) {
	ver, refused, err := decodeHostVerdict(hexBytes(t, "8101"))
	if err != nil {
		t.Fatalf("解码: %v", err)
	}
	if ver != 1 || refused != nil {
		t.Fatalf("应当接受且版本为 1，得到 %d %v", ver, refused)
	}

	ver, refused, err = decodeHostVerdict(hexBytes(t, "820101"))
	if err != nil {
		t.Fatalf("解码: %v", err)
	}
	if ver != 1 || refused == nil || *refused != refusalPairingRequired {
		t.Fatalf("应当是要求配对，得到 %d %v", ver, refused)
	}

	if _, _, err := decodeHostVerdict(hexBytes(t, "83010102")); err == nil {
		t.Fatal("三个字段的决定应当拒绝")
	}
	if _, _, err := decodeHostVerdict(hexBytes(t, "810101")); err == nil {
		t.Fatal("尾部多余字节应当拒绝")
	}
}

// 用 Rust 侧加密的决定验证解密：密钥来自 IK 的控制通道收方向，计数 0。
func TestOpenSealed(t *testing.T) {
	sk := deriveSessionKeys(hexBytes(t, vecIKHash),
		hexBytes(t, vecIKI2R), hexBytes(t, vecIKR2I))
	plain, err := openSealed(sk.control[1], hexBytes(t, vecIKVerdictSealed))
	if err != nil {
		t.Fatalf("解密: %v", err)
	}
	if got := hex.EncodeToString(plain); got != "8101" {
		t.Fatalf("明文不对: %s", got)
	}

	// 换个计数就该解不开：计数是 nonce 的一部分。
	bad := append([]byte(nil), hexBytes(t, vecIKVerdictSealed)...)
	bad[len(bad)-1] = 1
	if _, err := openSealed(sk.control[1], bad); err == nil {
		t.Fatal("改过计数的密封单元不该解得开")
	}
}

// XX：第一次连，三条消息，介绍在第 3 条里，决定在最后一条回复里。
func TestHandshakeXX(t *testing.T) {
	h := newHandshake(x25519Priv(t, vecCtrlStaticPriv), nil, defaultIntro())
	if h.pattern() != patternFirst {
		t.Fatalf("没有对端公钥时应当用 XX，得到模式 %d", h.pattern())
	}
	h.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))

	initMsg, err := h.start()
	if err != nil {
		t.Fatalf("第 1 步: %v", err)
	}
	if noise := handshakeInitNoise(t, initMsg, patternFirst); !bytes.Equal(noise, hexBytes(t, vecXXMsg1)) {
		t.Fatalf("HandshakeInit 里的第 1 条消息不对: %x", noise)
	}

	finishMsg, err := h.reply(wrapReply(hexBytes(t, vecXXMsg2), nil))
	if err != nil {
		t.Fatalf("第 2 步: %v", err)
	}
	wantFinish := append([]byte{0x81, 0x58, byte(len(vecXXMsg3) / 2)}, hexBytes(t, vecXXMsg3)...)
	if !bytes.Equal(finishMsg, wantFinish) {
		t.Fatalf("HandshakeFinish 不对\n得到 %x\n期望 %x", finishMsg, wantFinish)
	}

	// 决定用控制通道收方向、计数 0 加密。
	sealed := sealForTest(t, deriveKey(hexBytes(t, vecXXHash), hexBytes(t, vecXXR2I), labelControl), 0, hexBytes(t, "8101"))
	if err := h.verdictReply(wrapReply(nil, sealed)); err != nil {
		t.Fatalf("第 3 步: %v", err)
	}

	sk, err := h.keys()
	if err != nil {
		t.Fatalf("取密钥: %v", err)
	}
	wantKey := deriveKey(hexBytes(t, vecXXHash), hexBytes(t, vecXXI2R), labelControl)
	if got := hex.EncodeToString(sk.control[0][:]); got != hex.EncodeToString(wantKey[:]) {
		t.Fatal("控制通道发送方向的密钥不对")
	}
	if sk.safety != vecXXSafety {
		t.Fatalf("安全码不对: %s，期望 %s", sk.safety, vecXXSafety)
	}
	if len(sk.video) != videoStreams {
		t.Fatalf("应当有 %d 路画面的密钥，得到 %d", videoStreams, len(sk.video))
	}
}

// IK：被控端公钥已知，两条消息，决定就跟在第 2 条里。
func TestHandshakeIK(t *testing.T) {
	h := newHandshake(x25519Priv(t, vecCtrlStaticPriv),
		x25519Pub(t, vecHostStaticPub), defaultIntro())
	if h.pattern() != patternKnown {
		t.Fatalf("已知公钥时应当用 IK，得到模式 %d", h.pattern())
	}
	h.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))

	initMsg, err := h.start()
	if err != nil {
		t.Fatalf("第 1 步: %v", err)
	}
	if noise := handshakeInitNoise(t, initMsg, patternKnown); !bytes.Equal(noise, hexBytes(t, vecIKMsg1)) {
		t.Fatalf("HandshakeInit 里的第 1 条消息不对: %x", noise)
	}

	finish, err := h.reply(wrapReply(hexBytes(t, vecIKMsg2), hexBytes(t, vecIKVerdictSealed)))
	if err != nil {
		t.Fatalf("第 2 步: %v", err)
	}
	if finish != nil {
		t.Fatalf("IK 不该再发一条 HandshakeFinish: %x", finish)
	}

	sk, err := h.keys()
	if err != nil {
		t.Fatalf("取密钥: %v", err)
	}
	if sk.safety != vecIKSafety {
		t.Fatalf("安全码不对: %s，期望 %s", sk.safety, vecIKSafety)
	}
	wantKey := deriveKey(hexBytes(t, vecIKHash), hexBytes(t, vecIKR2I), labelControl)
	if got := hex.EncodeToString(sk.control[1][:]); got != hex.EncodeToString(wantKey[:]) {
		t.Fatal("控制通道接收方向的密钥不对")
	}
}

// 被控端拒绝时要把原因带出来，管理员才知道要去改 config.toml。
func TestHandshakeRefused(t *testing.T) {
	h := newHandshake(x25519Priv(t, vecCtrlStaticPriv), nil, defaultIntro())
	h.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))
	if _, err := h.start(); err != nil {
		t.Fatalf("第 1 步: %v", err)
	}
	if _, err := h.reply(wrapReply(hexBytes(t, vecXXMsg2), nil)); err != nil {
		t.Fatalf("第 2 步: %v", err)
	}
	// 决定里写的是「要配对码」。
	sealed := sealForTest(t, deriveKey(hexBytes(t, vecXXHash), hexBytes(t, vecXXR2I), labelControl), 0, hexBytes(t, "820101"))
	if err := h.verdictReply(wrapReply(nil, sealed)); err != nil {
		t.Fatalf("第 3 步: %v", err)
	}
	_, err := h.keys()
	if !errors.Is(err, errRefused) {
		t.Fatalf("应当是拒绝，得到 %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("[[paired]]")) {
		t.Fatalf("错误信息应当提示怎么修: %v", err)
	}
}

// 版本对不上要单独报，别混成「解不开」。
func TestHandshakeVersionMismatch(t *testing.T) {
	h := newHandshake(x25519Priv(t, vecCtrlStaticPriv), nil, defaultIntro())
	h.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))
	if _, err := h.start(); err != nil {
		t.Fatalf("第 1 步: %v", err)
	}
	if _, err := h.reply(wrapReply(hexBytes(t, vecXXMsg2), nil)); err != nil {
		t.Fatalf("第 2 步: %v", err)
	}
	// 版本写 2。
	sealed := sealForTest(t, deriveKey(hexBytes(t, vecXXHash), hexBytes(t, vecXXR2I), labelControl), 0, hexBytes(t, "8102"))
	if err := h.verdictReply(wrapReply(nil, sealed)); err != nil {
		t.Fatalf("第 3 步: %v", err)
	}
	if _, err := h.keys(); !errors.Is(err, errVersion) {
		t.Fatalf("应当是版本不匹配，得到 %v", err)
	}
}

// 被控端明说的握手错误要转成人能看懂的话。
func TestHandshakeErrorText(t *testing.T) {
	err := handshakeError(1)
	if !errors.Is(err, errRefused) {
		t.Fatalf("应当是拒绝，得到 %v", err)
	}
	// code 1 是「不认识路由器的公钥」：只有这一种才该提示重新批准。
	// 放宽成「所有 IK 失败都算密钥问题」会把网络抖动误报成换机，诱导管理员
	// 重新批准、重新信任首次见到的密钥，等于用抖动拆掉 TOFU。
	if !errors.Is(err, errKeyUnrecognized) {
		t.Fatalf("code 1 应当带 errKeyUnrecognized，得到 %v", err)
	}
	if err := handshakeError(99); !bytes.Contains([]byte(err.Error()), []byte("99")) {
		t.Fatalf("未知原因应当带上编号: %v", err)
	}
	if err := handshakeError(3); errors.Is(err, errKeyUnrecognized) {
		t.Fatalf("其他拒绝原因不该被当成密钥问题: %v", err)
	}
}

// 调用顺序错了要立刻报错。
func TestHandshakeOrder(t *testing.T) {
	h := newHandshake(x25519Priv(t, vecCtrlStaticPriv), nil, defaultIntro())
	if _, err := h.reply(wrapReply(hexBytes(t, vecXXMsg2), nil)); err == nil {
		t.Fatal("没发第 1 条就处理回复，应当失败")
	}
	if _, err := h.keys(); err == nil {
		t.Fatal("没走完就取密钥，应当失败")
	}
	if _, err := h.start(); err != nil {
		t.Fatalf("第 1 步: %v", err)
	}
	if _, err := h.start(); err == nil {
		t.Fatal("重复开始应当失败")
	}
	// IK 没有第二条回复。
	ik := newHandshake(x25519Priv(t, vecCtrlStaticPriv), x25519Pub(t, vecHostStaticPub), defaultIntro())
	ik.noise.setEphemeral(x25519Priv(t, vecCtrlEphPriv))
	if _, err := ik.start(); err != nil {
		t.Fatalf("IK 第 1 步: %v", err)
	}
	if _, err := ik.reply(wrapReply(hexBytes(t, vecIKMsg2), hexBytes(t, vecIKVerdictSealed))); err != nil {
		t.Fatalf("IK 第 2 步: %v", err)
	}
	if err := ik.verdictReply(nil); err == nil {
		t.Fatal("IK 没有第二条回复")
	}
}
