package perfgw

// 握手的编排：把 Noise 的消息装进 airhand 的握手消息里，解开被控端的决定，
// 最后交出会话密钥。收发交给调用方（quic.go 拿流、relay.go 转发），
// 这一层只吃字节，所以能直接用向量测。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// sessionVersion 是会话版本，必须与被控端精确一致。
	sessionVersion = 1

	// patternKnown / patternFirst 是 Pattern 的线上值。
	patternKnown = 0
	patternFirst = 1

	// videoStreams 是一个会话最多几路画面（airhand_proto::MAX_STREAMS）。
	videoStreams = 4

	// sealOverhead 是密封单元比明文多出来的：16 字节标签加 8 字节计数。
	sealOverhead = 24

	// firstCounter 是握手之后每一帧的计数起点：控制通道两个方向各已用掉计数 0
	// （被控端的决定、控制端的 Confirm），浏览器侧收发都从 1 接下去。
	firstCounter = 1
)

var (
	// errRefused 表示被控端明确拒绝了这次握手。
	errRefused = errors.New("被控端拒绝了这次握手")
	// errVersion 表示会话版本对不上。
	errVersion = errors.New("被控端的会话版本不匹配")
)

// refusal 是被控端拒绝的原因（HostVerdict.refused）。
type refusal uint64

const (
	refusalIncompatible    refusal = 0
	refusalPairingRequired refusal = 1
)

func refusalError(r refusal) error {
	switch r {
	case refusalIncompatible:
		return fmt.Errorf("%w：没有双方都支持的会话版本", errRefused)
	case refusalPairingRequired:
		return fmt.Errorf("%w：这台被控端没有预置路由器的公钥，需要在它的 config.toml 里加 [[paired]]", errRefused)
	default:
		return fmt.Errorf("%w：未知原因 %d", errRefused, uint64(r))
	}
}

// handshakeError 把被控端回的 HandshakeError 变成错误。它是明文，服务器也能伪造，
// 所以只用来给管理员提示，不改变任何信任判断。
func handshakeError(code uint64) error {
	reason := map[uint64]string{
		0: "不认识的握手模式",
		1: "被控端不认识路由器的公钥（可能重装过，或者有人冒充）",
		2: "配对码不对",
		3: "被控端现在不接受配对",
		4: "握手消息格式不对",
	}[code]
	if reason == "" {
		reason = fmt.Sprintf("未知原因 %d", code)
	}
	return fmt.Errorf("%w：%s", errRefused, reason)
}

// qualitySettings 是 ControllerIntro 里的初始画质。默认值与被控端侧的
// QualitySettings::default() 一致（30 帧、4000 kbps、短边 1080、自动码率、H.264）。
type qualitySettings struct {
	fps         uint8
	bitrateKbps uint32
	maxShort    uint16
	adaptive    bool
	codec       uint8
	drawCursor  bool
}

func defaultQuality() qualitySettings {
	return qualitySettings{fps: 30, bitrateKbps: 4000, maxShort: 1080, adaptive: true, codec: 0}
}

// streamView 是一路画面想看哪个显示器、短边上限多少。
type streamView struct {
	display  uint8
	maxShort uint16
}

// controllerIntro 是路由器在最后一条 Noise 消息里交给被控端的介绍。
type controllerIntro struct {
	name     string
	os       string
	settings qualitySettings
	audio    bool
	view     []streamView
	privacy  bool
}

// encode 按 ControllerIntro 的字段顺序写。两个尾部开关为 false 时不写，
// 数组长度随之变成 6（privacy 省略）与 5（draw_cursor 省略）。
func (i controllerIntro) encode() []byte {
	var w cbWriter
	if i.privacy {
		w.array(7)
	} else {
		w.array(6)
	}
	w.uint(sessionVersion)
	w.text(i.name)
	w.text(i.os)
	if i.settings.drawCursor {
		w.array(6)
	} else {
		w.array(5)
	}
	s := i.settings
	w.uint(uint64(s.fps))
	w.uint(uint64(s.bitrateKbps))
	w.uint(uint64(s.maxShort))
	w.boolean(s.adaptive)
	w.uint(uint64(s.codec))
	if s.drawCursor {
		w.boolean(true)
	}
	w.boolean(i.audio)
	w.array(len(i.view))
	for _, v := range i.view {
		w.array(2)
		w.uint(uint64(v.display))
		w.uint(uint64(v.maxShort))
	}
	if i.privacy {
		w.boolean(true)
	}
	return w.b
}

// handshakeReply 是被控端在握手期间发来的一条。字段都给成可选，被控端只会写其中一部分。
type handshakeReply struct {
	errCode *uint64
	noise   []byte
	verdict []byte
}

func decodeHandshakeReply(b []byte) (handshakeReply, error) {
	var out handshakeReply
	if len(b) > noiseMaxMsg {
		return out, errCBOR
	}
	r := &cbReader{b: b}
	n, err := r.mapLen()
	if err != nil {
		return out, err
	}
	for i := 0; i < n; i++ {
		key, err := r.uint()
		if err != nil {
			return out, err
		}
		switch key {
		case 0:
			code, err := r.uint()
			if err != nil {
				return out, err
			}
			out.errCode = &code
		case 2:
			if out.noise, err = r.bytes(); err != nil {
				return out, err
			}
		case 3:
			if out.verdict, err = r.bytes(); err != nil {
				return out, err
			}
		default:
			// 被控端升级后可能加字段，不认识的跳过。
			if err := r.skip(); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

// decodeHostVerdict 读被控端加密的决定：`[版本]` 或 `[版本, 拒绝原因]`。
// 拒绝原因为 None 时是尾部字段，被整个省略。
func decodeHostVerdict(b []byte) (uint16, *refusal, error) {
	r := &cbReader{b: b}
	n, err := r.array()
	if err != nil {
		return 0, nil, err
	}
	if n < 1 || n > 2 {
		return 0, nil, errCBOR
	}
	ver, err := r.uint()
	if err != nil {
		return 0, nil, err
	}
	var refused *refusal
	if n == 2 && !r.isNull() {
		v, err := r.uint()
		if err != nil {
			return 0, nil, err
		}
		rv := refusal(v)
		refused = &rv
	}
	if !r.done() {
		return 0, nil, errCBOR
	}
	return uint16(ver), refused, nil
}

// openSealed 解开一个密封单元：密文 | 16 字节标签 | 8 字节计数（小端）。
// 计数值就是 AES-256-GCM 的 nonce（前 4 字节为 0，后 8 字节是它）。
// 这与浏览器的 WebCrypto 直接对应：去掉末尾 8 字节正好是「密文接标签」。
func openSealed(key [keyLen]byte, data []byte) ([]byte, error) {
	if len(data) < sealOverhead {
		return nil, errNoise
	}
	body := data[:len(data)-8]
	counter := binary.LittleEndian.Uint64(data[len(data)-8:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	plain, err := gcm.Open(nil, nonce[:], body, nil)
	if err != nil {
		return nil, errNoise
	}
	return plain, nil
}

// sessionKeys 是握手之后路由器手里的密钥。方向按路由器算：sent 是发往被控端，
// recv 是收自被控端。
type sessionKeys struct {
	hash   []byte
	safety string
	// control 是控制通道，[0] 发、[1] 收。
	control [2][keyLen]byte
	// datagram 是控制数据报，[0] 发、[1] 收。
	datagram [2][keyLen]byte
	// video 是各路口径的接收密钥，只收不发。
	video [][keyLen]byte
}

// deriveSessionKeys 从握手哈希与两个方向的原始密钥派生全部通道密钥。
// 路由器是发起方：i2r 是自己的发送方向，r2i 是接收方向。
func deriveSessionKeys(handshakeHash, i2r, r2i []byte) *sessionKeys {
	sk := &sessionKeys{hash: handshakeHash, safety: safetyCode(handshakeHash)}
	sk.control[0] = deriveKey(handshakeHash, i2r, labelControl)
	sk.control[1] = deriveKey(handshakeHash, r2i, labelControl)
	sk.datagram[0] = deriveKey(handshakeHash, i2r, labelDatagram)
	sk.datagram[1] = deriveKey(handshakeHash, r2i, labelDatagram)
	for s := 0; s < videoStreams; s++ {
		sk.video = append(sk.video, deriveKey(handshakeHash, r2i, videoLabel(s)))
	}
	return sk
}

// handshake 走完一次端到端握手。
type handshake struct {
	noise   *noiseInitiator
	intro   []byte
	verdict []byte
	step    int
}

// newHandshake 按有没有被控端公钥选模式：有就走 IK（一个往返），没有就走 XX（多半个往返）。
func newHandshake(static *ecdh.PrivateKey, peer *ecdh.PublicKey, intro controllerIntro) *handshake {
	var n *noiseInitiator
	if peer != nil {
		n = newNoiseIK(static, peer, airhandPrologue(patternKnown))
	} else {
		n = newNoiseXX(static, airhandPrologue(patternFirst))
	}
	return &handshake{noise: n, intro: intro.encode()}
}

// pattern 是这次握手用的模式码，要写进 HandshakeInit。
func (h *handshake) pattern() uint64 {
	if h.noise.xx {
		return patternFirst
	}
	return patternKnown
}

// start 返回装进 Incoming.init 的那条 HandshakeInit。IK 的介绍跟在第 1 条消息里，
// XX 的等第 3 条。
func (h *handshake) start() ([]byte, error) {
	if h.step != 0 {
		return nil, errNoise
	}
	var payload []byte
	if !h.noise.xx {
		payload = h.intro
	}
	msg, err := h.noise.writeMessage1(payload)
	if err != nil {
		return nil, err
	}
	var w cbWriter
	w.mapN(2)
	w.uint(0)
	w.uint(h.pattern())
	w.uint(2)
	w.bytes(msg)
	h.step = 1
	return w.b, nil
}

// reply 处理被控端的第一条回复。IK 没有第 3 条消息，返回 nil，决定也在这条回复里；
// XX 要返回 HandshakeFinish，决定在下一轮。
func (h *handshake) reply(b []byte) ([]byte, error) {
	if h.step != 1 {
		return nil, errNoise
	}
	r, err := decodeHandshakeReply(b)
	if err != nil {
		return nil, err
	}
	if r.errCode != nil {
		return nil, handshakeError(*r.errCode)
	}
	if len(r.noise) == 0 {
		return nil, errNoise
	}
	if _, err := h.noise.readMessage2(r.noise); err != nil {
		return nil, err
	}
	if !h.noise.xx {
		h.verdict = r.verdict
		h.step = 2
		return nil, nil
	}
	msg, err := h.noise.writeMessage3(h.intro)
	if err != nil {
		return nil, err
	}
	h.step = 2
	var w cbWriter
	w.array(1)
	w.bytes(msg)
	return w.b, nil
}

// verdictReply 处理 XX 的第二条回复，里面是被控端加密的决定。
func (h *handshake) verdictReply(b []byte) error {
	if !h.noise.xx || h.step != 2 {
		return errNoise
	}
	r, err := decodeHandshakeReply(b)
	if err != nil {
		return err
	}
	if r.errCode != nil {
		return handshakeError(*r.errCode)
	}
	h.verdict = r.verdict
	h.step = 3
	return nil
}

// keys 解开被控端的决定并交出会话密钥。被控端拒绝时返回的错误里带着原因。
func (h *handshake) keys() (*sessionKeys, error) {
	if h.step < 2 {
		return nil, errNoise
	}
	hh := h.noise.handshakeHash()
	i2r, r2i, err := h.noise.finish()
	if err != nil {
		return nil, err
	}
	sk := deriveSessionKeys(hh, i2r, r2i)
	if len(h.verdict) == 0 {
		return nil, errNoise
	}
	// 决定是被控端在控制通道上发来的第一个密封单元（计数 0）。
	plain, err := openSealed(sk.control[1], h.verdict)
	if err != nil {
		return nil, err
	}
	version, refused, err := decodeHostVerdict(plain)
	if err != nil {
		return nil, err
	}
	if version != sessionVersion {
		return nil, fmt.Errorf("%w：被控端是 %d，要求 %d", errVersion, version, sessionVersion)
	}
	if refused != nil {
		return nil, refusalError(*refused)
	}
	h.step = 4
	return sk, nil
}

// confirm 是控制端在控制通道上发出的第一帧密文（计数 0），空映射。被控端解开它
// 才会在托盘显示这个控制端。
func confirmMessage() []byte {
	return []byte{0xa0}
}
