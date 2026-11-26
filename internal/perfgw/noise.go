package perfgw

// Noise_IK_25519_ChaChaPoly_BLAKE2s 与 Noise_XX_25519_ChaChaPoly_BLAKE2s 的最小实现。
//
// 为什么自己写：路由器要跟 Windows 上那份 Rust 被控端（snow 0.10）逐字节互通，
// 而 Go 生态里没有同时提供这两种模式、BLAKE2s 与 raw split 的成熟实现。
//
// 只写**发起方**：路由器就是控制端，永远由它发起握手；被控端那一侧不实现，
// 少一半代码也少一半解析面。模式也不做通用的 token 解释器 —— airhand 只用这两种，
// 写死顺序比解释一遍 token 表更难出错。
//
// 与 snow 对齐的几处细节（都靠 noise_test.go 里的黄金向量锁住）：
//   - HKDF 是 HMAC-BLAKE2s、不带 info，输出按 32 字节切段；
//   - nonce 是 4 字节 0 加 8 字节小端计数，从 0 开始；
//   - 密钥为空时 EncryptAndHash 是明文，但混入握手哈希的仍是那串字节；
//   - split 用 HKDF(ck, 空, 2)，第 1 段是发起方→响应方，第 2 段反过来。

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	noiseHashLen = 32
	noiseKeyLen  = 32
	noiseTagLen  = 16
	// noiseMaxMsg 取自 airhand_proto::handshake::MAX_MSG：握手每条消息的上限。
	noiseMaxMsg = 16 << 10

	noiseProtocolIK = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	noiseProtocolXX = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
)

// errNoise 表示握手消息不合法，或者根本不是这次握手的。
var errNoise = errors.New("握手消息不正确")

// hmacBlake2s 是 HMAC-BLAKE2s。注意不是 BLAKE2s 的 keyed 模式：Noise 规定的是
// 标准 HMAC 构造，两者算出来的东西不一样。
func hmacBlake2s(key, data []byte) [noiseHashLen]byte {
	m := hmac.New(func() hash.Hash {
		h, err := blake2s.New256(nil)
		if err != nil {
			// 空密钥不会失败；真失败了也没法继续，交给上层当作握手失败。
			panic("blake2s: " + err.Error())
		}
		return h
	}, key)
	m.Write(data)
	var out [noiseHashLen]byte
	copy(out[:], m.Sum(nil))
	return out
}

// noiseHKDF 是 Noise 的 HKDF：没有 info，按 32 字节一段输出。
func noiseHKDF(ck, ikm []byte, n int) [][noiseHashLen]byte {
	temp := hmacBlake2s(ck, ikm)
	out := make([][noiseHashLen]byte, n)
	var prev []byte
	for i := 1; i <= n; i++ {
		buf := make([]byte, 0, len(prev)+1)
		buf = append(buf, prev...)
		buf = append(buf, byte(i))
		out[i-1] = hmacBlake2s(temp[:], buf)
		prev = out[i-1][:]
	}
	return out
}

// noiseNonce 把计数摊成 12 字节：前 4 字节 0，后 8 字节小端。
// airhand 的会话帧把计数写在密文后面，用的也是同一个编号方式。
func noiseNonce(n uint64) [12]byte {
	var out [12]byte
	binary.LittleEndian.PutUint64(out[4:], n)
	return out
}

// noiseCipher 是一条方向上的 CipherState。key 为空表示还没 mixKey 过。
type noiseCipher struct {
	key []byte
	n   uint64
}

func (c *noiseCipher) setKey(key []byte) {
	c.key = key
	c.n = 0
}

func (c *noiseCipher) seal(ad, pt []byte) ([]byte, error) {
	if c.key == nil {
		return pt, nil
	}
	aead, err := chacha20poly1305.New(c.key)
	if err != nil {
		return nil, errNoise
	}
	nonce := noiseNonce(c.n)
	c.n++
	return aead.Seal(nil, nonce[:], pt, ad), nil
}

func (c *noiseCipher) open(ad, ct []byte) ([]byte, error) {
	if c.key == nil {
		return ct, nil
	}
	aead, err := chacha20poly1305.New(c.key)
	if err != nil {
		return nil, errNoise
	}
	nonce := noiseNonce(c.n)
	c.n++
	pt, err := aead.Open(nil, nonce[:], ct, ad)
	if err != nil {
		return nil, errNoise
	}
	return pt, nil
}

// noiseSym 是 SymmetricState：链密钥、握手哈希、当前钥。
type noiseSym struct {
	ck [noiseHashLen]byte
	h  [noiseHashLen]byte
	c  noiseCipher
}

func (s *noiseSym) init(protocolName string) {
	if len(protocolName) <= noiseHashLen {
		var h [noiseHashLen]byte
		copy(h[:], protocolName)
		s.h = h
	} else {
		s.h = blake2s.Sum256([]byte(protocolName))
	}
	s.ck = s.h
	s.c = noiseCipher{}
}

func (s *noiseSym) mixHash(data []byte) {
	buf := make([]byte, 0, noiseHashLen+len(data))
	buf = append(buf, s.h[:]...)
	buf = append(buf, data...)
	s.h = blake2s.Sum256(buf)
}

func (s *noiseSym) mixKey(ikm []byte) {
	out := noiseHKDF(s.ck[:], ikm, 2)
	s.ck = out[0]
	s.c.setKey(out[1][:])
}

func (s *noiseSym) encryptAndHash(pt []byte) ([]byte, error) {
	ct, err := s.c.seal(s.h[:], pt)
	if err != nil {
		return nil, err
	}
	s.mixHash(ct)
	return ct, nil
}

func (s *noiseSym) decryptAndHash(ct []byte) ([]byte, error) {
	pt, err := s.c.open(s.h[:], ct)
	if err != nil {
		return nil, err
	}
	s.mixHash(ct)
	return pt, nil
}

// split 取出两个方向的原始密钥：第 1 段发起方→响应方，第 2 段反过来。
// airhand 不从这两个数直接用，还要按通道标签再派生一次（见 keys.go）。
func (s *noiseSym) split() (i2r, r2i []byte) {
	out := noiseHKDF(s.ck[:], nil, 2)
	return out[0][:], out[1][:]
}

// wipe 把握手残留的密钥材料抹掉。
func (s *noiseSym) wipe() {
	s.ck = [noiseHashLen]byte{}
	s.c = noiseCipher{}
}

// dh 是 X25519。低阶点会让 ECDH 报错，一律当成握手失败。
func dh(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	out, err := priv.ECDH(pub)
	if err != nil {
		return nil, errNoise
	}
	return out, nil
}

// noiseInitiator 是发起方（控制端，也就是路由器）的握手状态。
type noiseInitiator struct {
	sym     noiseSym
	static  *ecdh.PrivateKey
	eph     *ecdh.PrivateKey
	peerKey *ecdh.PublicKey // 对端 static：IK 提前知道，XX 在第 2 条消息里学到
	peerEph *ecdh.PublicKey
	// xx 为真表示 Noise_XX（第一次连），否则是 Noise_IK。
	xx bool
	// epoch 记录走到第几条消息，防止调用顺序错了还往下算。
	epoch int
}

// newNoiseIK 准备一次 IK 握手。peer 是被控端的 static 公钥（已批准时存下来的）。
func newNoiseIK(static *ecdh.PrivateKey, peer *ecdh.PublicKey, prologue []byte) *noiseInitiator {
	h := &noiseInitiator{static: static, peerKey: peer}
	h.sym.init(noiseProtocolIK)
	h.sym.mixHash(prologue)
	// IK 带 `<- s` 预消息：初始化时就要把对端的 static 混进握手哈希，
	// 漏了这一步密钥照样能对上（ck 不经过 h），但每条消息的关联数据都会错，最后 AEAD 校验失败。
	if peer != nil {
		h.sym.mixHash(peer.Bytes())
	}
	return h
}

// newNoiseXX 准备一次 XX 握手。这时还不知道被控端的公钥。
func newNoiseXX(static *ecdh.PrivateKey, prologue []byte) *noiseInitiator {
	h := &noiseInitiator{static: static, xx: true}
	h.sym.init(noiseProtocolXX)
	h.sym.mixHash(prologue)
	return h
}

// setEphemeral 固定这次握手的临时密钥。只给测试用：生产代码走随机。
func (h *noiseInitiator) setEphemeral(k *ecdh.PrivateKey) { h.eph = k }

func (h *noiseInitiator) genEphemeral() error {
	if h.eph != nil {
		return nil
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	h.eph = k
	return nil
}

// writeMessage1 发出第一条消息。
// IK 是 e, es, s, ss 加负载；XX 只有 e 加负载（负载这时是明文）。
func (h *noiseInitiator) writeMessage1(payload []byte) ([]byte, error) {
	if h.epoch != 0 {
		return nil, errNoise
	}
	if !h.xx && h.peerKey == nil {
		return nil, errNoise
	}
	if err := h.genEphemeral(); err != nil {
		return nil, err
	}
	msg := make([]byte, 0, noiseMaxMsg)
	ephPub := h.eph.PublicKey().Bytes()
	msg = append(msg, ephPub...)
	h.sym.mixHash(ephPub)

	if !h.xx {
		// es
		es, err := dh(h.eph, h.peerKey)
		if err != nil {
			return nil, err
		}
		h.sym.mixKey(es)
		// s：把本端的 static 公钥加密发过去
		ks, err := h.sym.encryptAndHash(h.static.PublicKey().Bytes())
		if err != nil {
			return nil, err
		}
		msg = append(msg, ks...)
		// ss
		ss, err := dh(h.static, h.peerKey)
		if err != nil {
			return nil, err
		}
		h.sym.mixKey(ss)
	}

	body, err := h.sym.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	msg = append(msg, body...)
	h.epoch = 1
	return msg, nil
}

// readMessage2 解开响应方的第二条消息，返回它带的负载。
// IK 是 e, ee, se 加负载；XX 是 e, ee, s, es 加负载，并且在里面学到对端公钥。
func (h *noiseInitiator) readMessage2(msg []byte) ([]byte, error) {
	if h.epoch != 1 {
		return nil, errNoise
	}
	if len(msg) > noiseMaxMsg {
		return nil, errNoise
	}
	// XX 的第 2 条要先读 e，后面至少还有 s（32+16）与负载标签（16）。
	if len(msg) < noiseKeyLen {
		return nil, errNoise
	}
	peerEph, err := ecdh.X25519().NewPublicKey(msg[:noiseKeyLen])
	if err != nil {
		return nil, errNoise
	}
	h.peerEph = peerEph
	rest := msg[noiseKeyLen:]
	h.sym.mixHash(msg[:noiseKeyLen])

	ee, err := dh(h.eph, peerEph)
	if err != nil {
		return nil, err
	}
	h.sym.mixKey(ee)

	if h.xx {
		// XX 的第 2 条是 e, ee, s, es：先解开响应方的 static，再拿它算 es。
		if len(rest) < noiseKeyLen+noiseTagLen {
			return nil, errNoise
		}
		raw, err := h.sym.decryptAndHash(rest[:noiseKeyLen+noiseTagLen])
		if err != nil {
			return nil, err
		}
		if len(raw) != noiseKeyLen {
			return nil, errNoise
		}
		pub, err := ecdh.X25519().NewPublicKey(raw)
		if err != nil {
			return nil, errNoise
		}
		h.peerKey = pub
		rest = rest[noiseKeyLen+noiseTagLen:]
		es, err := dh(h.eph, pub)
		if err != nil {
			return nil, err
		}
		h.sym.mixKey(es)
	} else {
		// IK 的第 2 条是 e, ee, se：se 用的是本端 static 与响应方临时。
		se, err := dh(h.static, peerEph)
		if err != nil {
			return nil, err
		}
		h.sym.mixKey(se)
	}

	payload, err := h.sym.decryptAndHash(rest)
	if err != nil {
		return nil, err
	}
	h.epoch = 2
	return payload, nil
}

// writeMessage3 是 XX 的第三条：s, se 加负载。IK 没有这一步。
func (h *noiseInitiator) writeMessage3(payload []byte) ([]byte, error) {
	if !h.xx || h.epoch != 2 {
		return nil, errNoise
	}
	msg := make([]byte, 0, noiseMaxMsg)
	ks, err := h.sym.encryptAndHash(h.static.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	msg = append(msg, ks...)
	se, err := dh(h.static, h.peerEph)
	if err != nil {
		return nil, err
	}
	h.sym.mixKey(se)
	body, err := h.sym.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	msg = append(msg, body...)
	h.epoch = 3
	return msg, nil
}

// done 表示握手已经走完（IK 两条、XX 三条），可以取密钥了。
func (h *noiseInitiator) done() bool {
	if h.xx {
		return h.epoch == 3
	}
	return h.epoch == 2
}

// handshakeHash 是握手哈希，airhand 拿它当安全码的种子和各通道密钥的 salt。
func (h *noiseInitiator) handshakeHash() []byte {
	out := make([]byte, noiseHashLen)
	copy(out, h.sym.h[:])
	return out
}

// peerStatic 是握手学到的（IK 是已知的）对端 static 公钥。
func (h *noiseInitiator) peerStatic() []byte {
	if h.peerKey == nil {
		return nil
	}
	return h.peerKey.Bytes()
}

// finish 取出两个方向的原始密钥并抹掉握手状态。
func (h *noiseInitiator) finish() (i2r, r2i []byte, err error) {
	if !h.done() {
		return nil, nil, errNoise
	}
	i2r, r2i = h.sym.split()
	h.sym.wipe()
	h.eph = nil
	h.peerEph = nil
	// 归零之后 done() 不再成立，重复调用会拿到 errNoise 而不是一对全零密钥。
	h.epoch = 0
	return i2r, r2i, nil
}

// airhandPrologue 是 airhand_proto::handshake::prologue：把握手绑定到模式码，
// 服务器改了模式握手就会失败。前缀里的 9 是端到端格式的版本，跟信令的 10 不是一回事。
func airhandPrologue(patternCode uint32) []byte {
	out := make([]byte, 0, len("airhand e2e 9")+4)
	out = append(out, "airhand e2e 9"...)
	return binary.LittleEndian.AppendUint32(out, patternCode)
}
