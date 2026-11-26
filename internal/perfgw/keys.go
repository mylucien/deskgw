package perfgw

// 会话密钥的派生。握手给出两个方向的原始密钥（发起方→响应方、反过来），
// 每条通道再用 HKDF-SHA256(握手哈希当 salt, 原始密钥当 ikm, 通道标签当 info) 派生一把 ——
// 跟 airhand_link::secure::derive 一致。标签不同，所以从一条通道搬到另一条通道的帧解不开。

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// keyLen 是每条通道一个方向一把密钥的长度。
	keyLen = 32

	labelControl  = "airhand control"
	labelVideo    = "airhand video"
	labelBulk     = "airhand bulk"
	labelFiles    = "airhand files"
	labelAudio    = "airhand audio"
	labelDatagram = "airhand control datagram"
)

// deriveKey 派生一个方向、一条通道的密钥。
func deriveKey(handshakeHash, raw []byte, label string) [keyLen]byte {
	var out [keyLen]byte
	r := hkdf.New(sha256.New, raw, handshakeHash, []byte(label))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		// HKDF-SHA256 取 32 字节不会失败，除非标签长到离谱。
		panic("hkdf: " + err.Error())
	}
	return out
}

// videoLabel 是画面的第 n 路标签：第 0 路不带编号。
func videoLabel(stream int) string {
	if stream == 0 {
		return labelVideo
	}
	return fmt.Sprintf("%s %d", labelVideo, stream)
}

// safetyCode 是 airhand_proto::handshake::safety_code：从种子取 6 位十进制，写成 123-456。
// 两端算出来一样，第一次连接时给两边的人对一下。
func safetyCode(handshakeHash []byte) string {
	seed := deriveKey(handshakeHash, handshakeHash, "airhand safety code")
	n := binary.LittleEndian.Uint64(seed[:8]) % 1_000_000
	return fmt.Sprintf("%03d-%03d", n/1000, n%1000)
}
