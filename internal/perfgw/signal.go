package perfgw

import (
	"encoding/binary"
	"errors"
	"io"
)

// 信令版本必须与被控端的 SIGNAL_VERSION 精确相等，不相等时被控端直接拒绝。
const signalVersion = 10

// maxSignalMsg 是信令帧的负载上限，与被控端的 MAX_SIGNAL_MSG 一致。
const maxSignalMsg = 64 << 10

// 角色：被控端是 0，控制端是 1。
const roleHost = 0

// ClientMsg 的变体编号。编号是线上的类型，不能改。
const (
	msgRegister = 1
	msgRelease  = 3
	msgRekey    = 4
)

// ServerMsg 的变体编号。
const (
	msgRegistered = 1
	msgRekeyed    = 5
)

// errFrame 表示长度前缀本身不合法。
var errFrame = errors.New("信令帧格式不正确")

// errUnknownMsg 表示消息本身的变体不认识。按被控端的兼容规则，这种消息整条
// 跳过，不断开连接；帧有长度，跳过不会错位。
var errUnknownMsg = errors.New("不认识的信令消息")

// readFrame 读一个长度前缀帧（u32 小端长度 + 负载）。
// 对端正好在帧边界处关闭时返回 io.EOF。
func readFrame(r io.Reader, max int) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint32(prefix[:]))
	if n < 0 || n > max {
		return nil, errFrame
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeFrame 写一个长度前缀帧。
func writeFrame(w io.Writer, payload []byte) error {
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(payload)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// helloMsg 是 ClientHello：版本、角色、本机名称与系统。
type helloMsg struct {
	version uint16
	role    uint64
	name    string
	os      string
}

// decodeHello 解析 ClientHello。后面多出来的字段直接忽略：新版本被控端加了
// 字段时数组会变长，旧的服务端仍然能读。
func decodeHello(b []byte) (helloMsg, error) {
	var h helloMsg
	r := newCBReader(b)
	n, err := r.array()
	if err != nil || n < 4 {
		return h, errCBOR
	}
	version, err := r.uint()
	if err != nil {
		return h, err
	}
	h.version = uint16(version)
	if h.role, err = r.uint(); err != nil {
		return h, err
	}
	if h.name, err = r.text(); err != nil {
		return h, err
	}
	if h.os, err = r.text(); err != nil {
		return h, err
	}
	return h, nil
}

// encodeServerHello 生成 ServerHello。fileLimit 为 nil 表示不限单次粘贴的
// 字节数（我们不做文件粘贴，始终保持 nil）。
func encodeServerHello(version uint16, fileLimit *uint64) []byte {
	w := &cbWriter{}
	if fileLimit == nil {
		w.array(1)
		w.uint(uint64(version))
		return w.b
	}
	w.array(2)
	w.uint(uint64(version))
	w.uint(*fileLimit)
	return w.b
}

// reclaim 是被控端上次拿到的控制码与密钥。
type reclaim struct {
	code   uint32
	secret [16]byte
}

// clientMsg 是版本握手之后被控端发来的消息。
type clientMsg struct {
	kind    int
	reclaim *reclaim
	keep    bool
	rekey   bool
	secret  [16]byte
}

// decodeClientMsg 解析一条 ClientMsg。只有消息本身的变体不认识时返回
// errUnknownMsg，其余格式错误一律返回 errCBOR。
func decodeClientMsg(b []byte) (clientMsg, error) {
	var m clientMsg
	r := newCBReader(b)
	n, err := r.array()
	if err != nil || n < 1 {
		return m, errCBOR
	}
	variant, err := r.uint()
	if err != nil {
		return m, err
	}
	m.kind = int(variant)
	switch m.kind {
	case msgRegister:
		if n < 2 {
			return m, errCBOR
		}
		pn, err := r.array()
		if err != nil || pn < 3 {
			return m, errCBOR
		}
		if r.isNull() {
			if err := r.null(); err != nil {
				return m, err
			}
		} else {
			an, err := r.array()
			if err != nil || an < 2 {
				return m, errCBOR
			}
			code, err := r.uint()
			if err != nil {
				return m, err
			}
			sec, err := r.bytes()
			if err != nil || len(sec) != 16 {
				return m, errCBOR
			}
			rc := &reclaim{code: uint32(code)}
			copy(rc.secret[:], sec)
			m.reclaim = rc
		}
		if m.keep, err = r.boolean(); err != nil {
			return m, err
		}
		if m.rekey, err = r.boolean(); err != nil {
			return m, err
		}
	case msgRekey:
		if n < 2 {
			return m, errCBOR
		}
		pn, err := r.array()
		if err != nil || pn < 1 {
			return m, errCBOR
		}
		sec, err := r.bytes()
		if err != nil || len(sec) != 16 {
			return m, errCBOR
		}
		copy(m.secret[:], sec)
	case msgRelease:
		// 没有字段。以后加了字段也只是多几项，不读就行。
	default:
		return m, errUnknownMsg
	}
	return m, nil
}

// encodeRegistered 生成 Registered：分配给被控端的控制码与重连密钥。
func encodeRegistered(code uint32, secret [16]byte) []byte {
	w := &cbWriter{}
	w.array(2)
	w.uint(msgRegistered)
	w.array(2)
	w.uint(uint64(code))
	w.bytes(secret[:])
	return w.b
}

// encodeRekeyed 生成 Rekeyed：控制码不变，重连密钥换成这个。
func encodeRekeyed(secret [16]byte) []byte {
	w := &cbWriter{}
	w.array(2)
	w.uint(msgRekeyed)
	w.array(1)
	w.bytes(secret[:])
	return w.b
}
