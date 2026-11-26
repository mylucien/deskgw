package perfgw

import "errors"

// 这里只实现信令用到的一小部分 CBOR：定长数组、无符号整数、字节串、文本串、
// 布尔与空值。被控端的编码器（minicbor）不会产生不定长编码，也不用到负数、
// 浮点和标签，遇到它们一律拒绝，免得把解析面扩大到整个 CBOR。
//
// 额外的约束：
//   - 数组长度不能超过剩余字节数（每项至少一字节），否则一个前缀就能让这边
//     以为要读几十亿项；
//   - 字节串、文本串的长度同样不能超过剩余字节；
//   - skip 的嵌套深度有上限，防止构造出来的深层嵌套把栈打满。

const (
	cbUint  = 0
	cbBytes = 2
	cbText  = 3
	cbArray = 4
	cbMap   = 5
	cbTag   = 6
	cbOther = 7

	// cbMaxDepth 是 skip 允许的最大嵌套深度。
	cbMaxDepth = 8
)

// errCBOR 表示字节串不是本包认识的 CBOR。
var errCBOR = errors.New("CBOR 编码不正确")

// cbReader 从一段字节里顺序读取数据项。
type cbReader struct {
	b []byte
	i int
}

func newCBReader(b []byte) *cbReader { return &cbReader{b: b} }

// done 表示已经读到末尾。
func (r *cbReader) done() bool { return r.i >= len(r.b) }

func (r *cbReader) byteAt() (byte, error) {
	if r.i >= len(r.b) {
		return 0, errCBOR
	}
	c := r.b[r.i]
	r.i++
	return c, nil
}

// head 读一个数据项的头，返回主类型与参数。不定长（附加信息 31）直接拒绝。
func (r *cbReader) head() (int, uint64, error) {
	c, err := r.byteAt()
	if err != nil {
		return 0, 0, err
	}
	major := int(c >> 5)
	ai := int(c & 0x1f)
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		v, err := r.byteAt()
		if err != nil {
			return 0, 0, err
		}
		return major, uint64(v), nil
	case ai == 25:
		if r.i+2 > len(r.b) {
			return 0, 0, errCBOR
		}
		v := uint64(r.b[r.i])<<8 | uint64(r.b[r.i+1])
		r.i += 2
		return major, v, nil
	case ai == 26:
		if r.i+4 > len(r.b) {
			return 0, 0, errCBOR
		}
		v := uint64(r.b[r.i])<<24 | uint64(r.b[r.i+1])<<16 | uint64(r.b[r.i+2])<<8 | uint64(r.b[r.i+3])
		r.i += 4
		return major, v, nil
	case ai == 27:
		if r.i+8 > len(r.b) {
			return 0, 0, errCBOR
		}
		var v uint64
		for k := 0; k < 8; k++ {
			v = v<<8 | uint64(r.b[r.i+k])
		}
		r.i += 8
		return major, v, nil
	default:
		return 0, 0, errCBOR
	}
}

// array 读数组头，返回元素个数。
func (r *cbReader) array() (int, error) {
	major, n, err := r.head()
	if err != nil {
		return 0, err
	}
	if major != cbArray || n > uint64(len(r.b)-r.i) {
		return 0, errCBOR
	}
	return int(n), nil
}

// uint 读一个无符号整数。
func (r *cbReader) uint() (uint64, error) {
	major, n, err := r.head()
	if err != nil {
		return 0, err
	}
	if major != cbUint {
		return 0, errCBOR
	}
	return n, nil
}

// bytes 读一个字节串。
func (r *cbReader) bytes() ([]byte, error) {
	major, n, err := r.head()
	if err != nil {
		return nil, err
	}
	if major != cbBytes || n > uint64(len(r.b)-r.i) {
		return nil, errCBOR
	}
	out := r.b[r.i : r.i+int(n)]
	r.i += int(n)
	return out, nil
}

// text 读一个文本串。不校验 UTF-8：名称只用来显示，按原样保留。
func (r *cbReader) text() (string, error) {
	major, n, err := r.head()
	if err != nil {
		return "", err
	}
	if major != cbText || n > uint64(len(r.b)-r.i) {
		return "", errCBOR
	}
	out := string(r.b[r.i : r.i+int(n)])
	r.i += int(n)
	return out, nil
}

// boolean 读一个布尔值。
func (r *cbReader) boolean() (bool, error) {
	c, err := r.byteAt()
	if err != nil {
		return false, err
	}
	switch c {
	case 0xf5:
		return true, nil
	case 0xf4:
		return false, nil
	}
	return false, errCBOR
}

// isNull 判断下一个数据项是不是空值（不移动位置）。
func (r *cbReader) isNull() bool { return r.i < len(r.b) && r.b[r.i] == 0xf6 }

// null 读一个空值。
func (r *cbReader) null() error {
	c, err := r.byteAt()
	if err != nil {
		return err
	}
	if c != 0xf6 {
		return errCBOR
	}
	return nil
}

// skip 跳过一个完整的数据项。
func (r *cbReader) skip() error { return r.skipDepth(0) }

func (r *cbReader) skipDepth(depth int) error {
	if depth > cbMaxDepth {
		return errCBOR
	}
	major, n, err := r.head()
	if err != nil {
		return err
	}
	switch major {
	case cbUint, cbOther:
		// 头里的参数已经把整个数据项读完了。
		return nil
	case cbBytes, cbText:
		if n > uint64(len(r.b)-r.i) {
			return errCBOR
		}
		r.i += int(n)
		return nil
	case cbArray:
		if n > uint64(len(r.b)-r.i) {
			return errCBOR
		}
		for k := uint64(0); k < n; k++ {
			if err := r.skipDepth(depth + 1); err != nil {
				return err
			}
		}
		return nil
	case cbMap:
		if n > uint64(len(r.b)-r.i)/2 {
			return errCBOR
		}
		for k := uint64(0); k < n*2; k++ {
			if err := r.skipDepth(depth + 1); err != nil {
				return err
			}
		}
		return nil
	default: // cbTag：标签号已读走，后面还跟一个数据项
		return r.skipDepth(depth + 1)
	}
}

// cbWriter 拼一段 CBOR。
type cbWriter struct {
	b []byte
}

func (w *cbWriter) head(major int, n uint64) {
	switch {
	case n < 24:
		w.b = append(w.b, byte(major<<5)|byte(n))
	case n <= 0xff:
		w.b = append(w.b, byte(major<<5)|24, byte(n))
	case n <= 0xffff:
		w.b = append(w.b, byte(major<<5)|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		w.b = append(w.b, byte(major<<5)|26,
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		w.b = append(w.b, byte(major<<5)|27,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func (w *cbWriter) uint(v uint64) { w.head(cbUint, v) }

func (w *cbWriter) bytes(p []byte) {
	w.head(cbBytes, uint64(len(p)))
	w.b = append(w.b, p...)
}

func (w *cbWriter) text(s string) {
	w.head(cbText, uint64(len(s)))
	w.b = append(w.b, s...)
}

func (w *cbWriter) array(n int) { w.head(cbArray, uint64(n)) }

func (w *cbWriter) boolean(v bool) {
	if v {
		w.b = append(w.b, 0xf5)
	} else {
		w.b = append(w.b, 0xf4)
	}
}

func (w *cbWriter) null() { w.b = append(w.b, 0xf6) }
