package tunnel

import (
	"errors"
	"fmt"
)

// RDCleanPath 版本号：3389 + 1。
const cleanPathVersion = 3390

// ASN.1 DER 标签。
const (
	tagSequence    = 0x30
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagUTF8String  = 0x0c
)

// CleanPathRequest 是浏览器发来的 RDCleanPath 请求。
// Destination 仅作解析，绝不用作连接目标；目标地址一律来自数据库。
type CleanPathRequest struct {
	Destination       string
	ProxyAuth         string
	PreconnectionBlob string
	X224Connection    []byte
}

// derTLV 是一个 DER 元素。
type derTLV struct {
	Tag   byte
	Value []byte
}

// derLength 编码 DER 长度字段。
func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for v := n; v > 0; v >>= 8 {
		tmp = append([]byte{byte(v & 0xff)}, tmp...)
	}
	return append([]byte{byte(0x80 | len(tmp))}, tmp...)
}

// derWrap 用给定标签包裹内容。
func derWrap(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derLength(len(content))...)
	return append(out, content...)
}

// derContext 用上下文标签 [n]（EXPLICIT）包裹内容。
func derContext(n int, content []byte) []byte {
	return derWrap(byte(0xa0+n), content)
}

// derInteger 编码非负整数。
func derInteger(v int) []byte {
	if v == 0 {
		return derWrap(tagInteger, []byte{0})
	}
	var tmp []byte
	for x := v; x > 0; x >>= 8 {
		tmp = append([]byte{byte(x & 0xff)}, tmp...)
	}
	if tmp[0]&0x80 != 0 {
		tmp = append([]byte{0}, tmp...)
	}
	return derWrap(tagInteger, tmp)
}

// derOctet 编码字节串。
func derOctet(b []byte) []byte { return derWrap(tagOctetString, b) }

// derUTF8 编码 UTF-8 字符串。
func derUTF8(s string) []byte { return derWrap(tagUTF8String, []byte(s)) }

// derReadOne 从 data[offset:] 读取一个 TLV，返回元素、消耗字节数。
func derReadOne(data []byte, offset int) (derTLV, int, error) {
	if offset >= len(data) {
		return derTLV{}, 0, errors.New("DER 数据为空")
	}
	tag := data[offset]
	if offset+1 >= len(data) {
		return derTLV{}, 0, errors.New("DER 长度字段缺失")
	}
	first := data[offset+1]
	var length, header int
	if first < 0x80 {
		length = int(first)
		header = 2
	} else {
		n := int(first & 0x7f)
		if n == 0 || n > 4 {
			return derTLV{}, 0, errors.New("DER 长度格式不支持")
		}
		if offset+2+n > len(data) {
			return derTLV{}, 0, errors.New("DER 长度字段被截断")
		}
		length = 0
		for i := 0; i < n; i++ {
			length = (length << 8) | int(data[offset+2+i])
		}
		header = 2 + n
	}
	start := offset + header
	end := start + length
	if end > len(data) {
		return derTLV{}, 0, errors.New("DER 内容被截断")
	}
	return derTLV{Tag: tag, Value: data[start:end]}, end - offset, nil
}

// derChildren 解析构造类型内的所有子元素。
func derChildren(data []byte) ([]derTLV, error) {
	out := []derTLV{}
	for off := 0; off < len(data); {
		tlv, used, err := derReadOne(data, off)
		if err != nil {
			return nil, err
		}
		if used <= 0 {
			return nil, errors.New("DER 元素长度为零")
		}
		out = append(out, tlv)
		off += used
	}
	return out, nil
}

// derIntValue 读取 INTEGER 的值（非负、不超过 4 字节）。
func derIntValue(b []byte) (int, error) {
	if len(b) == 0 || len(b) > 4 {
		return 0, errors.New("DER INTEGER 长度非法")
	}
	v := 0
	for _, x := range b {
		v = (v << 8) | int(x)
	}
	return v, nil
}

// parseCleanPathRequest 解析浏览器发来的 RDCleanPath 请求。
func parseCleanPathRequest(data []byte) (CleanPathRequest, error) {
	var req CleanPathRequest
	outer, _, err := derReadOne(data, 0)
	if err != nil {
		return req, err
	}
	if outer.Tag != tagSequence {
		return req, fmt.Errorf("期望 SEQUENCE，实际 0x%02x", outer.Tag)
	}
	children, err := derChildren(outer.Value)
	if err != nil {
		return req, err
	}
	for _, child := range children {
		ctx := int(child.Tag & 0x1f)
		inner, _, err := derReadOne(child.Value, 0)
		if err != nil {
			return req, fmt.Errorf("解析上下文 [%d] 失败: %w", ctx, err)
		}
		switch ctx {
		case 0:
			v, err := derIntValue(inner.Value)
			if err != nil || v != cleanPathVersion {
				return req, fmt.Errorf("RDCleanPath 版本不支持: %d", v)
			}
		case 2:
			req.Destination = string(inner.Value)
		case 3:
			req.ProxyAuth = string(inner.Value)
		case 5:
			req.PreconnectionBlob = string(inner.Value)
		case 6:
			req.X224Connection = append([]byte(nil), inner.Value...)
		}
	}
	if len(req.X224Connection) == 0 {
		return req, errors.New("请求缺少 x224_connection_pdu")
	}
	return req, nil
}

// buildCleanPathResponse 构造 RDCleanPath 响应，携带 X.224 确认与服务器证书链。
func buildCleanPathResponse(serverAddr string, x224Response []byte, certChain [][]byte) []byte {
	certOctets := []byte{}
	for _, der := range certChain {
		certOctets = append(certOctets, derOctet(der)...)
	}
	parts := []byte{}
	parts = append(parts, derContext(0, derInteger(cleanPathVersion))...)
	parts = append(parts, derContext(6, derOctet(x224Response))...)
	parts = append(parts, derContext(7, derWrap(tagSequence, certOctets))...)
	parts = append(parts, derContext(9, derUTF8(serverAddr))...)
	return derWrap(tagSequence, parts)
}

// buildCleanPathError 构造 RDCleanPath 错误响应。
func buildCleanPathError(code, httpStatus int) []byte {
	errParts := []byte{}
	errParts = append(errParts, derContext(0, derInteger(code))...)
	errParts = append(errParts, derContext(1, derInteger(httpStatus))...)
	parts := []byte{}
	parts = append(parts, derContext(0, derInteger(cleanPathVersion))...)
	parts = append(parts, derContext(1, derWrap(tagSequence, errParts))...)
	return derWrap(tagSequence, parts)
}
