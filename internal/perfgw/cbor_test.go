package perfgw

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("坏的测试向量 %q: %v", s, err)
	}
	return b
}

func TestCBORHead(t *testing.T) {
	cases := []struct {
		hex  string
		want uint64
	}{
		{"00", 0},
		{"17", 23},
		{"1818", 24},
		{"18ff", 255},
		{"190100", 256},
		{"1a00010000", 65536},
		{"1b0000000100000000", 1 << 32},
	}
	for _, c := range cases {
		r := newCBReader(mustHex(t, c.hex))
		got, err := r.uint()
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if got != c.want {
			t.Fatalf("%s: 得到 %d，期望 %d", c.hex, got, c.want)
		}
		if !r.done() {
			t.Fatalf("%s: 还有剩余字节", c.hex)
		}
	}
}

func TestCBORRejects(t *testing.T) {
	if _, err := newCBReader(nil).array(); err == nil {
		t.Fatal("空字节应当报错")
	}
	if _, err := newCBReader(mustHex(t, "18")).uint(); err == nil {
		t.Fatal("缺参数应当报错")
	}
	if _, err := newCBReader(mustHex(t, "1a0001")).uint(); err == nil {
		t.Fatal("参数不完整应当报错")
	}
	if _, err := newCBReader(mustHex(t, "9f")).array(); err == nil {
		t.Fatal("不定长数组应当报错")
	}
	if _, err := newCBReader(mustHex(t, "9b0000000fffffffff")).array(); err == nil {
		t.Fatal("数组长度超过剩余字节应当报错")
	}
	if _, err := newCBReader(mustHex(t, "5b0000000fffffffff")).bytes(); err == nil {
		t.Fatal("字节串长度超过剩余字节应当报错")
	}
	if _, err := newCBReader(mustHex(t, "80")).uint(); err == nil {
		t.Fatal("数组不是整数，应当报错")
	}
}

func TestCBORSkip(t *testing.T) {
	// [1, "a", h'0102', {3: [4]}, true]
	r := newCBReader(mustHex(t, "85016161420102a1038104f5"))
	if _, err := r.array(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := r.skip(); err != nil {
			t.Fatalf("第 %d 项: %v", i, err)
		}
	}
	if !r.done() {
		t.Fatal("还有剩余字节")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != "03000000010203" {
		t.Fatalf("写到线上的字节是 %s", got)
	}
	got, err := readFrame(&buf, maxSignalMsg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("读回 %v", got)
	}
}

func TestFrameTooLarge(t *testing.T) {
	// 前缀声明 65537 字节，超过 64KiB 上限。
	r := bytes.NewReader(mustHex(t, "01000100"))
	if _, err := readFrame(r, maxSignalMsg); err == nil {
		t.Fatal("超过上限应当报错")
	}
}
