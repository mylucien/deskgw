package perfgw

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// 下面这些向量取自 Airhand v0.4.0 的 crates/airhand-proto/tests/v10.rs，
// 是被控端实际走线时的字节。改这里就等于改协议，必须同时核对上游。

func TestDecodeClientHello(t *testing.T) {
	h, err := decodeHello(mustHex(t, "840a006250436157"))
	if err != nil {
		t.Fatal(err)
	}
	if h.version != 10 || h.role != roleHost || h.name != "PC" || h.os != "W" {
		t.Fatalf("解析结果 %+v", h)
	}
}

func TestDecodeClientHelloSkipsExtraFields(t *testing.T) {
	// 数组多一项（模拟新版本被控端加了字段），前四项照旧。
	h, err := decodeHello(mustHex(t, "850a00625043615700"))
	if err != nil {
		t.Fatal(err)
	}
	if h.name != "PC" || h.os != "W" {
		t.Fatalf("解析结果 %+v", h)
	}
}

func TestEncodeServerHello(t *testing.T) {
	if got := hex.EncodeToString(encodeServerHello(signalVersion, nil)); got != "810a" {
		t.Fatalf("不限文件：%s", got)
	}
	zero := uint64(0)
	if got := hex.EncodeToString(encodeServerHello(signalVersion, &zero)); got != "820a00" {
		t.Fatalf("文件上限 0：%s", got)
	}
}

func TestDecodeRegister(t *testing.T) {
	m, err := decodeClientMsg(mustHex(t, "820183f6f5f4"))
	if err != nil {
		t.Fatal(err)
	}
	if m.kind != msgRegister || m.reclaim != nil || !m.keep || m.rekey {
		t.Fatalf("解析结果 %+v", m)
	}
}

func TestDecodeRegisterWithReclaim(t *testing.T) {
	// [1, [[123456, h'0707…], false, false]]
	vec := "820183821a0001e24050" + strings.Repeat("07", 16) + "f4f4"
	m, err := decodeClientMsg(mustHex(t, vec))
	if err != nil {
		t.Fatal(err)
	}
	if m.kind != msgRegister || m.reclaim == nil {
		t.Fatalf("解析结果 %+v", m)
	}
	if m.reclaim.code != 123456 {
		t.Fatalf("控制码 %d", m.reclaim.code)
	}
	for _, b := range m.reclaim.secret {
		if b != 7 {
			t.Fatalf("密钥 %v", m.reclaim.secret)
		}
	}
	if m.keep || m.rekey {
		t.Fatalf("keep/rekey 解析结果 %+v", m)
	}
}

func TestDecodeRekey(t *testing.T) {
	vec := "82048150" + strings.Repeat("07", 16)
	m, err := decodeClientMsg(mustHex(t, vec))
	if err != nil {
		t.Fatal(err)
	}
	if m.kind != msgRekey {
		t.Fatalf("类型 %d", m.kind)
	}
	for _, b := range m.secret {
		if b != 7 {
			t.Fatalf("密钥 %v", m.secret)
		}
	}
}

func TestDecodeRelease(t *testing.T) {
	m, err := decodeClientMsg(mustHex(t, "8103"))
	if err != nil {
		t.Fatal(err)
	}
	if m.kind != msgRelease {
		t.Fatalf("类型 %d", m.kind)
	}
}

func TestDecodeUnknownMessage(t *testing.T) {
	// Connect 是控制端的消息（变体 2），被控端不会发；不认识的整条跳过。
	_, err := decodeClientMsg(mustHex(t, "820284071a0001e240f6420102"))
	if !errors.Is(err, errUnknownMsg) {
		t.Fatalf("期望 errUnknownMsg，得到 %v", err)
	}
}

func TestEncodeRegistered(t *testing.T) {
	secret := [16]byte{}
	for i := range secret {
		secret[i] = 7
	}
	want := "8201821a0001e24050" + strings.Repeat("07", 16)
	if got := hex.EncodeToString(encodeRegistered(123456, secret)); got != want {
		t.Fatalf("得到 %s", got)
	}
	// 待批准的控制码在 0x40000000 以上，要写成 4 字节参数。
	if got := hex.EncodeToString(encodeRegistered(pendingCodeBase, secret)); !strings.HasPrefix(got, "8201821a40000000") {
		t.Fatalf("得到 %s", got)
	}
}

func TestEncodeRekeyed(t *testing.T) {
	// 注意方向：Rekey 是被控端发的（变体 4），Rekeyed 是服务端回的（变体 5）。
	secret := [16]byte{}
	for i := range secret {
		secret[i] = 7
	}
	want := "82058150" + strings.Repeat("07", 16)
	if got := hex.EncodeToString(encodeRekeyed(secret)); got != want {
		t.Fatalf("得到 %s", got)
	}
}

func TestRegistryClaim(t *testing.T) {
	g := newRegistry()
	now := time.Now().Unix()
	a, err := g.claim(nil, "PC1", "Windows 11", "192.168.1.20", now)
	if err != nil {
		t.Fatal(err)
	}
	if a.code < pendingCodeBase {
		t.Fatalf("待批准记录的控制码 %d 落在了主机 id 区间", a.code)
	}
	b, err := g.claim(nil, "PC2", "Windows 11", "192.168.1.21", now)
	if err != nil {
		t.Fatal(err)
	}
	if a.code == b.code {
		t.Fatal("两次接入拿到了同一个控制码")
	}
	// 带对的控制码与密钥重连：取回同一个控制码。
	again, err := g.claim(&reclaim{code: a.code, secret: a.secret}, "PC1", "Windows 11", "192.168.1.20", now+5)
	if err != nil {
		t.Fatal(err)
	}
	if again.code != a.code {
		t.Fatalf("重连拿到了新控制码 %d", again.code)
	}
	// 密钥不对：当作新设备，换一个控制码。
	wrong := &reclaim{code: a.code}
	other, err := g.claim(wrong, "PC3", "Windows 11", "192.168.1.22", now+6)
	if err != nil {
		t.Fatal(err)
	}
	if other.code == a.code {
		t.Fatal("密钥不对时不应该取回原控制码")
	}
	if n := len(g.list()); n != 3 {
		t.Fatalf("待批准记录 %d 条", n)
	}
}

func TestRegistryReap(t *testing.T) {
	g := newRegistry()
	now := time.Now().Unix()
	p, err := g.claim(nil, "PC", "Windows", "192.168.1.20", now)
	if err != nil {
		t.Fatal(err)
	}
	// 在线的不清理。
	g.setOnline(p.code, true)
	if n := g.reap(now+3600, 60); n != 0 {
		t.Fatalf("清理了在线的记录 %d 条", n)
	}
	g.setOnline(p.code, false)
	if n := g.reap(now+3600, 60); n != 1 {
		t.Fatalf("清理了 %d 条", n)
	}
	if n := len(g.list()); n != 0 {
		t.Fatalf("还剩 %d 条", n)
	}
}
