package perfgw

// 控制台接入点的单元测试：票据、名额、占位符、错误映射与密钥包格式。
// 真正的握手与转发在 relay_test.go 与 session_test.go 里测。

import (
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTicketOneShot 票据只能用一次，且绑定来源 IP。
func TestTicketOneShot(t *testing.T) {
	m := NewTicketManager(time.Minute)
	tok, err := m.Issue(1, 2, 3, "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Consume(tok, "10.0.0.6"); !errors.Is(err, ErrTicket) {
		t.Fatalf("换一个 IP 还接受了: %v", err)
	}
	// 上面那次已经销毁票据，正确 IP 也用不了。
	if _, err := m.Consume(tok, "10.0.0.5"); !errors.Is(err, ErrTicket) {
		t.Fatalf("票据被用了两次: %v", err)
	}
	tok, _ = m.Issue(1, 2, 3, "10.0.0.5")
	tk, err := m.Consume(tok, "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if tk.UserID != 1 || tk.HostID != 2 || tk.SessionID != 3 {
		t.Fatalf("票据内容不对: %+v", tk)
	}
}

// TestTicketExpired 过期票据不能被消费。
func TestTicketExpired(t *testing.T) {
	m := NewTicketManager(time.Minute)
	tok, _ := m.Issue(1, 2, 3, "10.0.0.5")
	m.mu.Lock()
	m.items[tok].ExpiresAt = time.Now().Add(-time.Second)
	m.mu.Unlock()
	if _, err := m.Consume(tok, "10.0.0.5"); !errors.Is(err, ErrTicket) {
		t.Fatalf("过期票据还接受了: %v", err)
	}
}

// TestLimitsPerHost 一台主机默认只允许一个会话，全局满了拒绝其他主机。
func TestLimitsPerHost(t *testing.T) {
	l := NewLimits(2, 1)
	if err := l.acquire(7); err != nil {
		t.Fatal(err)
	}
	if err := l.acquire(7); !errors.Is(err, errHostBusy) {
		t.Fatalf("同主机第二个会话应当被拒: %v", err)
	}
	if err := l.acquire(8); err != nil {
		t.Fatal(err)
	}
	if err := l.acquire(9); !errors.Is(err, errFull) {
		t.Fatalf("全局名额满了还放行: %v", err)
	}
	l.release(7)
	if err := l.acquire(9); err != nil {
		t.Fatalf("释放后应当能再占: %v", err)
	}
	total, hosts := l.counts()
	if total != 2 || hosts[8] != 1 || hosts[9] != 1 || hosts[7] != 0 {
		t.Fatalf("计数不对: %d %v", total, hosts)
	}
}

// TestLimitsSet 后台把上限调小不会踢掉已有会话，但新连接按新值判断。
func TestLimitsSet(t *testing.T) {
	l := NewLimits(4, 2)
	_ = l.acquire(1)
	_ = l.acquire(1)
	l.Set(1, 1)
	if err := l.acquire(2); !errors.Is(err, errFull) {
		t.Fatalf("调小之后还放行: %v", err)
	}
	l.release(1)
	l.release(1)
	if err := l.acquire(2); err != nil {
		t.Fatalf("名额空出来还拒绝: %v", err)
	}
	// 非法值退回默认。
	l.Set(-1, 99)
	if _, per := l.counts(); per[2] != 1 {
		t.Fatalf("计数不对: %v", per)
	}
}

// TestParseHostRef 只接受 h<正整数>，其余一律拒绝。
func TestParseHostRef(t *testing.T) {
	for _, in := range []string{"h1", "h4294967295"} {
		if _, err := parseHostRef(in); err != nil {
			t.Fatalf("%q 应当合法: %v", in, err)
		}
	}
	for _, in := range []string{"", "1", "H1", "h", "h0", "h-1", "h1x", "x1"} {
		if _, err := parseHostRef(in); err == nil {
			t.Fatalf("%q 应当被拒", in)
		}
	}
	if id, _ := parseHostRef("h42"); id != 42 {
		t.Fatalf("解析结果不对: %d", id)
	}
}

// TestErrorKind 错误映射决定浏览器显示哪句提示，改错会让人排查错方向。
func TestErrorKind(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{errHostOffline, "codeNotFound"},
		{errNotApproved, "codeNotFound"},
		{errHostBusy, "hostBusy"},
		{errFull, "limit"},
		{errKeyChanged, "hostKeyChanged"},
		{errPairingRequired, "pairingRequired"},
		{errVersion, "incompatible"},
		{errNoise, "incompatible"},
		{errors.New("拨号超时"), "serverError"},
	}
	for _, c := range cases {
		if got := errorKind(c.err); got != c.want {
			t.Fatalf("%v → %s，期望 %s", c.err, got, c.want)
		}
	}
	// 被控端拒绝时的包装错误也要认出来。
	if got := errorKind(refusalError(refusalPairingRequired)); got != "pairingRequired" {
		t.Fatalf("配对原因没识别出来: %s", got)
	}
}

// TestBuildKeyBundle ready 里的密钥必须是 32 字节的十六进制，计数起点按 4.9：
// 控制通道两个方向都从 1 开始，数据报与视频从 0 开始。
func TestBuildKeyBundle(t *testing.T) {
	k := &sessionKeys{safety: "123-456"}
	for i := 0; i < keyLen; i++ {
		k.control[0][i] = 0x11
		k.control[1][i] = 0x22
		k.datagram[0][i] = 0x33
		k.datagram[1][i] = 0x44
	}
	for lane := 0; lane < videoStreams; lane++ {
		var key [keyLen]byte
		key[0] = byte(lane)
		k.video = append(k.video, key)
	}
	b := buildKeyBundle(k)
	if len(b.ControlSend) != 2*keyLen || b.ControlSend[:2] != "11" {
		t.Fatalf("控制发送密钥不对: %s", b.ControlSend)
	}
	if b.ControlRecvCounter != 1 || b.ControlSendCounter != 1 {
		t.Fatalf("控制通道计数起点不对: %+v", b)
	}
	if b.DatagramRecvCounter != 0 || b.DatagramSendCounter != 0 {
		t.Fatalf("数据报计数起点不对: %+v", b)
	}
	if len(b.Video) != videoStreams {
		t.Fatalf("视频密钥数量不对: %d", len(b.Video))
	}
	raw, err := hex.DecodeString(b.Video[2])
	if err != nil || len(raw) != keyLen || raw[0] != 2 {
		t.Fatalf("第 2 路视频密钥不对: %v %x", err, raw)
	}
	// wipe 之后路由器手里不再有可用的密钥。
	k.wipe()
	if k.control[0] != ([keyLen]byte{}) || k.hash != nil {
		t.Fatal("wipe 没有清干净")
	}
}

// TestConsoleRejectsBadTicket 没票据、票据对不上用户都要在升级之前拒绝。
func TestConsoleRejectsBadTicket(t *testing.T) {
	c := NewConsole(nil, NewTicketManager(time.Minute), NewLimits(1, 1))
	var ended, audited int
	c.End = func(int64, string, string) { ended++ }
	c.Audit = func(int64, string, string, string, string) { audited++ }

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/perf?ticket=nope", nil)
	c.Serve(rec, req, ConsoleClient{UserID: 1, ClientIP: "10.0.0.5"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无票据应当是 401: %d", rec.Code)
	}

	tok, _ := c.Tickets().Issue(2, 3, 4, "10.0.0.5")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/ws/perf?ticket="+tok, nil)
	c.Serve(rec, req, ConsoleClient{UserID: 1, ClientIP: "10.0.0.5"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("票据用户不符应当是 403: %d", rec.Code)
	}
	if ended != 0 || audited != 0 {
		t.Fatalf("升级之前失败不该动会话记录: ended=%d audited=%d", ended, audited)
	}
}

// TestConsoleUpgradeFailsCleanly 票据有效但主机不可用时，要收尾会话记录。
func TestConsoleUpgradeFailsCleanly(t *testing.T) {
	c := NewConsole(nil, NewTicketManager(time.Minute), NewLimits(1, 1))
	c.Host = func(int64) (HostInfo, error) { return HostInfo{}, errors.New("没有这台主机") }
	var state, detail string
	c.End = func(_ int64, s, d string) { state, detail = s, d }
	c.Audit = func(int64, string, string, string, string) {}

	tok, _ := c.Tickets().Issue(1, 3, 4, "10.0.0.5")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/perf?ticket="+tok, nil)
	c.Serve(rec, req, ConsoleClient{UserID: 1, ClientIP: "10.0.0.5"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("主机不存在应当是 404: %d", rec.Code)
	}
	if state != "failed" || detail != "codeNotFound" {
		t.Fatalf("会话记录没收尾: %s %s", state, detail)
	}
}
