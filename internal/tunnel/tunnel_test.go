package tunnel

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestTrimReasonShort(t *testing.T) {
	if got := trimReason("连接被重置"); got != "连接被重置" {
		t.Fatalf("短原因不应被改动: %q", got)
	}
}

func TestTrimReasonASCII(t *testing.T) {
	got := trimReason(strings.Repeat("a", 500))
	if len(got) != 120 {
		t.Fatalf("应截断到 120 字节，实际 %d", len(got))
	}
}

// close 帧的 reason 有长度上限，截断时不能把多字节字符切成两半。
func TestTrimReasonUTF8Boundary(t *testing.T) {
	cases := []string{
		strings.Repeat("测", 60),       // 180 字节，截断点正好落在字符边界
		"a" + strings.Repeat("测", 60), // 截断点落在字符中间，必须回退
		strings.Repeat("😀", 40),       // 4 字节字符
	}
	for _, s := range cases {
		got := trimReason(s)
		if len(got) > 120 {
			t.Fatalf("截断结果超长: %d", len(got))
		}
		if !utf8.ValidString(got) {
			t.Fatalf("截断结果不是合法 UTF-8: %q", got)
		}
		if !strings.HasPrefix(s, got) {
			t.Fatal("截断结果应为原串前缀")
		}
	}
}

func TestTicketConsumeOnce(t *testing.T) {
	m := NewTicketManager(time.Minute)
	tok, err := m.Issue(7, 21, 99, "192.168.1.5")
	if err != nil {
		t.Fatalf("签发票据失败: %v", err)
	}
	tk, err := m.Consume(tok, "192.168.1.5")
	if err != nil {
		t.Fatalf("首次消费应成功: %v", err)
	}
	if tk.UserID != 7 || tk.HostID != 21 || tk.SessionID != 99 {
		t.Fatalf("票据内容不符: %+v", tk)
	}
	if _, err := m.Consume(tok, "192.168.1.5"); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("票据应一次性，实际 %v", err)
	}
}

func TestTicketRejectsOtherIP(t *testing.T) {
	m := NewTicketManager(time.Minute)
	tok, err := m.Issue(1, 2, 3, "10.0.0.2")
	if err != nil {
		t.Fatalf("签发票据失败: %v", err)
	}
	if _, err := m.Consume(tok, "10.0.0.3"); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("来源 IP 不符应拒绝，实际 %v", err)
	}
	// 校验失败也必须销毁票据，避免被反复尝试
	if _, err := m.Consume(tok, "10.0.0.2"); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("失败消费后票据应已销毁，实际 %v", err)
	}
}

func TestTicketExpires(t *testing.T) {
	m := NewTicketManager(20 * time.Millisecond)
	tok, err := m.Issue(1, 2, 3, "10.0.0.2")
	if err != nil {
		t.Fatalf("签发票据失败: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := m.Consume(tok, "10.0.0.2"); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("过期票据应拒绝，实际 %v", err)
	}
}

func TestTicketUnknownToken(t *testing.T) {
	m := NewTicketManager(time.Minute)
	if _, err := m.Consume("no-such-token", "10.0.0.2"); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("未知票据应拒绝，实际 %v", err)
	}
}

// 新连接只收掉「同一用户 + 同一主机」的旧隧道：别的目标、别的用户、
// 以及它自己都要留着。按主机关闭会把别人正在用的会话一起踢掉。
func TestSupersedeHost(t *testing.T) {
	g := NewGateway(nil, nil, nil, nil)
	var closed []int64
	mk := func(id, hostID, userID int64) {
		e := &liveSession{id: id, hostID: hostID, userID: userID}
		e.closeFn = func() { closed = append(closed, id) }
		g.addLive(e)
	}
	mk(1, 100, 7) // 同一用户、同一主机的旧隧道，应被关闭
	mk(2, 100, 7) // 本次新连接，应保留
	mk(3, 200, 7) // 其他主机，应保留
	mk(4, 100, 8) // 另一个用户连同一台主机，应保留

	if n := g.supersedeHost(100, 7, 2); n != 1 {
		t.Fatalf("应关闭 1 条同用户同主机旧隧道，实际 %d", n)
	}
	if len(closed) != 1 || closed[0] != 1 {
		t.Fatalf("应只关闭 id=1，实际 %v", closed)
	}
}
