package auth

import (
	"testing"
	"time"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	enc, err := HashPassword("s3cret-密码")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(enc, "s3cret-密码") {
		t.Fatal("正确密码应校验通过")
	}
	if VerifyPassword(enc, "s3cret-密码 ") {
		t.Fatal("错误密码不应通过")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	// 依次为：空串、明文、段数不足、算法不符、参数不合法、salt 非 base64、哈希为空
	bad := []string{
		"",
		"plain-text",
		"$argon2id$v=19$m=1,t=1,p=1$c2FsdA",
		"$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=x,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=1,t=1,p=1$!!!$aGFzaA",
		"$argon2id$v=19$m=1,t=1,p=1$c2FsdA$",
	}
	for _, s := range bad {
		if VerifyPassword(s, "whatever") {
			t.Fatalf("格式非法的哈希不应通过: %q", s)
		}
	}
}

// 计数阶段不能被判定为锁定，否则永远攒不满 5 次失败（历史缺陷）。
func TestLockOnlyAfterThreshold(t *testing.T) {
	m := NewManager(30)
	const key = "10.0.0.1|admin"
	for i := 0; i < maxFailures-1; i++ {
		m.Fail(key)
		if m.Locked(key) {
			t.Fatalf("第 %d 次失败不应锁定", i+1)
		}
	}
	m.Fail(key)
	if !m.Locked(key) {
		t.Fatal("达到阈值后应锁定")
	}
	m.Clear(key)
	if m.Locked(key) {
		t.Fatal("Clear 后应立即解锁")
	}
}

func TestFailureCountIsPerKey(t *testing.T) {
	m := NewManager(30)
	for i := 0; i < maxFailures; i++ {
		m.Fail("10.0.0.1|admin")
	}
	if !m.Locked("10.0.0.1|admin") {
		t.Fatal("该键应被锁定")
	}
	if m.Locked("10.0.0.2|admin") {
		t.Fatal("其他来源 IP 不应受影响")
	}
}

func TestRevokeUser(t *testing.T) {
	m := NewManager(30)
	t1, err := m.Create(1, "alice", "user")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t2, err := m.Create(1, "alice", "user")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t3, err := m.Create(2, "bob", "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n := m.RevokeUser(1); n != 2 {
		t.Fatalf("应注销 2 个会话，实际 %d", n)
	}
	for _, tok := range []string{t1, t2} {
		if _, ok := m.Get(tok); ok {
			t.Fatal("被注销用户的会话仍然有效")
		}
	}
	if _, ok := m.Get(t3); !ok {
		t.Fatal("其他用户的会话不应被牵连")
	}
}

func TestIdleExpiryAndPrune(t *testing.T) {
	m := NewManager(1)
	tok, err := m.Create(1, "alice", "user")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// 直接改 LastSeen 模拟长时间未访问，避免测试里真等一分钟
	m.mu.Lock()
	m.sessions[tok].LastSeen = time.Now().Add(-2 * time.Minute)
	m.mu.Unlock()
	if _, ok := m.Get(tok); ok {
		t.Fatal("超过空闲上限的会话不应通过校验")
	}
	if m.ActiveSessions() != 0 {
		t.Fatal("过期会话应被惰性删除")
	}

	tok2, err := m.Create(1, "alice", "user")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.mu.Lock()
	m.sessions[tok2].LastSeen = time.Now().Add(-2 * time.Minute)
	m.pruneSessionsLocked()
	left := len(m.sessions)
	m.mu.Unlock()
	if left != 0 {
		t.Fatalf("清理任务应删除过期会话，剩余 %d", left)
	}
}

func TestSetIdleIgnoresNonPositive(t *testing.T) {
	m := NewManager(30)
	m.SetIdle(0)
	m.SetIdle(-1)
	if got := m.Idle(); got != 30*time.Minute {
		t.Fatalf("非正的空闲值应被忽略，实际 %v", got)
	}
	m.SetIdle(5)
	if got := m.Idle(); got != 5*time.Minute {
		t.Fatalf("空闲值未更新，实际 %v", got)
	}
}
