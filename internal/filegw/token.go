// Package filegw 实现 SMB 文件网关：短期文件令牌、内存中凭据与流式文件操作。
package filegw

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Credentials 是一次文件会话使用的 Windows 凭据，仅驻留内存。
type Credentials struct {
	Username string
	Password string
	Domain   string
}

// Wipe 在会话结束时清除内存中的明文密码。
func (c *Credentials) Wipe() {
	if c == nil {
		return
	}
	for i := range c.Password {
		c.Password = c.Password[:i] + "\x00" + c.Password[i+1:]
	}
	c.Password = ""
	c.Username = ""
	c.Domain = ""
}

// fileToken 保存一条文件会话的状态。
type fileToken struct {
	secret    string
	userID    int64
	hostID    int64
	sessionID int64
	clientIP  string
	creds     Credentials
	expires   time.Time
}

// TokenManager 管理短期文件令牌。凭据只存在这里，不落盘、不写日志。
type TokenManager struct {
	mu     sync.Mutex
	tokens map[string]*fileToken
	ttl    time.Duration
}

// NewTokenManager 构造令牌管理器。
func NewTokenManager(ttl time.Duration) *TokenManager {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	m := &TokenManager{tokens: map[string]*fileToken{}, ttl: ttl}
	go m.janitor()
	return m
}

// janitor 定期清理过期令牌，确保其中的明文凭据不会因无人访问而长期驻留内存。
func (m *TokenManager) janitor() {
	interval := m.ttl / 2
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		m.pruneLocked()
		m.mu.Unlock()
	}
}

var (
	// ErrInvalidToken 表示令牌不存在、过期或来源 IP 不匹配。
	ErrInvalidToken = errors.New("文件令牌无效或已过期")
)

// Issue 签发一个文件令牌，绑定用户、主机、会话与来源 IP。
func (m *TokenManager) Issue(userID, hostID, sessionID int64, ip string, creds Credentials) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[secret] = &fileToken{
		secret: secret, userID: userID, hostID: hostID, sessionID: sessionID,
		clientIP: ip, creds: creds, expires: time.Now().Add(m.ttl),
	}
	return secret, nil
}

// Resolve 校验令牌并返回其绑定的上下文与凭据副本。
// 每次访问都会续期，避免长时间浏览目录时令牌过期。
func (m *TokenManager) Resolve(secret, ip string) (userID, hostID, sessionID int64, creds Credentials, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[secret]
	if !ok {
		return 0, 0, 0, Credentials{}, ErrInvalidToken
	}
	if time.Now().After(t.expires) || t.clientIP != ip {
		m.dropLocked(secret)
		return 0, 0, 0, Credentials{}, ErrInvalidToken
	}
	t.expires = time.Now().Add(m.ttl)
	return t.userID, t.hostID, t.sessionID, t.creds, nil
}

// Revoke 撤销令牌并清除明文凭据。
func (m *TokenManager) Revoke(secret string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropLocked(secret)
}

// RevokeSession 撤销某会话的全部令牌，在 RDP 会话结束时调用。
func (m *TokenManager) RevokeSession(sessionID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for secret, t := range m.tokens {
		if t.sessionID == sessionID {
			m.dropLocked(secret)
		}
	}
}

// Count 返回当前有效令牌数（运行状态用）。
func (m *TokenManager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	return len(m.tokens)
}

func (m *TokenManager) dropLocked(secret string) {
	if t, ok := m.tokens[secret]; ok {
		t.creds.Wipe()
		delete(m.tokens, secret)
	}
}

func (m *TokenManager) pruneLocked() {
	now := time.Now()
	for secret, t := range m.tokens {
		if now.After(t.expires) {
			m.dropLocked(secret)
		}
	}
}
