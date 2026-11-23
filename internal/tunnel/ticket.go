// Package tunnel 实现 RDP 连接票据与 WS↔TCP 字节转发。
package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Ticket 是一次性连接票据，绑定用户、主机、会话与发起 IP。
type Ticket struct {
	Token     string
	UserID    int64
	HostID    int64
	SessionID int64
	ClientIP  string
	ExpiresAt time.Time
}

// ErrTicketInvalid 表示票据不存在、已使用、已过期或来源 IP 不符。
var ErrTicketInvalid = errors.New("连接票据无效")

// TicketManager 在内存中保存短时票据。
type TicketManager struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]*Ticket
}

// NewTicketManager 创建票据管理器，ttl 为票据有效期。
func NewTicketManager(ttl time.Duration) *TicketManager {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	m := &TicketManager{ttl: ttl, items: make(map[string]*Ticket)}
	go m.janitor()
	return m
}

// Issue 签发票据。token 为 32 字节随机串的 URL 安全编码。
func (m *TicketManager) Issue(userID, hostID, sessionID int64, clientIP string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[tok] = &Ticket{
		Token: tok, UserID: userID, HostID: hostID, SessionID: sessionID,
		ClientIP: clientIP, ExpiresAt: time.Now().Add(m.ttl),
	}
	return tok, nil
}

// Consume 校验并立即销毁票据。校验内容含有效期与来源 IP。
func (m *TicketManager) Consume(token, clientIP string) (*Ticket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.items[token]
	if !ok {
		return nil, ErrTicketInvalid
	}
	delete(m.items, token)
	if time.Now().After(t.ExpiresAt) || t.ClientIP != clientIP {
		return nil, ErrTicketInvalid
	}
	cp := *t
	return &cp, nil
}

func (m *TicketManager) janitor() {
	ticker := time.NewTicker(m.ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for k, t := range m.items {
			if now.After(t.ExpiresAt) {
				delete(m.items, k)
			}
		}
		m.mu.Unlock()
	}
}
