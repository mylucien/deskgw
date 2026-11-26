package perfgw

// 一次性连接票据。浏览器先带登录态换票据，再拿票据开 WebSocket：
// 票据只活 30 秒、只能用一个、绑定发起 IP，避免 WebSocket 的 URL 被
// 别人拿走就能用（同源 Cookie 在跨站请求里带不过去，票据是第二道）。

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ErrTicket 表示票据不存在、已使用、已过期或来源 IP 不符。
var ErrTicket = errors.New("连接票据无效")

// Ticket 是一次性连接票据，绑定用户、主机、会话与发起 IP。
type Ticket struct {
	UserID    int64
	HostID    int64
	SessionID int64
	ClientIP  string
	ExpiresAt time.Time
}

// TicketManager 在内存中保存短时票据。
type TicketManager struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]*Ticket
}

// NewTicketManager 创建票据管理器，ttl 为有效期，非法值按 30 秒。
func NewTicketManager(ttl time.Duration) *TicketManager {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	m := &TicketManager{ttl: ttl, items: make(map[string]*Ticket)}
	go m.janitor()
	return m
}

// Issue 签发票据，token 是 32 字节随机串的 URL 安全编码。
func (m *TicketManager) Issue(userID, hostID, sessionID int64, clientIP string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	m.mu.Lock()
	m.items[tok] = &Ticket{
		UserID: userID, HostID: hostID, SessionID: sessionID,
		ClientIP: clientIP, ExpiresAt: time.Now().Add(m.ttl),
	}
	m.mu.Unlock()
	return tok, nil
}

// Consume 校验并立即销毁票据。校验内容含有效期与来源 IP。
func (m *TicketManager) Consume(token, clientIP string) (*Ticket, error) {
	if token == "" {
		return nil, ErrTicket
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.items[token]
	if !ok {
		return nil, ErrTicket
	}
	delete(m.items, token)
	if time.Now().After(t.ExpiresAt) || t.ClientIP != clientIP {
		return nil, ErrTicket
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
