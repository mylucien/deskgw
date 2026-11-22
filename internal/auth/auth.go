// Package auth 实现密码哈希、服务端会话、CSRF 与登录限流。
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB，约 19MB，适配路由器
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
	tokenLen     = 32

	maxFailures  = 5
	lockDuration = 10 * time.Minute

	// maxFailureKeys 限制失败计数表的条目数。键是「IP|用户名」，
	// 攻击者可以用随机用户名制造无限增长，因此必须设上限并在后台清理。
	maxFailureKeys = 4096
)

// HashPassword 生成 argon2id 编码串：$argon2id$v=19$m=...,t=...,p=1$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword 校验密码，格式不合法时返回 false。
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Session 是登录态。
type Session struct {
	Token    string
	UserID   int64
	Username string
	Role     string
	LastSeen time.Time
}

type failure struct {
	count       int
	lockedUntil time.Time
	last        time.Time
}

// Manager 管理会话与失败计数，全部在内存中。
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	failures map[string]*failure
	idle     time.Duration
}

// NewManager 创建会话管理器。
func NewManager(idleMinutes int) *Manager {
	m := &Manager{
		sessions: make(map[string]*Session),
		failures: make(map[string]*failure),
		idle:     time.Duration(idleMinutes) * time.Minute,
	}
	go m.janitor()
	return m
}

// janitor 定期清理已解锁的失败计数，避免长期运行后表持续增长。
func (m *Manager) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		m.pruneFailuresLocked()
		m.mu.Unlock()
	}
}

func (m *Manager) pruneFailuresLocked() {
	now := time.Now()
	for k, f := range m.failures {
		if f.count == 0 && !f.lockedUntil.IsZero() && !now.Before(f.lockedUntil) {
			delete(m.failures, k)
		}
	}
}

// SetIdle 运行时更新会话空闲超时；非正值忽略。
func (m *Manager) SetIdle(minutes int) {
	if minutes <= 0 {
		return
	}
	m.mu.Lock()
	m.idle = time.Duration(minutes) * time.Minute
	m.mu.Unlock()
}

// Idle 返回当前会话空闲超时。
func (m *Manager) Idle() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.idle
}

// RandomToken 生成 URL 安全的随机串。
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Create 为用户创建会话。
func (m *Manager) Create(userID int64, username, role string) (string, error) {
	for i := 0; i < 5; i++ {
		tok := RandomToken(tokenLen)
		m.mu.Lock()
		if _, exists := m.sessions[tok]; !exists {
			m.sessions[tok] = &Session{
				Token: tok, UserID: userID, Username: username,
				Role: role, LastSeen: time.Now(),
			}
			m.mu.Unlock()
			return tok, nil
		}
		m.mu.Unlock()
	}
	return "", errors.New("生成会话令牌失败")
}

// Get 返回仍有效的会话并滑动续期。
func (m *Manager) Get(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[token]
	if !ok {
		return nil, false
	}
	if time.Since(s.LastSeen) > m.idle {
		delete(m.sessions, token)
		return nil, false
	}
	cp := *s
	cp.LastSeen = time.Now()
	m.sessions[token] = &cp
	return &cp, true
}

// Delete 销毁会话。
func (m *Manager) Delete(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

// Locked 判断某个键（IP+用户名）是否处于锁定状态。
// 只有真正锁定过（lockedUntil 非零）且尚未到期才返回 true；
// 计数阶段的记录必须保留，否则永远攒不满 5 次失败。
func (m *Manager) Locked(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.failures[key]
	if f == nil {
		return false
	}
	if f.lockedUntil.IsZero() {
		return false
	}
	if time.Now().Before(f.lockedUntil) {
		return true
	}
	delete(m.failures, key)
	return false
}

// Fail 记录一次失败，达到阈值后锁定。
func (m *Manager) Fail(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	f := m.failures[key]
	if f == nil {
		if len(m.failures) >= maxFailureKeys {
			m.pruneFailuresLocked()
			if len(m.failures) >= maxFailureKeys {
				m.evictOldestLocked()
			}
		}
		f = &failure{}
		m.failures[key] = f
	}
	f.last = now
	f.count++
	if f.count >= maxFailures {
		f.lockedUntil = now.Add(lockDuration)
		f.count = 0
	}
}

// evictOldestLocked 在计数表达到上限时淘汰最久未活动的条目。
func (m *Manager) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, f := range m.failures {
		if oldestKey == "" || f.last.Before(oldest) {
			oldestKey, oldest = k, f.last
		}
	}
	if oldestKey != "" {
		delete(m.failures, oldestKey)
	}
}

// Clear 清除某键的失败记录。
func (m *Manager) Clear(key string) {
	m.mu.Lock()
	delete(m.failures, key)
	m.mu.Unlock()
}

// ActiveSessions 返回当前会话数，供后台状态页使用。
func (m *Manager) ActiveSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}
