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
	// argonParallel 是并发 argon2 计算的上限，见 argonSlots。
	argonParallel = 2
	saltLen       = 16
	tokenLen      = 32

	maxFailures  = 5
	lockDuration = 10 * time.Minute

	// maxIPFailures 是同一来源 IP 在锁定期内允许的失败总数（跨用户名）。
	// 用户名维度可以靠随机用户名灌满，IP 维度是第二道闸门：
	// 攻击者可以换用户名，但换不掉来源地址。
	maxIPFailures = 50

	// maxFailureKeys 是每张计数表的软上限。键是「IP|用户名」，
	// 攻击者可以用随机用户名制造无限增长，因此必须设上限并在后台清理。
	maxFailureKeys = 4096
	// maxFailureKeysHard 是硬上限：软上限只淘汰未锁定条目，
	// 涨到硬上限才会动锁定中的条目。灌表挤掉别人锁定的成本因此翻倍。
	maxFailureKeysHard = maxFailureKeys * 2

	// failureWindow 是失败计数的有效期。没有它，一年多以前累计的 4 次失败
	// 会和今天的一次输入凑成锁定：正常用户偶发输错也会被逐渐推向锁定，
	// 而且永远无法恢复。窗口外重新计数。
	failureWindow = 15 * time.Minute
)

// argonSlots 限制同时进行的 argon2 计算数量。每次校验要占约 19MB 内存，
// 路由器可用内存有限：不设上限时，几十个并发登录请求就能把进程打到 OOM。
// 排队比 OOM 好——请求方只是变慢，服务不会整体崩掉。
var argonSlots = make(chan struct{}, argonParallel)

// acquire 占用一个 argon2 计算名额，返回释放函数。
func acquire() func() {
	argonSlots <- struct{}{}
	return func() { <-argonSlots }
}

// HashPassword 生成 argon2id 编码串：$argon2id$v=19$m=...,t=...,p=1$<salt>$<hash>
func HashPassword(password string) (string, error) {
	defer acquire()()

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
	defer acquire()()
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
	mu         sync.Mutex
	sessions   map[string]*Session
	failures   map[string]*failure
	ipFailures map[string]*failure
	idle       time.Duration
}

// NewManager 创建会话管理器。
func NewManager(idleMinutes int) *Manager {
	m := &Manager{
		sessions:   make(map[string]*Session),
		failures:   make(map[string]*failure),
		ipFailures: make(map[string]*failure),
		idle:       time.Duration(idleMinutes) * time.Minute,
	}
	go m.janitor()
	return m
}

// janitor 定期清理已解锁的失败计数和已过期的登录会话。
// 只依赖 Get() 的惰性删除不够：从不再次访问的会话会一直留在内存里。
func (m *Manager) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		m.pruneFailuresLocked()
		m.pruneSessionsLocked()
		m.mu.Unlock()
	}
}

func (m *Manager) pruneSessionsLocked() {
	now := time.Now()
	for tok, s := range m.sessions {
		if now.Sub(s.LastSeen) > m.idle {
			delete(m.sessions, tok)
		}
	}
}

func (m *Manager) pruneFailuresLocked() {
	m.pruneTableLocked(m.failures)
	m.pruneTableLocked(m.ipFailures)
}

// pruneTableLocked 删除已经解锁且不再计数的条目。
func (m *Manager) pruneTableLocked(table map[string]*failure) {
	now := time.Now()
	for k, f := range table {
		if f.count == 0 && !f.lockedUntil.IsZero() && !now.Before(f.lockedUntil) {
			delete(table, k)
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

// RevokeUser 注销某个用户的全部登录会话，返回注销数量。
// 用户被停用、删除或降权时调用，避免旧会话继续以缓存角色访问接口。
func (m *Manager) RevokeUser(userID int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for tok, s := range m.sessions {
		if s.UserID == userID {
			delete(m.sessions, tok)
			n++
		}
	}
	return n
}

// Locked 判断某个键（IP+用户名）是否处于锁定状态。
// 只有真正锁定过（lockedUntil 非零）且尚未到期才返回 true；
// 计数阶段的记录必须保留，否则永远攒不满 5 次失败。
func (m *Manager) Locked(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return lockedIn(m.failures, key)
}

// LockedIP 判断来源 IP 是否因跨用户名的失败总量被锁定。
func (m *Manager) LockedIP(ip string) bool {
	if ip == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return lockedIn(m.ipFailures, ip)
}

// lockedIn 在已持锁的前提下判断条目是否仍在锁定期内，顺便清掉过期的。
func lockedIn(table map[string]*failure, key string) bool {
	f := table[key]
	if f == nil {
		return false
	}
	if f.lockedUntil.IsZero() {
		return false
	}
	if time.Now().Before(f.lockedUntil) {
		return true
	}
	delete(table, key)
	return false
}

// Fail 记录一次失败，达到阈值后锁定。
func (m *Manager) Fail(key string) {
	m.FailFrom(key, "")
}

// FailFrom 同时记录「IP|用户名」与来源 IP 两个维度的失败。
func (m *Manager) FailFrom(key, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.bumpLocked(m.failures, key, maxFailures, now)
	if ip != "" {
		m.bumpLocked(m.ipFailures, ip, maxIPFailures, now)
	}
}

func (m *Manager) bumpLocked(table map[string]*failure, key string, threshold int, now time.Time) {
	if key == "" {
		return
	}
	f := table[key]
	if f == nil {
		if len(table) >= maxFailureKeys {
			m.pruneTableLocked(table)
			if len(table) >= maxFailureKeys {
				// 先只淘汰未锁定的条目；只有涨到硬上限才动锁定中的，
				// 否则灌满表就能把别人正在生效的锁定挤掉。
				if !evictOldest(table, false) && len(table) >= maxFailureKeysHard {
					evictOldest(table, true)
				}
			}
		}
		f = &failure{}
		table[key] = f
	} else if f.count > 0 && now.Sub(f.last) > failureWindow {
		// 计数太旧：重新开始，不让几年前的失败叠加到这次上。
		f.count = 0
	}
	f.last = now
	f.count++
	if f.count >= threshold {
		f.lockedUntil = now.Add(lockDuration)
		f.count = 0
	}
}

// evictOldest 淘汰最久未活动的条目。includeLocked 为 false 时跳过仍在
// 锁定期的条目，保证攻击者无法用新键把别人的锁定挤出去。
func evictOldest(table map[string]*failure, includeLocked bool) bool {
	now := time.Now()
	var oldestKey string
	var oldest time.Time
	for k, f := range table {
		if !includeLocked && !f.lockedUntil.IsZero() && now.Before(f.lockedUntil) {
			continue
		}
		if oldestKey == "" || f.last.Before(oldest) {
			oldestKey, oldest = k, f.last
		}
	}
	if oldestKey == "" {
		return false
	}
	delete(table, oldestKey)
	return true
}

// Clear 清除某键的失败记录。
func (m *Manager) Clear(key string) {
	m.mu.Lock()
	delete(m.failures, key)
	m.mu.Unlock()
}

// ClearIP 清除来源 IP 的跨用户名失败计数。
// 登录成功说明这个出口不是攻击来源，继续累计只会误伤同一 NAT 后的其他人。
func (m *Manager) ClearIP(ip string) {
	if ip == "" {
		return
	}
	m.mu.Lock()
	delete(m.ipFailures, ip)
	m.mu.Unlock()
}

// RevokeUserExcept 注销某个用户的登录会话，但保留 keepToken。
// 用户改自己的密码时用它：其余设备上的旧登录要失效，当前这台不该被踢出去。
func (m *Manager) RevokeUserExcept(userID int64, keepToken string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for tok, s := range m.sessions {
		if s.UserID == userID && tok != keepToken {
			delete(m.sessions, tok)
			n++
		}
	}
	return n
}

// ActiveSessions 返回当前会话数，供后台状态页使用。
func (m *Manager) ActiveSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}
