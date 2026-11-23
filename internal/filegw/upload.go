package filegw

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"
)

// ErrUploadOffset 表示分片偏移与已写入位置不一致。
var ErrUploadOffset = errors.New("分片偏移不连续，请重新上传")

// Upload 是一次分片上传会话：整条上传复用同一条 SMB 连接与文件句柄，
// 避免每个 4MiB 分片都重新做一次 TCP + NTLM 认证（2GiB 约 512 次）。
type Upload struct {
	conn   *Conn
	file   *smb2.File
	mu     sync.Mutex
	offset int64
	closed bool
}

// BeginUpload 建立上传会话并创建（截断）目标文件。
func BeginUpload(address string, port int, share, path string, creds Credentials) (*Upload, error) {
	conn, err := Connect(address, port, share, creds)
	if err != nil {
		return nil, err
	}
	f, err := conn.OpenWrite(path, 0)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Upload{conn: conn, file: f}, nil
}

// Offset 返回已写入字节数。
func (u *Upload) Offset() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.offset
}

// WriteChunk 从 r 读取至多 limit 字节写入文件。offset 必须等于当前偏移。
// 返回实际写入量；调用方负责在写入后再判断是否还有多余数据。
func (u *Upload) WriteChunk(offset int64, r io.Reader, limit int64) (int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, errors.New("上传会话已关闭")
	}
	if offset != u.offset {
		return 0, ErrUploadOffset
	}
	if limit < 0 {
		limit = 0
	}
	n, err := io.Copy(u.file, io.LimitReader(r, limit))
	u.offset += n
	return n, err
}

// Close 关闭文件与连接。重复调用安全。
func (u *Upload) Close() {
	if u == nil {
		return
	}
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.closed = true
	f := u.file
	u.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
	u.conn.Close()
}

type uploadEntry struct {
	up        *Upload
	userID    int64
	hostID    int64
	sessionID int64
	lastUsed  time.Time
}

// UploadManager 保存进行中的分片上传，按空闲时间回收。
type UploadManager struct {
	mu    sync.Mutex
	items map[string]*uploadEntry
	ttl   time.Duration
}

// NewUploadManager 构造上传会话管理器。ttl 为无活动回收时间。
func NewUploadManager(ttl time.Duration) *UploadManager {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	m := &UploadManager{items: make(map[string]*uploadEntry), ttl: ttl}
	go m.janitor()
	return m
}

// Add 登记一条上传会话，返回随机 ID。
func (m *UploadManager) Add(up *Upload, userID, hostID, sessionID int64) (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	m.mu.Lock()
	m.items[id] = &uploadEntry{
		up: up, userID: userID, hostID: hostID, sessionID: sessionID,
		lastUsed: time.Now(),
	}
	m.mu.Unlock()
	return id, nil
}

// Get 取出上传会话并校验归属与关联会话。
func (m *UploadManager) Get(id string, userID, sessionID int64) (*Upload, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.items[id]
	if !ok || e.userID != userID || e.sessionID != sessionID {
		return nil, false
	}
	e.lastUsed = time.Now()
	return e.up, true
}

// Drop 关闭并移除上传会话。
func (m *UploadManager) Drop(id string) {
	m.mu.Lock()
	e, ok := m.items[id]
	delete(m.items, id)
	m.mu.Unlock()
	if ok {
		e.up.Close()
	}
}

// RevokeSession 关闭某个远程会话的全部上传。
func (m *UploadManager) RevokeSession(sessionID int64) {
	m.mu.Lock()
	var drop []*Upload
	for id, e := range m.items {
		if e.sessionID == sessionID {
			drop = append(drop, e.up)
			delete(m.items, id)
		}
	}
	m.mu.Unlock()
	for _, up := range drop {
		up.Close()
	}
}

func (m *UploadManager) janitor() {
	interval := m.ttl / 2
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		var drop []*Upload
		for id, e := range m.items {
			if now.Sub(e.lastUsed) > m.ttl {
				drop = append(drop, e.up)
				delete(m.items, id)
			}
		}
		m.mu.Unlock()
		for _, up := range drop {
			up.Close()
		}
	}
}
