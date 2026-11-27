package filegw

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

// ErrUploadOffset 表示分片偏移与已写入位置不一致。
var ErrUploadOffset = errors.New("分片偏移不连续，请重新上传")

// ErrTooManyUploads 表示并发上传会话已达上限。
var ErrTooManyUploads = errors.New("同时进行的上传过多，请先完成或取消其他上传")

// 上传会话的并发上限。全局 SMB 名额只有 24 个（client.go 的 maxConns），
// begin 不限量的话，一个用户可以全部占满，其他人的列表、下载、上传都会失败。
const (
	maxUploadsPerUser = 3
	maxUploadsGlobal  = 16
)

// Upload 是一次分片上传会话：整条上传复用同一条 SMB 连接与文件句柄，
// 避免每个 4MiB 分片都重新做一次 TCP + NTLM 认证（2GiB 约 512 次）。
//
// 数据先写到同目录的临时文件，finish 时再改名到目标路径：直接截断目标
// 文件的话，上传中途断开会把用户原有文件变成残缺文件。
type Upload struct {
	conn   *Conn
	file   *File
	share  string
	final  string
	tmp    string
	mu     sync.Mutex
	offset int64
	// size 是 begin 时调用方声明的文件大小。-1 表示未声明（旧接口），
	// finish 时按实际写入量提交。
	size   int64
	closed bool
}

// BeginUpload 建立上传会话，在目标目录下创建临时文件。
// 返回的 exists 表示目标文件已经存在，调用方据此决定是否需要用户确认覆盖。
func BeginUpload(address string, port int, share, path string, size int64, creds Credentials) (*Upload, bool, error) {
	conn, err := Connect(address, port, share, creds)
	if err != nil {
		return nil, false, err
	}
	exists := false
	if info, err := conn.Stat(path); err == nil && info != nil && !info.IsDir() {
		exists = true
	}
	tmp := tempName(path)
	f, err := conn.OpenWrite(tmp, 0)
	if err != nil {
		conn.Close()
		return nil, false, err
	}
	return &Upload{conn: conn, file: f, share: share, final: path, tmp: tmp, size: size}, exists, nil
}

// Size 返回 begin 时声明的大小，-1 表示未声明。
func (u *Upload) Size() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.size
}

// tempName 生成同目录下的临时文件名，带随机后缀避免并发上传互相覆盖。
func tempName(path string) string {
	var tag [4]byte
	_, _ = rand.Read(tag[:])
	suffix := ".deskgw-" + hex.EncodeToString(tag[:]) + ".part"
	if len(path)+len(suffix) <= 240 {
		return path + suffix
	}
	// Windows 单个文件名上限 255 字节；超长时截断基名，保留目录。
	dir, base := "", path
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		dir, base = path[:i+1], path[i+1:]
	}
	keep := 240 - len(dir) - len(suffix)
	if keep < 1 {
		keep = 1
	}
	if len(base) > keep {
		// 不切断多字节字符。
		for keep > 0 && base[keep]&0xC0 == 0x80 {
			keep--
		}
		base = base[:keep]
	}
	return dir + base + suffix
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

// ShareName 返回上传所在的共享名，供审计使用。
func (u *Upload) ShareName() string { return u.share }

// TargetPath 返回 begin 时确定的目标路径。审计必须取这里的值，
// 不能用 finish 请求体里的 path，否则调用方可以伪造审计记录。
func (u *Upload) TargetPath() string { return u.final }

// Commit 关闭临时文件并把它改名到目标路径。
//
// Windows 的 SMB rename 不覆盖已存在文件。原实现先删目标再改名：改名失败
// （权限、目标被占用、磁盘满）时 discardLocked 会把临时文件也删掉，新旧文件
// 一起消失。现在改成「把旧文件挪成备份 → 改名 → 删备份」：任何一步失败都能
// 把旧文件放回原处，最多留下一个 .deskgw-bak 文件。
func (u *Upload) Commit() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return errors.New("上传会话已关闭")
	}
	u.closed = true
	if u.file != nil {
		err := u.file.Close()
		u.file = nil
		if err != nil {
			u.discardLocked()
			return err
		}
	}
	var backup string
	if _, err := u.conn.share.Stat(u.final); err == nil {
		backup = tempName(u.final) + ".bak"
		if err := u.conn.share.Rename(u.final, backup); err != nil {
			u.discardLocked()
			return err
		}
	}
	if err := u.conn.share.Rename(u.tmp, u.final); err != nil {
		if backup != "" {
			// 放回旧文件；失败也只能把备份留下，至少数据还在。
			_ = u.conn.share.Rename(backup, u.final)
		}
		u.discardLocked()
		return err
	}
	if backup != "" {
		_ = u.conn.share.Remove(backup)
	}
	u.tmp = ""
	u.conn.Close()
	return nil
}

// discardLocked 删除临时文件并释放连接。调用方必须持有 u.mu。
func (u *Upload) discardLocked() {
	if u.tmp != "" {
		_ = u.conn.share.Remove(u.tmp)
		u.tmp = ""
	}
	u.conn.Close()
}

// Close 丢弃未完成的上传并释放连接。重复调用安全。
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
	u.file = nil
	u.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
	if u.tmp != "" {
		_ = u.conn.share.Remove(u.tmp)
		u.tmp = ""
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

// Add 登记一条上传会话，返回随机 ID。超出并发上限时返回 ErrTooManyUploads，
// 调用方负责关闭已经建立的 SMB 连接。
func (m *UploadManager) Add(up *Upload, userID, hostID, sessionID int64) (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.items) >= maxUploadsGlobal {
		return "", ErrTooManyUploads
	}
	perUser := 0
	for _, e := range m.items {
		if e.userID == userID {
			perUser++
		}
	}
	if perUser >= maxUploadsPerUser {
		return "", ErrTooManyUploads
	}
	m.items[id] = &uploadEntry{
		up: up, userID: userID, hostID: hostID, sessionID: sessionID,
		lastUsed: time.Now(),
	}
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
