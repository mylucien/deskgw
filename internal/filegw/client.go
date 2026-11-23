package filegw

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"
)

// maxConns 限制同时存在的 SMB 连接数。每次文件操作都会新建连接，
// 大文件分片上传会瞬时打满，必须设上限保护路由器与目标主机。
const maxConns = 24

var connSlots = make(chan struct{}, maxConns)

// ErrTooManyConns 表示并发 SMB 连接已达上限。
var ErrTooManyConns = errors.New("文件连接数已达上限，请稍后重试")

// Entry 是文件列表中的一项。
type Entry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
}

// Conn 是一次 SMB 连接的句柄。每次文件操作新建连接、用完即关，
// 凭据不缓存、不复用，降低明文驻留时间。
type Conn struct {
	tcp     net.Conn
	session *smb2.Session
	share   *smb2.Share
	once    sync.Once
	release func()
}

// Connect 用给定凭据连接目标主机的共享。address 来自数据库，前端无法指定。
func Connect(address string, port int, share string, creds Credentials) (*Conn, error) {
	select {
	case connSlots <- struct{}{}:
	default:
		return nil, ErrTooManyConns
	}
	release := true
	defer func() {
		if release {
			<-connSlots
		}
	}()

	target := net.JoinHostPort(address, strconv.Itoa(port))
	tcp, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接 SMB 服务失败: %w", err)
	}
	// Dial 与 Mount 都可能因对端不响应而无限挂起，统一用总超时兜底。
	_ = tcp.SetDeadline(time.Now().Add(20 * time.Second))
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     creds.Username,
			Password: string(creds.Password),
			Domain:   creds.Domain,
		},
	}
	sess, err := d.Dial(tcp)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("SMB 认证失败: %w", err)
	}
	sh, err := sess.Mount(share)
	if err != nil {
		sess.Logoff()
		tcp.Close()
		return nil, fmt.Errorf("挂载共享失败: %w", err)
	}
	_ = tcp.SetDeadline(time.Time{})
	release = false
	return &Conn{
		tcp: tcp, session: sess, share: sh,
		release: func() { <-connSlots },
	}, nil
}

// Close 释放共享、会话与 TCP 连接，并归还并发名额。
func (c *Conn) Close() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		// 关闭阶段同样不能无限等待：对端失联时 Umount 可能一直阻塞。
		_ = c.tcp.SetDeadline(time.Now().Add(3 * time.Second))
		if c.share != nil {
			_ = c.share.Umount()
		}
		if c.session != nil {
			_ = c.session.Logoff()
		}
		if c.tcp != nil {
			_ = c.tcp.Close()
		}
		if c.release != nil {
			c.release()
		}
	})
}

// List 返回目录下的条目。
func (c *Conn) List(dir string) ([]Entry, error) {
	infos, err := c.share.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(infos))
	for _, info := range infos {
		if info == nil || info.Name() == "." || info.Name() == ".." {
			continue
		}
		out = append(out, Entry{
			Name: info.Name(), IsDir: info.IsDir(),
			Size: info.Size(), ModTime: info.ModTime().Unix(),
		})
	}
	return out, nil
}

// Stat 返回文件信息。
func (c *Conn) Stat(path string) (os.FileInfo, error) {
	return c.share.Stat(path)
}

// OpenRead 以只读方式打开文件，供下载流式读取。
func (c *Conn) OpenRead(path string) (*smb2.File, error) {
	return c.share.OpenFile(path, os.O_RDONLY, 0)
}

// OpenWrite 打开文件用于写入。offset>0 时不截断，用于断点续传。
func (c *Conn) OpenWrite(path string, offset int64) (*smb2.File, error) {
	flag := os.O_WRONLY | os.O_CREATE
	if offset == 0 {
		flag |= os.O_TRUNC
	}
	f, err := c.share.OpenFile(path, flag, 0666)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, 0); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}

// Mkdir 创建目录。
func (c *Conn) Mkdir(path string) error { return c.share.Mkdir(path, 0777) }

// Rename 重命名文件或目录。
func (c *Conn) Rename(oldPath, newPath string) error {
	return c.share.Rename(oldPath, newPath)
}

// Remove 删除文件或空目录。
func (c *Conn) Remove(path string) error { return c.share.Remove(path) }
