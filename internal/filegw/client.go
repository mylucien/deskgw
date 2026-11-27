package filegw

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"
)

// maxConns 限制同时存在的 SMB 连接数。每次文件操作都会新建连接，
// 大文件分片上传会瞬时打满，必须设上限保护路由器与目标主机。
const maxConns = 24

// idleTimeout 是单次 SMB 读写的空闲上限。
//
// Connect 只给拨号与挂载设了超时，之后会把 deadline 清掉；目标主机卡住
// （休眠、网络分区、安全软件拦截）时，读写会永久阻塞，一条连接就长期占着
// 全局 24 个名额之一，几十次之后整个文件功能不可用。每次读写前把期限往后
// 推一段，只要还有进展就不会误杀。
const idleTimeout = 60 * time.Second

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
	// 显式构造 UNC 路径。go-smb2 在只传共享名时会拿 TCP 对端地址拼路径，而
	// RemoteAddr 带端口，最终变成 `\\192.168.1.213:445\C$`；这个字符串会进
	// 目标机的安全软件日志，多出来的端口让拦截记录难以辨认。
	sh, err := sess.Mount(fmt.Sprintf(`\\%s\%s`, address, share))
	if err != nil {
		sess.Logoff()
		tcp.Close()
		return nil, mountError(share, err)
	}
	_ = tcp.SetDeadline(time.Time{})
	release = false
	return &Conn{
		tcp: tcp, session: sess, share: sh,
		release: func() { <-connSlots },
	}, nil
}

// mountError 把挂载阶段的失败翻译成用户能看懂的原因。这一步的连接重置几乎都
// 来自目标机的安全软件：隐藏共享（C$、ADMIN$ 等以 $ 结尾的名字）是横向渗透
// 防护的重点目标，被拦下时对方直接重置连接，客户端只能看到 connection reset。
func mountError(share string, err error) error {
	if !isConnReset(err) {
		return fmt.Errorf("挂载共享失败: %w", err)
	}
	if strings.HasSuffix(share, "$") {
		return fmt.Errorf("挂载共享失败: %w（%s 是隐藏共享，目标机的安全软件常以「横向渗透防护」拦截这类访问，请改用普通共享名，或把本机加入该软件的信任列表）", err, share)
	}
	return fmt.Errorf("挂载共享失败: %w（目标机在挂载阶段断开了连接，常见原因是安全软件拦截或 SMB 服务异常）", err)
}

// isConnReset 判断错误链里是否包含 TCP 连接被重置。go-smb2 会在错误文本里
// 保留底层 net 错误，但 ConnectionError 没有实现 Unwrap，两种方式都试一遍。
func isConnReset(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return strings.Contains(err.Error(), "connection reset by peer")
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

// touch 把读写期限推到 idleTimeout 之后。
func (c *Conn) touch() {
	if c.tcp != nil {
		_ = c.tcp.SetDeadline(time.Now().Add(idleTimeout))
	}
}

// File 是 *smb2.File 的薄包装：每次读写前把连接的空闲期限往后推，
// 让卡死的目标机在 idleTimeout 后报错而不是一直挂着。
type File struct {
	f *smb2.File
	c *Conn
}

func (f *File) Read(p []byte) (int, error) {
	f.c.touch()
	return f.f.Read(p)
}

func (f *File) Write(p []byte) (int, error) {
	f.c.touch()
	return f.f.Write(p)
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	f.c.touch()
	return f.f.Seek(offset, whence)
}

func (f *File) Stat() (os.FileInfo, error) {
	f.c.touch()
	return f.f.Stat()
}

func (f *File) Close() error {
	// 关闭不清 deadline：Close 也可能阻塞，让它受同一个上限约束。
	f.c.touch()
	return f.f.Close()
}

// List 返回目录下的条目。
func (c *Conn) List(dir string) ([]Entry, error) {
	c.touch()
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
	c.touch()
	return c.share.Stat(path)
}

// OpenRead 以只读方式打开文件，供下载流式读取。
func (c *Conn) OpenRead(path string) (*File, error) {
	c.touch()
	f, err := c.share.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return &File{f: f, c: c}, nil
}

// OpenWrite 打开文件用于写入。offset>0 时不截断，用于断点续传。
func (c *Conn) OpenWrite(path string, offset int64) (*File, error) {
	c.touch()
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
	return &File{f: f, c: c}, nil
}

// Mkdir 创建目录。
func (c *Conn) Mkdir(path string) error {
	c.touch()
	return c.share.Mkdir(path, 0777)
}

// Rename 重命名文件或目录。
func (c *Conn) Rename(oldPath, newPath string) error {
	c.touch()
	return c.share.Rename(oldPath, newPath)
}

// Remove 删除文件或空目录。
func (c *Conn) Remove(path string) error {
	c.touch()
	return c.share.Remove(path)
}
