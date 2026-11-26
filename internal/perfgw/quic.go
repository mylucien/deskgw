// Package perfgw 实现性能模式的接入层：接收 Airhand 被控端的 QUIC 连接、
// 完成信令握手、把接入的主机放进待批准列表。
//
// 这里只做接入。端到端握手、会话密钥下发与密文转发在后续版本接入，路由器
// 不解密画面，也不解析视频。
package perfgw

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/mylucien/deskgw/internal/config"
)

// alpn 与被控端 airhand-proto 的 ALPN 一致，对不上时 QUIC 握手直接失败。
const alpn = "airhand/1"

const (
	// handshakeTimeout 覆盖「接受信令流 + 读完 Hello 与 Register」的整个过程。
	// 被控端自己在 8 秒后放弃握手，这里留一点余量。
	handshakeTimeout = 15 * time.Second
	// staleAfter 是待批准记录在离线之后保留的时长：短时间重连能取回同一个
	// 控制码，再久就重新分配。
	staleAfter = 10 * time.Minute
	// 每个来源 IP 每分钟允许的新连接数。注册接口只监听局域网，但不能假设
	// 局域网里都是善意设备。
	connBurst  = 12
	connWindow = 60
)

// pendingTTL 供清理循环使用，单位秒。
const pendingTTL = int64(staleAfter / time.Second)

// Server 是性能模式的接入端。启用之后监听一个 UDP 端口，接受被控端的 QUIC
// 连接；浏览器侧的控制台连接在后续版本接入。
type Server struct {
	cfg config.Config
	ln  *quic.Listener
	// addr 是实际监听地址。配置里写 :0 时取到的是随机端口，日志与测试都要这个。
	addr string
	reg  *registry
	fp   string
	id   *ecdh.PrivateKey
	lim  *limiter
	stop chan struct{}
	once sync.Once
	sid  atomic.Uint64
	// onPeer 在第一次（Noise XX）握手学到被控端公钥时被调用，用来记进数据库。
	// 必须在 Start 之前设置。
	onPeer func(code uint32, pub []byte)
	// onAdopt 在进程重启后判断「这个控制码与重连密钥是不是一台批准过的主机」。
	onAdopt func(code uint32, secret [16]byte) bool
	// onApproved / onSecret 把批准结果与换新的重连密钥写回数据库。
	onApproved func(hostID int64, secret [16]byte)
	onSecret   func(hostID uint32, secret [16]byte)
	// onRegister 在一台新被控端出现在待批准列表时被调用（写审计用）。
	onRegister func(p Pending)

	// conns 记录每个控制码当前挂在哪条 QUIC 连接上，用于发 Incoming 与收掉
	// 同一台主机的旧连接：浏览器直接关标签或切换网络时，旧连接可能残留到空闲超时。
	cmu   sync.Mutex
	conns map[uint32]*hostConn
}

// hostConn 是一台在线被控端的连接。
//
// 信令流只有一个读者（serve 里的循环），但写有两处：serve 回答 Rekey、
// 别的 goroutine 发 Incoming。帧是整体的，不能交叉写，所以加锁。
type hostConn struct {
	code uint32
	name string
	os   string
	ip   string
	conn *quic.Conn
	sig  *quic.Stream
	wmu  sync.Mutex

	// subs 按会话号分拣被控端新开的单向流。AcceptUniStream 是整条连接共用
	// 的，而一条连接上可能同时挂多个会话（同屏共享），所以必须在这里按流头
	// 里的会话号分发，否则两个会话会互相抢流。
	smu  sync.Mutex
	subs map[uint64]chan sessionStream
}

// sessionStream 是被控端新开的一条单向流以及它的通道号（流头已经读掉）。
type sessionStream struct {
	rs   *quic.ReceiveStream
	lane uint8
}

// subscribe 给一个会话开一条分发通道。缓冲几帧，免得接受循环被慢会话拖住。
func (h *hostConn) subscribe(sid uint64) chan sessionStream {
	ch := make(chan sessionStream, 16)
	h.smu.Lock()
	h.subs[sid] = ch
	h.smu.Unlock()
	return ch
}

// unsubscribe 注销会话，并把还没来得及取走的流取消掉。
func (h *hostConn) unsubscribe(sid uint64) {
	h.smu.Lock()
	ch, ok := h.subs[sid]
	if ok {
		delete(h.subs, sid)
	}
	h.smu.Unlock()
	if !ok {
		return
	}
	for {
		select {
		case st := <-ch:
			st.rs.CancelRead(0)
		default:
			return
		}
	}
}

// demux 把被控端新开的单向流按会话号交给对应会话；没有会话认领的直接丢弃。
func (h *hostConn) demux() {
	for {
		rs, err := h.conn.AcceptUniStream(h.conn.Context())
		if err != nil {
			return
		}
		var hdr [sessionHeaderLen]byte
		if _, err := io.ReadFull(rs, hdr[:]); err != nil {
			rs.CancelRead(0)
			continue
		}
		sid, lane, err := decodeSessionHeader(hdr[:])
		if err != nil {
			rs.CancelRead(0)
			continue
		}
		h.smu.Lock()
		ch := h.subs[sid]
		h.smu.Unlock()
		if ch == nil {
			rs.CancelRead(0)
			continue
		}
		select {
		case ch <- sessionStream{rs: rs, lane: lane}:
		default:
			// 会话侧来不及取：丢掉这一帧，比卡住整条连接好（浏览器会请求关键帧）。
			rs.CancelRead(0)
		}
	}
}

// sendSignal 往信令流写一条消息。
func (h *hostConn) sendSignal(msg []byte) error {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	return writeFrame(h.sig, msg)
}

// New 读取（或生成）证书并绑定 UDP 端口。端口占用时返回错误，是否让整个
// 网关因此启动失败由调用方决定。
func New(cfg config.Config) (*Server, error) {
	cert, fp, err := loadOrCreateCert(cfg.PerfCert, cfg.PerfKey)
	if err != nil {
		return nil, err
	}
	id, err := loadOrCreateIdentity(cfg.PerfIdentity)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", cfg.PerfListen)
	if err != nil {
		return nil, fmt.Errorf("性能模式监听地址不合法: %w", err)
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("监听 %s: %w", cfg.PerfListen, err)
	}
	ln, err := quic.Listen(pc, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		EnableDatagrams: true,
		// 被控端自己 8 秒放弃握手，这里留一点余量。
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       45 * time.Second,
		// 空闲桌面可能几十秒没有画面变化，靠 QUIC 心跳保住连接与 NAT 表项。
		KeepAlivePeriod: 20 * time.Second,
		// 每帧画面一条单向流，连续几帧同时在传是常事。
		MaxIncomingStreams:    8,
		MaxIncomingUniStreams: 64,
		// 一帧上限 32MiB，接收窗口必须容得下整帧，否则读一半就卡住。
		MaxStreamReceiveWindow:     36 << 20,
		MaxConnectionReceiveWindow: 80 << 20,
	})
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("启动 QUIC 监听: %w", err)
	}
	return &Server{
		cfg: cfg, ln: ln, addr: pc.LocalAddr().String(),
		reg: newRegistry(), fp: fp, id: id, lim: newLimiter(),
		stop: make(chan struct{}), conns: map[uint32]*hostConn{},
	}, nil
}

// Fingerprint 返回证书指纹，需要写进每台被控端的 server_fp。
func (s *Server) Fingerprint() string { return s.fp }

// Identity 返回控制端公钥（64 位小写十六进制），需要写进每台被控端
// config.toml 的 [[paired]].key。丢了私钥文件就要重新预置所有被控端。
func (s *Server) Identity() string { return identityPublic(s.id) }

// Listen 返回实际的监听地址。
func (s *Server) Listen() string { return s.addr }

// OnPeerKey 设置「学到被控端公钥」的回调。code 是主机 id（批准之后控制码
// 就等于它）。必须在 Start 之前调用。
func (s *Server) OnPeerKey(fn func(code uint32, pub []byte)) { s.onPeer = fn }

// OnAdopt 设置「重启后认回已批准主机」的回调。返回 true 表示数据库里有这台
// 主机且重连密钥一致。必须在 Start 之前调用。
func (s *Server) OnAdopt(fn func(code uint32, secret [16]byte) bool) { s.onAdopt = fn }

// OnApproved 设置批准之后持久化重连密钥的回调。必须在 Start 之前调用。
func (s *Server) OnApproved(fn func(hostID int64, secret [16]byte)) { s.onApproved = fn }

// OnSecret 设置重连密钥更换后的持久化回调（被控端本机换了控制码时会走 Rekey）。
func (s *Server) OnSecret(fn func(hostID uint32, secret [16]byte)) { s.onSecret = fn }

// OnRegister 设置「新被控端接入」的回调，用来写审计。
func (s *Server) OnRegister(fn func(p Pending)) { s.onRegister = fn }

// Start 启动接受连接与清理过期记录的循环。
func (s *Server) Start() {
	go s.accept()
	go s.reapLoop()
}

// Close 停止监听并断开所有在线被控端。
func (s *Server) Close() error {
	var err error
	s.once.Do(func() {
		close(s.stop)
		err = s.ln.Close()
		s.cmu.Lock()
		for code, hc := range s.conns {
			_ = hc.conn.CloseWithError(1, "server shutting down")
			delete(s.conns, code)
		}
		s.cmu.Unlock()
	})
	return err
}

// Pending 返回待批准列表的快照。
func (s *Server) Pending() []Pending {
	list := s.reg.list()
	out := make([]Pending, 0, len(list))
	for _, p := range list {
		out = append(out, Pending{
			Code: p.code, Name: p.name, OS: p.os, IP: p.ip,
			FirstSeen: p.firstSeen, LastSeen: p.lastSeen,
		})
	}
	return out
}

// PendingByCode 按控制码取一条待批准记录。
func (s *Server) PendingByCode(code uint32) (Pending, bool) {
	p, ok := s.reg.get(code)
	if !ok || p.approved {
		return Pending{}, false
	}
	return Pending{
		Code: p.code, Name: p.name, OS: p.os, IP: p.ip,
		FirstSeen: p.firstSeen, LastSeen: p.lastSeen,
	}, true
}

// Approve 把待批准的被控端换成正式主机：控制码改成 hosts.id，然后断开连接。
// 被控端会带着旧控制码重连，从 Registered 里拿到新的控制码并保存下来。
func (s *Server) Approve(code uint32, hostID int64) error {
	if hostID <= 0 || hostID > math.MaxUint32 {
		return errHostIDUsed
	}
	secret, err := s.reg.approve(code, uint32(hostID))
	if err != nil {
		return err
	}
	if s.onApproved != nil {
		s.onApproved(hostID, secret)
	}
	s.cmu.Lock()
	hc := s.conns[code]
	s.cmu.Unlock()
	if hc != nil {
		// 断开是让被控端重新注册、拿到新控制码的最省事的办法；
		// 被控端自己会重连（它本来就要在控制码变了之后重连）。
		_ = hc.conn.CloseWithError(0, "approved")
	}
	return nil
}

// Pending 是一条待批准记录。
type Pending struct {
	Code      uint32
	Name      string
	OS        string
	IP        string
	FirstSeen int64
	LastSeen  int64
}

func (s *Server) accept() {
	for {
		conn, err := s.ln.Accept(context.Background())
		if err != nil {
			// Accept 只在监听关闭后返回错误；这里按退出处理，不再空转重试。
			select {
			case <-s.stop:
			default:
				log.Printf("性能模式：接受连接失败: %v", err)
			}
			return
		}
		if !s.lim.allow(remoteIP(conn.RemoteAddr())) {
			_ = conn.CloseWithError(2, "too many connections")
			continue
		}
		go s.serve(conn)
	}
}

// serve 在一条 QUIC 连接上完成信令握手，之后守着信令流处理 Release / Rekey。
func (s *Server) serve(conn *quic.Conn) {
	defer conn.CloseWithError(0, "")
	ip := remoteIP(conn.RemoteAddr())

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	st, err := conn.AcceptStream(ctx)
	cancel()
	if err != nil {
		return
	}
	_ = st.SetDeadline(time.Now().Add(handshakeTimeout))

	frame, err := readFrame(st, maxSignalMsg)
	if err != nil {
		return
	}
	hello, err := decodeHello(frame)
	if err != nil {
		return
	}
	// 版本不一致也要回答，被控端按回答里的版本提示升级哪一端。
	if err := writeFrame(st, encodeServerHello(signalVersion, nil)); err != nil {
		return
	}
	if int(hello.version) != signalVersion || hello.role != roleHost {
		return
	}

	// 被控端把 Register 紧跟 Hello 发出来，不等回答。
	frame, err = readFrame(st, maxSignalMsg)
	if err != nil {
		return
	}
	msg, err := decodeClientMsg(frame)
	if err != nil || msg.kind != msgRegister {
		return
	}
	p, created, err := s.reg.claim(msg.reclaim, hello.name, hello.os, ip,
		time.Now().Unix(), s.onAdopt)
	if err != nil {
		return
	}
	if err := writeFrame(st, encodeRegistered(p.code, p.secret)); err != nil {
		return
	}
	if created && s.onRegister != nil && !p.approved {
		s.onRegister(Pending{
			Code: p.code, Name: p.name, OS: p.os, IP: p.ip,
			FirstSeen: p.firstSeen, LastSeen: p.lastSeen,
		})
	}
	_ = st.SetDeadline(time.Time{})

	hc := &hostConn{
		code: p.code, name: p.name, os: p.os, ip: ip, conn: conn, sig: st,
		subs: map[uint64]chan sessionStream{},
	}
	go hc.demux()

	s.cmu.Lock()
	old := s.conns[p.code]
	s.conns[p.code] = hc
	s.cmu.Unlock()
	if old != nil && old.conn != conn {
		_ = old.conn.CloseWithError(1, "superseded")
	}

	log.Printf("性能模式：被控端接入 %s（%s，%s），控制码 %d", p.name, p.os, ip, p.code)
	defer s.detach(p.code, conn, p.name)

	for {
		frame, err := readFrame(st, maxSignalMsg)
		if err != nil {
			return
		}
		m, err := decodeClientMsg(frame)
		if err != nil {
			if errors.Is(err, errUnknownMsg) {
				continue
			}
			return
		}
		switch m.kind {
		case msgRelease:
			s.reg.drop(p.code)
			_ = conn.CloseWithError(1, "released")
			return
		case msgRekey:
			secret, err := newSecret()
			if err != nil {
				return
			}
			s.reg.setSecret(p.code, secret)
			if p.approved && s.onSecret != nil {
				s.onSecret(p.code, secret)
			}
			if err := hc.sendSignal(encodeRekeyed(secret)); err != nil {
				return
			}
		}
	}
}

// detach 只在当前连接仍属于这个控制码时清理，避免把新连接的状态删掉。
func (s *Server) detach(code uint32, conn *quic.Conn, name string) {
	s.cmu.Lock()
	if hc := s.conns[code]; hc != nil && hc.conn == conn {
		delete(s.conns, code)
	}
	s.cmu.Unlock()
	s.reg.setOnline(code, false)
	log.Printf("性能模式：被控端离线 %s（控制码 %d）", name, code)
}

// reapLoop 周期清理长时间离线的待批准记录。
func (s *Server) reapLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-t.C:
			if n := s.reg.reap(now.Unix(), pendingTTL); n > 0 {
				log.Printf("性能模式：清理 %d 条过期的待批准记录", n)
			}
		}
	}
}

// remoteIP 取对端的 IP，去掉端口。
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// limiter 是每个来源 IP 的连接速率限制。
type limiter struct {
	mu   sync.Mutex
	seen map[string]*limitEntry
}

type limitEntry struct {
	window int64
	n      int
}

func newLimiter() *limiter { return &limiter{seen: map[string]*limitEntry{}} }

// allow 判断这个来源 IP 现在能否再建一条连接。
func (l *limiter) allow(ip string) bool {
	now := time.Now().Unix()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 1024 {
		// 局域网里的设备数有限，超过这个量只可能是被扫了；整体清空即可，
		// 代价是被限速的地址重新获得一次配额。
		l.seen = map[string]*limitEntry{}
	}
	e, ok := l.seen[ip]
	if !ok || now-e.window >= connWindow {
		l.seen[ip] = &limitEntry{window: now, n: 1}
		return true
	}
	if e.n >= connBurst {
		return false
	}
	e.n++
	return true
}
