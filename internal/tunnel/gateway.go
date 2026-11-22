package tunnel

import (
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mylucien/deskgw/internal/auth"
	"github.com/mylucien/deskgw/internal/host"
)

// liveSession 是一条正在转发的连接。closeFn 用于强制断开。
type liveSession struct {
	id       int64
	closeFn  func()
}

// Gateway 管理 RDP 隧道。
type Gateway struct {
	db        *sql.DB
	tickets   *TicketManager
	maxFrame  int64
	dialTime  time.Duration
	auditFn   func(userID any, action, target, detail, ip string)
	onEnd     func(sessionID int64) // 会话结束时回调（撤销文件令牌等），可为 nil
	mu        sync.Mutex
	live      map[int64]*liveSession
}

// NewGateway 构造网关。auditFn / onEnd 均可为 nil。
func NewGateway(db *sql.DB, tickets *TicketManager, auditFn func(userID any, action, target, detail, ip string), onEnd func(sessionID int64)) *Gateway {
	return &Gateway{
		db: db, tickets: tickets, auditFn: auditFn, onEnd: onEnd,
		maxFrame: 1 << 20, dialTime: 10 * time.Second,
		live: make(map[int64]*liveSession),
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 32 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		return sameOrigin(origin, r.Host)
	},
}

func sameOrigin(origin, hostValue string) bool {
	i := strings.Index(origin, "://")
	if i < 0 {
		return false
	}
	return strings.EqualFold(origin[i+3:], hostValue)
}

// Serve 处理一次 WebSocket 升级与 RDP 隧道。调用方已完成登录态校验。
func (g *Gateway) Serve(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	token := r.URL.Query().Get("ticket")
	ticket, err := g.tickets.Consume(token, clientIP(r))
	if err != nil {
		http.Error(w, "连接票据无效", http.StatusUnauthorized)
		return
	}
	if ticket.UserID != sess.UserID {
		http.Error(w, "连接票据与登录用户不符", http.StatusForbidden)
		return
	}
	h, err := host.Get(g.db, ticket.HostID)
	if err != nil || !h.Enabled {
		http.Error(w, "主机不存在或已停用", http.StatusNotFound)
		return
	}
	target := host.Resolve(h)

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		g.endSession(ticket.SessionID, "upgrade_failed", err.Error())
		return
	}
	ws.SetReadLimit(g.maxFrame)

	// 第一条二进制消息必须是 RDCleanPath 请求。
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	mt, first, err := ws.ReadMessage()
	ws.SetReadDeadline(time.Time{})
	if err != nil {
		g.rejectAndClose(ws, "读取 RDCleanPath 请求失败: "+err.Error(), ticket.SessionID)
		return
	}
	if mt != websocket.BinaryMessage {
		g.rejectAndClose(ws, "首帧不是二进制消息", ticket.SessionID)
		return
	}
	req, err := parseCleanPathRequest(first)
	if err != nil {
		g.rejectAndClose(ws, "RDCleanPath 请求解析失败: "+err.Error(), ticket.SessionID)
		return
	}
	// 浏览器传入的 destination 一律忽略，目标地址只认数据库。
	_ = req.Destination

	tcpConn, err := net.DialTimeout("tcp", target, g.dialTime)
	if err != nil {
		g.rejectAndClose(ws, "连接 RDP 主机失败: "+err.Error(), ticket.SessionID)
		return
	}
	tcpConn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := tcpConn.Write(req.X224Connection); err != nil {
		tcpConn.Close()
		g.rejectAndClose(ws, "发送 X.224 请求失败: "+err.Error(), ticket.SessionID)
		return
	}
	x224Resp, err := readTPKT(tcpConn)
	if err != nil {
		tcpConn.Close()
		g.rejectAndClose(ws, "读取 X.224 确认失败: "+err.Error(), ticket.SessionID)
		return
	}

	tlsConn := tls.Client(tcpConn, &tls.Config{
		InsecureSkipVerify: true, // RDP 服务器普遍自签；证书链回传浏览器自行校验
		ServerName:         parseHost(target),
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		g.rejectAndClose(ws, "RDP TLS 握手失败: "+err.Error(), ticket.SessionID)
		return
	}
	tcpConn.SetDeadline(time.Time{})
	var certChain [][]byte
	for _, c := range tlsConn.ConnectionState().PeerCertificates {
		certChain = append(certChain, c.Raw)
	}
	if err := ws.WriteMessage(websocket.BinaryMessage,
		buildCleanPathResponse(target, x224Resp, certChain)); err != nil {
		tlsConn.Close()
		g.endSession(ticket.SessionID, "write_response_failed", err.Error())
		return
	}

	g.markActive(ticket.SessionID, ticket.ClientIP)
	g.audit(sess.UserID, "rdp.connect", h.Name, target+" via "+ticket.ClientIP, ticket.ClientIP)

	done := make(chan struct{}, 2)
	stop := make(chan struct{})
	entry := &liveSession{id: ticket.SessionID}
	entry.closeFn = func() {
		select {
		case <-stop:
			return
		default:
		}
		close(stop)
		_ = tlsConn.Close()
		_ = ws.Close()
	}
	g.addLive(entry)

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage || len(data) == 0 {
				continue
			}
			if _, err := tlsConn.Write(data); err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := tlsConn.Read(buf)
			if n > 0 {
				if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	entry.closeFn()
	g.removeLive(ticket.SessionID)
	g.endSession(ticket.SessionID, "closed", "")
	g.audit(sess.UserID, "rdp.disconnect", h.Name, target, ticket.ClientIP)
}

// CloseSession 强制断开指定在线会话，返回是否命中。
func (g *Gateway) CloseSession(id int64) bool {
	g.mu.Lock()
	entry := g.live[id]
	g.mu.Unlock()
	if entry == nil {
		return false
	}
	entry.closeFn()
	return true
}

// LiveIDs 返回当前在线会话 ID 集合。
func (g *Gateway) LiveIDs() map[int64]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[int64]bool, len(g.live))
	for id := range g.live {
		out[id] = true
	}
	return out
}

func (g *Gateway) addLive(e *liveSession) {
	g.mu.Lock()
	g.live[e.id] = e
	g.mu.Unlock()
}

func (g *Gateway) removeLive(id int64) {
	g.mu.Lock()
	delete(g.live, id)
	g.mu.Unlock()
}

func (g *Gateway) markActive(sessionID int64, ip string) {
	_, _ = g.db.Exec(`UPDATE sessions SET state='active', client_ip=? WHERE id=?`, ip, sessionID)
}

func (g *Gateway) endSession(sessionID int64, state, detail string) {
	res, err := g.db.Exec(`UPDATE sessions SET state=?, ended_at=? WHERE id=? AND ended_at IS NULL`,
		state, time.Now().Unix(), sessionID)
	if err != nil {
		return
	}
	// 只有首次真正结束会话时才撤销该会话的文件令牌，保证回调幂等。
	if n, _ := res.RowsAffected(); n > 0 && g.onEnd != nil {
		g.onEnd(sessionID)
	}
}

func (g *Gateway) audit(userID any, action, target, detail, ip string) {
	if g.auditFn != nil {
		g.auditFn(userID, action, target, detail, ip)
	}
}

func (g *Gateway) rejectAndClose(ws *websocket.Conn, reason string, sessionID int64) {
	_ = ws.WriteMessage(websocket.BinaryMessage, buildCleanPathError(1, http.StatusBadGateway))
	_ = ws.Close()
	g.endSession(sessionID, "handshake_failed", reason)
}

// readTPKT 读取一个完整的 TPKT 包（4 字节头 + 负载）。
func readTPKT(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 3 {
		return nil, errors.New("X.224 响应不是 TPKT 包")
	}
	length := int(header[2])<<8 | int(header[3])
	if length < 4 || length > 65535 {
		return nil, fmt.Errorf("X.224 TPKT 长度非法: %d", length)
	}
	out := make([]byte, length)
	copy(out, header)
	if _, err := io.ReadFull(conn, out[4:]); err != nil {
		return nil, err
	}
	return out, nil
}

func parseHost(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
