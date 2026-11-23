// Package tunnel 实现一次性连接票据与 WS↔TCP 字节转发。
//
// 网关不解析 RDP、不终结 TLS：浏览器内的 WASM 客户端自己完成
// X.224 → TLS → CredSSP(NLA) → RDP，网关只看到 TLS 记录。
// 目标地址只来自数据库，浏览器无法指定。
package tunnel

import (
	"database/sql"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mylucien/deskgw/internal/auth"
	"github.com/mylucien/deskgw/internal/host"
)

const (
	// wsReadLimit 单条 WebSocket 消息上限。TLS 记录通常不超过 16KiB，
	// 1MiB 足够覆盖拥塞窗口内的批量发送，同时防止内存被单帧撑爆。
	wsReadLimit = 1 << 20
	// pingInterval / pongWait 用于识别半开连接：30 秒发一次 ping，
	// 90 秒收不到任何消息（含 pong）即判定断开。
	pingInterval = 30 * time.Second
	pongWait     = 90 * time.Second
	// idleTimeout 是「没有任何 RDP 数据」的上限。心跳不算数据：
	// 浏览器标签页被挂起时连接会在这里结束，释放并发名额。
	idleTimeout = 30 * time.Minute
	// dialTimeout 是连接目标主机的超时。
	dialTimeout = 10 * time.Second
)

// liveSession 是一条正在转发的连接。close 用于强制断开，可被多处并发调用。
type liveSession struct {
	id      int64
	userID  int64
	hostID  int64
	once    sync.Once
	closeFn func()
}

// close 幂等：正常断开与后台「强制下线」可能同时触发。
func (s *liveSession) close() {
	s.once.Do(s.closeFn)
}

// Gateway 管理 RDP 字节隧道。
type Gateway struct {
	db       *sql.DB
	tickets  *TicketManager
	maxFrame int64
	dialTime time.Duration
	idle     time.Duration
	auditFn  func(userID any, action, target, detail, ip string)
	onEnd    func(sessionID int64) // 会话结束时回调（撤销文件令牌等），可为 nil
	mu       sync.Mutex
	live     map[int64]*liveSession
}

// NewGateway 构造网关。auditFn / onEnd 均可为 nil。
func NewGateway(db *sql.DB, tickets *TicketManager, auditFn func(userID any, action, target, detail, ip string), onEnd func(sessionID int64)) *Gateway {
	return &Gateway{
		db: db, tickets: tickets, auditFn: auditFn, onEnd: onEnd,
		maxFrame: wsReadLimit, dialTime: dialTimeout, idle: idleTimeout,
		live: make(map[int64]*liveSession),
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 32 * 1024,
	CheckOrigin:     checkOrigin,
}

// checkOrigin 只接受同源的 http(s) 页面发起的 WebSocket。
// 校验 scheme 可挡住 file://、chrome-extension:// 等非 Web 来源；
// TLS 直连时还要求 Origin 必须是 https，避免从明文页面借道。
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	i := strings.Index(origin, "://")
	if i < 0 {
		return false
	}
	scheme := strings.ToLower(origin[:i])
	if scheme != "http" && scheme != "https" {
		return false
	}
	if r.TLS != nil && scheme != "https" {
		return false
	}
	return strings.EqualFold(origin[i+3:], r.Host)
}

// Serve 处理一次 WebSocket 升级与字节转发。调用方已完成登录态校验。
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

	// 先建立 TCP，再标记 active：连不上目标时不留 active 记录。
	tcpConn, err := net.DialTimeout("tcp", target, g.dialTime)
	if err != nil {
		g.closeWithReason(ws, ticket.SessionID, "connect_failed", "无法连接目标主机")
		return
	}

	// 记录可能已在连接期间被后台强制下线或清理，此时不应继续建立会话。
	if !g.markActive(ticket.SessionID, ticket.ClientIP) {
		_ = tcpConn.Close()
		_ = ws.Close()
		return
	}
	g.audit(sess.UserID, "rdp.connect", h.Name, target+" via "+ticket.ClientIP, ticket.ClientIP)

	entry := &liveSession{id: ticket.SessionID, userID: ticket.UserID, hostID: ticket.HostID}
	entry.closeFn = func() {
		_ = tcpConn.Close()
		_ = ws.Close()
	}
	g.addLive(entry)

	var lastData atomic.Int64
	lastData.Store(time.Now().UnixNano())

	// 三个 goroutine 竞争写入结束原因；缓冲足够容纳所有发送者。
	done := make(chan string, 4)
	stop := make(chan struct{})

	// 浏览器 → 目标主机。
	go func() {
		for {
			// 半开连接检测：任何消息（含 pong）都会重置读超时。
			_ = ws.SetReadDeadline(time.Now().Add(pongWait))
			mt, data, err := ws.ReadMessage()
			if err != nil {
				done <- "读取 WebSocket 失败: " + err.Error()
				return
			}
			if mt != websocket.BinaryMessage || len(data) == 0 {
				continue
			}
			if _, err := tcpConn.Write(data); err != nil {
				done <- "写入目标主机失败: " + err.Error()
				return
			}
			lastData.Store(time.Now().UnixNano())
		}
	}()

	// 目标主机 → 浏览器。
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := tcpConn.Read(buf)
			if n > 0 {
				if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					done <- "写入 WebSocket 失败: " + err.Error()
					return
				}
				lastData.Store(time.Now().UnixNano())
			}
			if err != nil {
				done <- "读取目标主机失败: " + err.Error()
				return
			}
		}
	}()

	// 心跳：WriteControl 可与 WriteMessage 并发调用。
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
			case <-stop:
				return
			}
		}
	}()

	// 空闲超时：标签页休眠或客户端异常时，仅靠心跳仍会长期占用名额。
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				last := time.Unix(0, lastData.Load())
				if time.Since(last) > g.idle {
					done <- "空闲超时"
					return
				}
			case <-stop:
				return
			}
		}
	}()

	reason := <-done
	close(stop)
	entry.close()
	g.removeLive(ticket.SessionID)
	g.endSession(ticket.SessionID, "closed", reason)
	g.audit(sess.UserID, "rdp.disconnect", h.Name, reason, ticket.ClientIP)
}

// CloseSession 强制断开指定在线会话，返回是否命中。
func (g *Gateway) CloseSession(id int64) bool {
	g.mu.Lock()
	entry := g.live[id]
	g.mu.Unlock()
	if entry == nil {
		return false
	}
	entry.close()
	return true
}

// CloseUser 强制断开某个用户的全部在线会话，返回断开数量。
func (g *Gateway) CloseUser(userID int64) int {
	return g.closeWhere(func(e *liveSession) bool { return e.userID == userID })
}

// CloseHost 强制断开指向某台主机的全部在线会话，返回断开数量。
func (g *Gateway) CloseHost(hostID int64) int {
	return g.closeWhere(func(e *liveSession) bool { return e.hostID == hostID })
}

func (g *Gateway) closeWhere(match func(*liveSession) bool) int {
	g.mu.Lock()
	var targets []*liveSession
	for _, e := range g.live {
		if match(e) {
			targets = append(targets, e)
		}
	}
	g.mu.Unlock()
	for _, e := range targets {
		e.close()
	}
	return len(targets)
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

// markActive 把会话标记为 active，返回是否仍然命中。
// 只更新仍在进行中的记录：若清理任务已把它收尾，不能把 ended_at 已置的
// 记录重新标记为 active。
func (g *Gateway) markActive(sessionID int64, ip string) bool {
	res, err := g.db.Exec(`UPDATE sessions SET state='active', client_ip=?
		WHERE id=? AND ended_at IS NULL`, ip, sessionID)
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n > 0
}

func (g *Gateway) endSession(sessionID int64, state, detail string) {
	res, err := g.db.Exec(`UPDATE sessions SET state=?, ended_at=?, detail=? WHERE id=? AND ended_at IS NULL`,
		state, time.Now().Unix(), clipDetail(detail), sessionID)
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

// closeWithReason 在建立会话前失败时，用 WebSocket close 帧把原因带回浏览器。
// 浏览器侧可读取 close code/reason，直接显示"主机不可达"等提示。
func (g *Gateway) closeWithReason(ws *websocket.Conn, sessionID int64, state, reason string) {
	_ = ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseInternalServerErr, trimReason(reason)),
		time.Now().Add(5*time.Second))
	_ = ws.Close()
	g.endSession(sessionID, state, reason)
}

// maxDetail 限制落库的失败原因长度。原因里可能带对端返回的字符串，
// 不截断会给数据库留一个可以反复写入的放大点。
const maxDetail = 512

// clipDetail 截断失败原因，并避免把 UTF-8 字符切一半。
func clipDetail(s string) string {
	if len(s) <= maxDetail {
		return s
	}
	cut := maxDetail
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// trimReason 把原因截断到 close 帧允许的长度（123 字节）；
// 若截断点落在 UTF-8 字符中间则回退到字符边界，避免出现乱码。
func trimReason(s string) string {
	const max = 120
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
