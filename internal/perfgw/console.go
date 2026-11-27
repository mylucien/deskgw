package perfgw

// 浏览器控制台的接入点：票据、connect / ready / error / ended、心跳，以及
// 把转发层接到 WebSocket 上。
//
// 只做接入与会话生命周期，加解密和消息解析全在浏览器里（4.11）。这里
// 拿到的密文一律原样转发，路由器看不到画面，也看不到键鼠内容。

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mylucien/deskgw/internal/httpx"
	"github.com/mylucien/deskgw/internal/textutil"
)

const (
	// connectWait 是建立 WebSocket 之后等第一条 connect 消息的时间。
	connectWait = 10 * time.Second
	// consolePing 是路由器主动发心跳的间隔；pongWait 是收不到任何消息的上限。
	consolePing = 30 * time.Second
	pongWait    = 90 * time.Second
	// readyTimeout 是写 ready 的时限。ready 里有密钥，不能写到一半就挂着。
	readyTimeout = 10 * time.Second
	// 上行违规次数上限：偶尔一条格式不对可以忽略，连续几十条说明对端不是
	// 我们的控制端，直接断开。
	maxViolations = 32
)

var (
	// errKeyChanged 表示数据库里记的被控端公钥读不出来（重装或有人改过库）。
	errKeyChanged = errors.New("被控端公钥无效")
	// errBadHost 表示 connect 里的主机占位符不合法。
	errBadHost = errors.New("主机占位符不合法")
)

// HostInfo 是接入层要的上层数据：主机名、系统、已记录的公钥。
type HostInfo struct {
	ID      int64
	Name    string
	OS      string
	Modes   string
	Enabled bool
	PerfKey []byte
}

// ConsoleClient 是已登录用户的身份，由 API 层从会话里取。
type ConsoleClient struct {
	UserID   int64
	Username string
	ClientIP string
}

// Console 是浏览器控制台的接入点。
//
// 查主机、写审计、收尾会话记录都是上层的事，这里只留函数字段，免得 perfgw
// 直接依赖数据库。
type Console struct {
	srv     *Server
	tickets *TicketManager
	limits  *Limits

	// live 是当前在跑的会话（键是 sessions 表的 id），用于僵尸清理判断、
	// 管理员强制下线，以及按用户/主机批量断开。userID 与 hostID 用来匹配。
	mu   sync.Mutex
	live map[int64]liveConsole

	// Host 按 id 取主机信息，error 表示主机不可用。
	Host func(id int64) (HostInfo, error)
	// Begin 把待连接的会话记录标记为 active。
	Begin func(sessionID int64)
	// End 收尾会话记录，state 是 closed 或 failed。
	End func(sessionID int64, state, detail string)
	// Audit 写一条审计事件。
	Audit func(userID int64, action, target, detail, ip string)
}

// NewConsole 构造控制台接入点。Host / Begin / End / Audit 由调用方设置。
func NewConsole(srv *Server, tickets *TicketManager, limits *Limits) *Console {
	return &Console{srv: srv, tickets: tickets, limits: limits, live: map[int64]liveConsole{}}
}

// liveConsole 是一条正在跑的控制台会话。close 用于强制断开。
type liveConsole struct {
	userID int64
	hostID int64
	close  func()
}

// LiveIDs 返回当前在跑的会话 id 集合，供僵尸清理判断。
func (c *Console) LiveIDs() map[int64]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[int64]bool, len(c.live))
	for id := range c.live {
		out[id] = true
	}
	return out
}

// CloseSession 强制结束一条会话，返回是否命中。
func (c *Console) CloseSession(id int64) bool {
	c.mu.Lock()
	e := c.live[id]
	c.mu.Unlock()
	if e.close == nil {
		return false
	}
	e.close()
	return true
}

// CloseHost 断开指向某台主机的全部性能模式会话，返回断开数量。
func (c *Console) CloseHost(hostID int64) int {
	return c.closeWhere(func(e liveConsole) bool { return e.hostID == hostID })
}

// CloseUser 断开某个用户的全部性能模式会话，返回断开数量。
func (c *Console) CloseUser(userID int64) int {
	return c.closeWhere(func(e liveConsole) bool { return e.userID == userID })
}

func (c *Console) closeWhere(match func(liveConsole) bool) int {
	c.mu.Lock()
	var targets []func()
	for _, e := range c.live {
		if match(e) {
			targets = append(targets, e.close)
		}
	}
	c.mu.Unlock()
	for _, fn := range targets {
		fn()
	}
	return len(targets)
}

func (c *Console) addLive(id, userID, hostID int64, fn func()) {
	c.mu.Lock()
	c.live[id] = liveConsole{userID: userID, hostID: hostID, close: fn}
	c.mu.Unlock()
}

func (c *Console) removeLive(id int64) {
	c.mu.Lock()
	delete(c.live, id)
	c.mu.Unlock()
}

// Limits 返回名额表，供后台改限额时直接调整。
func (c *Console) Limits() *Limits { return c.limits }

// Tickets 返回票据管理器，供 API 签发票据。
func (c *Console) Tickets() *TicketManager { return c.tickets }

var consoleUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 32 * 1024,
	CheckOrigin:     httpx.SameOrigin,
}

// Serve 处理一次控制台连接。调用方已完成登录态校验。
func (c *Console) Serve(w http.ResponseWriter, r *http.Request, cl ConsoleClient) {
	tk, err := c.tickets.Consume(r.URL.Query().Get("ticket"), cl.ClientIP)
	if err != nil {
		http.Error(w, "连接票据无效", http.StatusUnauthorized)
		return
	}
	if tk.UserID != cl.UserID {
		http.Error(w, "连接票据与登录用户不符", http.StatusForbidden)
		return
	}
	info, err := c.Host(tk.HostID)
	if err != nil || !info.Enabled || !textutil.HasMode(info.Modes, "perf") {
		c.failBefore(w, tk, cl, "codeNotFound", "主机不存在或已停用", http.StatusNotFound)
		return
	}

	ws, err := consoleUpgrader.Upgrade(w, r, nil)
	if err != nil {
		c.endSession(tk.SessionID, "failed", "无法建立 WebSocket")
		return
	}
	defer ws.Close()
	ws.SetReadLimit(maxControlMsg + upHeader)

	// 第一条必须是 connect，带上主机占位符。票据已经绑了主机，这里再核一次，
	// 避免浏览器拿着 A 的票据去连 B。
	if err := checkConnect(ws, info.ID); err != nil {
		c.reject(ws, tk, cl, "codeNotFound", err.Error())
		return
	}

	// 名额在握手之前占：握手要开流，失败了再放回去。
	if err := c.limits.acquire(info.ID); err != nil {
		c.reject(ws, tk, cl, errorKind(err), err.Error())
		return
	}
	defer c.limits.release(info.ID)

	key, err := parsePeerKey(info.PerfKey)
	if err != nil {
		c.reject(ws, tk, cl, "hostKeyChanged", "路由器记录的被控端公钥无效，请重新批准")
		return
	}
	started := time.Now()
	// 被控端托盘上显示的控制端名称用登录名，方便本机用户知道是谁连进来的。
	intro := browserIntro()
	if name := textutil.Runes(cl.Username, 32); name != "" {
		intro.name = name
	}
	sess, err := c.srv.StartSession(uint32(info.ID), sessionPeer{
		name: intro.name, ip: net.ParseIP(cl.ClientIP),
	}, intro, key)
	if err != nil {
		c.reject(ws, tk, cl, errorKind(err), err.Error())
		return
	}

	// ready 里有会话密钥，写完就把路由器内存里的密钥清掉：之后只搬密文，
	// 路由器手里没有能解开画面的东西。
	bundle := buildKeyBundle(sess.keys)
	safety := sess.keys.safety
	sess.keys.wipe()
	ready := map[string]any{
		"type":       "ready",
		"session_id": sess.id,
		"host": map[string]any{
			"id": info.ID, "name": info.Name, "os": info.OS,
		},
		"safety": safety,
		"keys":   bundle,
	}
	_ = ws.SetWriteDeadline(time.Now().Add(readyTimeout))
	if err := ws.WriteJSON(ready); err != nil {
		sess.close()
		c.endSession(tk.SessionID, "failed", "写入 ready 失败")
		return
	}
	_ = ws.SetWriteDeadline(time.Time{})

	if c.Begin != nil {
		c.Begin(tk.SessionID)
	}
	c.audit(cl.UserID, "perf.connect", info.Name, cl.ClientIP, cl.ClientIP)

	rl := newRelay(sess, ws, newRateLimiter())
	c.addLive(tk.SessionID, cl.UserID, info.ID, func() { rl.stop("管理员强制下线") })
	defer c.removeLive(tk.SessionID)
	done := make(chan struct{})
	go func() {
		rl.run()
		close(done)
	}()
	go keepalive(ws, rl)

	c.pump(ws, rl)
	rl.stop("浏览器已断开")
	<-done

	reason := rl.endReason()
	c.endSession(tk.SessionID, "closed", reason)
	c.audit(cl.UserID, "perf.end", info.Name,
		time.Since(started).Round(time.Second).String()+"，"+reason, cl.ClientIP)
}

// pump 读浏览器发来的消息，直到连接断开或浏览器主动 disconnect。
func (c *Console) pump(ws *websocket.Conn, rl *relay) {
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(pongWait))
	})
	bad := 0
	for {
		_ = ws.SetReadDeadline(time.Now().Add(pongWait))
		mt, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		switch mt {
		case websocket.TextMessage:
			var m struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			switch m.Type {
			case "ping":
				rl.sendJSON(map[string]any{"type": "pong"})
			case "disconnect":
				rl.stop("浏览器主动断开")
				return
			}
		case websocket.BinaryMessage:
			if len(data) >= upHeader {
				var err error
				switch data[0] {
				case frameUpStream:
					err = rl.upStream(data[1], data[upHeader:])
				case frameUpDatagram:
					err = rl.upDatagram(data[1], data[upHeader:])
				default:
					err = errUpLane
				}
				if err != nil {
					bad++
					if bad > maxViolations {
						rl.stop("上行消息不合法")
						return
					}
				}
			}
		}
	}
}

// keepalive 定期发 ping，浏览器回 pong 就说明这条连接还活着。
func keepalive(ws *websocket.Conn, rl *relay) {
	t := time.NewTicker(consolePing)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
				return
			}
		case <-rl.sink.done:
			return
		}
	}
}

// checkConnect 读第一条消息并核对主机占位符。
func checkConnect(ws *websocket.Conn, hostID int64) error {
	_ = ws.SetReadDeadline(time.Now().Add(connectWait))
	mt, data, err := ws.ReadMessage()
	if err != nil {
		return errors.New("没有收到 connect")
	}
	if mt != websocket.TextMessage {
		return errors.New("第一条消息必须是 connect")
	}
	var m struct {
		Type string `json:"type"`
		Host string `json:"host"`
	}
	if err := json.Unmarshal(data, &m); err != nil || m.Type != "connect" {
		return errors.New("第一条消息必须是 connect")
	}
	id, err := parseHostRef(m.Host)
	if err != nil || id != hostID {
		return errors.New("主机与票据不符")
	}
	return nil
}

// parseHostRef 解析主机占位符 `h<id>`。
func parseHostRef(s string) (int64, error) {
	if len(s) < 2 || s[0] != 'h' {
		return 0, errBadHost
	}
	id, err := strconv.ParseInt(s[1:], 10, 64)
	if err != nil || id <= 0 {
		return 0, errBadHost
	}
	return id, nil
}

// parsePeerKey 把数据库里的公钥字节变成 ecdh 公钥；空表示还没学过。
func parsePeerKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) == 0 {
		return nil, nil
	}
	k, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, errKeyChanged
	}
	return k, nil
}

// browserIntro 是握手时交给被控端的控制端介绍。初始画质用固定默认值，
// 浏览器在 ready 之后用 Settings / View 消息再改。
func browserIntro() controllerIntro {
	return controllerIntro{
		name: "deskgw", os: "Web", settings: defaultQuality(),
		view: []streamView{{display: 0, maxShort: 1080}},
	}
}

// keyBundle 是 ready 里的会话密钥包（4.9）：控制通道收发、控制数据报收发、
// 四路画面的接收密钥，全部十六进制，避免 JSON 数组把密钥摊成一堆小数。
type keyBundle struct {
	ControlSend  string   `json:"control_send"`
	ControlRecv  string   `json:"control_recv"`
	DatagramSend string   `json:"datagram_send"`
	DatagramRecv string   `json:"datagram_recv"`
	BulkSend     string   `json:"bulk_send"`
	BulkRecv     string   `json:"bulk_recv"`
	Video        []string `json:"video"`

	ControlSendCounter  uint64 `json:"control_send_counter"`
	ControlRecvCounter  uint64 `json:"control_recv_counter"`
	DatagramSendCounter uint64 `json:"datagram_send_counter"`
	DatagramRecvCounter uint64 `json:"datagram_recv_counter"`
	// 大块通道两个方向都从 0 开始：握手不在这条通道上发东西。
	BulkSendCounter uint64 `json:"bulk_send_counter"`
	BulkRecvCounter uint64 `json:"bulk_recv_counter"`
}

func buildKeyBundle(k *sessionKeys) keyBundle {
	b := keyBundle{
		ControlSend:         hex.EncodeToString(k.control[0][:]),
		ControlRecv:         hex.EncodeToString(k.control[1][:]),
		DatagramSend:        hex.EncodeToString(k.datagram[0][:]),
		DatagramRecv:        hex.EncodeToString(k.datagram[1][:]),
		BulkSend:            hex.EncodeToString(k.bulk[0][:]),
		BulkRecv:            hex.EncodeToString(k.bulk[1][:]),
		Video:               make([]string, 0, len(k.video)),
		ControlSendCounter:  firstCounter,
		ControlRecvCounter:  firstCounter,
		DatagramSendCounter: 0,
		DatagramRecvCounter: 0,
	}
	for i := range k.video {
		b.Video = append(b.Video, hex.EncodeToString(k.video[i][:]))
	}
	return b
}

// errorKind 把内部错误映射成浏览器认识的类型（4.10 的错误处理表）。
func errorKind(err error) string {
	switch {
	case errors.Is(err, errHostBusy), errors.Is(err, errFull):
		return "hostBusy"
	case errors.Is(err, errPairingRequired):
		return "pairingRequired"
	case errors.Is(err, errHostOffline), errors.Is(err, errNotApproved),
		errors.Is(err, errBadHost):
		return "codeNotFound"
	case errors.Is(err, errKeyChanged):
		return "hostKeyChanged"
	default:
		return "incompatible"
	}
}

// reject 在升级之后失败：先发 error，再关连接，最后收尾会话记录。
func (c *Console) reject(ws *websocket.Conn, tk *Ticket, cl ConsoleClient, kind, msg string) {
	_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = ws.WriteJSON(map[string]any{"type": "error", "kind": kind, "message": msg})
	_ = ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, clipReason(msg)),
		time.Now().Add(5*time.Second))
	c.audit(cl.UserID, "perf.connect_failed", strconv.FormatInt(tk.HostID, 10), kind, cl.ClientIP)
	c.endSession(tk.SessionID, "failed", kind)
}

// failBefore 在升级之前失败：只能回 HTTP 状态码。
func (c *Console) failBefore(w http.ResponseWriter, tk *Ticket, cl ConsoleClient, kind, msg string, status int) {
	http.Error(w, msg, status)
	c.audit(cl.UserID, "perf.connect_failed", strconv.FormatInt(tk.HostID, 10), kind, cl.ClientIP)
	c.endSession(tk.SessionID, "failed", kind)
}

func (c *Console) endSession(sessionID int64, state, detail string) {
	if c.End != nil {
		c.End(sessionID, state, detail)
	}
}

func (c *Console) audit(userID int64, action, target, detail, ip string) {
	if c.Audit != nil {
		c.Audit(userID, action, target, detail, ip)
	}
}
