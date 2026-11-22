// Package api 提供 REST 接口、会话中间件与静态页面托管。
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/mylucien/deskgw/internal/audit"
	"github.com/mylucien/deskgw/internal/auth"
	"github.com/mylucien/deskgw/internal/config"
	"github.com/mylucien/deskgw/internal/filegw"
	"github.com/mylucien/deskgw/internal/host"
	"github.com/mylucien/deskgw/internal/tunnel"
	"github.com/mylucien/deskgw/internal/user"
	"github.com/mylucien/deskgw/web"
)

const sessionCookie = "deskgw_session"
const csrfCookie = "deskgw_csrf"

// Server 保存 API 依赖。
type Server struct {
	db         *sql.DB
	auth       *auth.Manager
	cfg        config.Config
	tickets    *tunnel.TicketManager
	gateway    *tunnel.Gateway
	fileTokens *filegw.TokenManager
	started    time.Time
}

type ctxKey int

const sessionKey ctxKey = 1

// New 构造 HTTP handler。
func New(db *sql.DB, mgr *auth.Manager, cfg config.Config) http.Handler {
	s := &Server{db: db, auth: mgr, cfg: cfg, started: time.Now()}
	// 启动时以数据库中持久化的会话超时为准（后台可改），缺省沿用环境变量配置。
	var savedIdle string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='session_idle_min'`).Scan(&savedIdle); err == nil {
		if n, e := strconv.Atoi(savedIdle); e == nil && n > 0 {
			mgr.SetIdle(n)
		}
	}
	s.tickets = tunnel.NewTicketManager(30 * time.Second)
	s.fileTokens = filegw.NewTokenManager(30 * time.Minute)
	s.gateway = tunnel.NewGateway(db, s.tickets,
		func(uid any, action, target, detail, ip string) {
			writeAudit(s, uid, action, target, detail, ip)
		}, s.fileTokens.RevokeSession)
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	// clientIP 直接取 r.RemoteAddr（真实 TCP 对端），不信任 X-Forwarded-For / X-Real-IP。
	// deskgw 部署在边缘、前面无反向代理；启用 RealIP 会让伪造头绕过登录限流与票据/令牌的 IP 绑定。
	r.Use(s.securityHeaders)
	r.Use(s.issueCSRF)

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		ok(w, map[string]any{
			"status": "ok", "version": "0.3.0",
			"uptime": int(time.Since(s.started).Seconds()),
		})
	})
	r.Post("/api/login", s.login)

	// WebSocket 握手由浏览器发起，无法附加自定义 CSRF 头；
	// 会话 Cookie 同源、Origin 校验与一次性票据共同提供保护。
	r.Group(func(r chi.Router) {
		r.Use(s.requireSession)
		r.Get("/ws/rdp", s.rdpWebSocket)
	})

	r.Group(func(r chi.Router) {
		r.Use(s.requireSession)
		r.Use(s.requireCSRF)
		r.Post("/api/logout", s.logout)
		r.Get("/api/me", s.me)
		r.Get("/api/hosts", s.myHosts)
		r.Post("/api/sessions", s.createSession)

		r.Route("/api/files", func(r chi.Router) {
			r.Post("/token", s.createFileToken)
			r.Get("/list", s.listFiles)
			r.Post("/upload", s.uploadFile)
			r.Get("/download", s.downloadFile)
			r.Post("/mkdir", func(w http.ResponseWriter, q *http.Request) { s.fileMutation(w, q, "mkdir") })
			r.Post("/rename", func(w http.ResponseWriter, q *http.Request) { s.fileMutation(w, q, "rename") })
			r.Post("/delete", func(w http.ResponseWriter, q *http.Request) { s.fileMutation(w, q, "delete") })
		})

		r.Route("/api/admin", func(r chi.Router) {
			r.Use(s.requireAdmin)
			r.Route("/users", func(r chi.Router) {
				r.Get("/", s.listUsers)
				r.Post("/", s.createUser)
				r.Put("/{id}", s.updateUser)
				r.Delete("/{id}", s.deleteUser)
			})
			r.Route("/hosts", func(r chi.Router) {
				r.Get("/", s.listHosts)
				r.Post("/", s.createHost)
				r.Put("/{id}", s.updateHost)
				r.Delete("/{id}", s.deleteHost)
			})
			r.Get("/audit", s.listAudit)
			r.Get("/audit/export", s.exportAudit)
			r.Get("/sessions", s.listSessions)
			r.Delete("/sessions/{id}", s.killSession)
			r.Get("/settings", s.getSettings)
			r.Put("/settings", s.putSettings)
		})
	})

	static := web.Handler()
	r.Method(http.MethodGet, "/", static)
	r.Handle("/*", static)
	return r
}

// ---- 中间件 ---------------------------------------------------------------

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss: ws:; "+
				"worker-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// issueCSRF 使用双提交 Cookie：Cookie 非 HttpOnly，写操作要求同值请求头。
func (s *Server) issueCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if c, err := r.Cookie(csrfCookie); err == nil {
			tok = c.Value
		}
		if tok == "" {
			tok = auth.RandomToken(24)
			http.SetCookie(w, &http.Cookie{
				Name: csrfCookie, Value: tok, Path: "/",
				HttpOnly: false, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
			})
		}
		next.ServeHTTP(w, r.WithContext(setCSRF(r.Context(), tok)))
	})
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			fail(w, http.StatusUnauthorized, "unauthorized", "请先登录")
			return
		}
		sess, ok := s.auth.Get(c.Value)
		if !ok {
			clearCookie(w, sessionCookie, s.cfg.CookieSecure)
			fail(w, http.StatusUnauthorized, "unauthorized", "登录已过期")
			return
		}
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), sess)))
	})
}

func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-CSRF-Token") != csrfFrom(r.Context()) {
			fail(w, http.StatusForbidden, "csrf", "CSRF 校验失败")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := fromContext(r.Context())
		if sess == nil || sess.Role != "admin" {
			fail(w, http.StatusForbidden, "forbidden", "需要管理员权限")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- 登录与会话 -----------------------------------------------------------

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	ip := clientIP(r)
	key := ip + "|" + in.Username
	if s.auth.Locked(key) {
		writeAudit(s, nil, "login_locked", in.Username, "", ip)
		fail(w, http.StatusTooManyRequests, "locked", "尝试次数过多，请 10 分钟后再试")
		return
	}
	u, hash, err := user.GetByUsername(s.db, in.Username)
	if err != nil || !u.Enabled || !auth.VerifyPassword(hash, in.Password) {
		s.auth.Fail(key)
		writeAudit(s, nullableID(u.ID), "login_failed", in.Username, "", ip)
		fail(w, http.StatusUnauthorized, "invalidCredentials", "用户名或密码错误")
		return
	}
	s.auth.Clear(key)
	tok, err := s.auth.Create(u.ID, u.Username, u.Role)
	if err != nil {
		fail(w, http.StatusInternalServerError, "serverError", "创建会话失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/",
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(s.auth.Idle().Minutes()) * 60,
	})
	writeAudit(s, u.ID, "login", u.Username, "", ip)
	ok(w, map[string]any{"user": u})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.auth.Delete(c.Value)
	}
	clearCookie(w, sessionCookie, s.cfg.CookieSecure)
	ok(w, map[string]any{})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	sess := fromContext(r.Context())
	u, err := user.Get(s.db, sess.UserID)
	if err != nil {
		fail(w, http.StatusUnauthorized, "unauthorized", "用户已不存在")
		return
	}
	ok(w, map[string]any{"user": u, "csrf": csrfFrom(r.Context())})
}

// createSession 校验权限与并发上限后签发一次性 RDP 连接票据。
func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	sess := fromContext(r.Context())
	var in struct {
		HostID int64 `json:"host_id"`
	}
	if err := readJSON(r, &in); err != nil || in.HostID < 1 {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	h, err := host.Get(s.db, in.HostID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !h.Enabled) {
		fail(w, http.StatusNotFound, "notFound", "主机不存在或已停用")
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}
	if sess.Role != "admin" {
		var granted int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM user_hosts WHERE user_id=? AND host_id=?`,
			sess.UserID, in.HostID).Scan(&granted); err != nil {
			serverError(w, err)
			return
		}
		if granted == 0 {
			fail(w, http.StatusForbidden, "forbidden", "无权访问该主机")
			return
		}
	}
	var active int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=? AND state IN ('pending','active')`,
		sess.UserID).Scan(&active); err != nil {
		serverError(w, err)
		return
	}
	u, err := user.Get(s.db, sess.UserID)
	if err != nil {
		serverError(w, err)
		return
	}
	limit := u.MaxSessions
	if limit <= 0 {
		limit = 2
	}
	if active >= limit {
		fail(w, http.StatusTooManyRequests, "limit", "已达到并发会话上限")
		return
	}

	res, err := s.db.Exec(`INSERT INTO sessions (user_id, host_id, client_ip, started_at, state, mode)
		VALUES (?, ?, ?, ?, 'pending', 'rdp')`,
		sess.UserID, in.HostID, clientIP(r), time.Now().Unix())
	if err != nil {
		serverError(w, err)
		return
	}
	sid, err := res.LastInsertId()
	if err != nil {
		serverError(w, err)
		return
	}
	tok, err := s.tickets.Issue(sess.UserID, in.HostID, sid, clientIP(r))
	if err != nil {
		serverError(w, err)
		return
	}
	writeAudit(s, sess.UserID, "rdp.ticket", h.Name, strconv.FormatInt(sid, 10), clientIP(r))
	ok(w, map[string]any{"ticket": tok, "session_id": sid, "ws_path": "/ws/rdp?ticket=" + tok})
}

// rdpWebSocket 将已登录的请求交给隧道网关处理。
func (s *Server) rdpWebSocket(w http.ResponseWriter, r *http.Request) {
	sess := fromContext(r.Context())
	s.gateway.Serve(w, r, sess)
}

func (s *Server) myHosts(w http.ResponseWriter, r *http.Request) {
	sess := fromContext(r.Context())
	var list []host.Host
	var err error
	if sess.Role == "admin" {
		list, err = host.List(s.db)
	} else {
		list, err = host.ListByUser(s.db, sess.UserID)
	}
	if err != nil {
		serverError(w, err)
		return
	}
	ok(w, list)
}

// ---- 用户管理 -------------------------------------------------------------

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request) {
	list, err := user.List(s.db)
	if err != nil {
		serverError(w, err)
		return
	}
	ok(w, list)
}

type userInput struct {
	Username       string  `json:"username"`
	Password       string  `json:"password"`
	Role           string  `json:"role"`
	Enabled        bool    `json:"enabled"`
	AllowFile      bool    `json:"allow_file"`
	AllowClipboard bool    `json:"allow_clipboard"`
	MaxSessions    int     `json:"max_sessions"`
	HostIDs        []int64 `json:"host_ids"`
}

func inputToUser(in userInput) user.User {
	return user.User{
		Username: in.Username, Role: in.Role, Enabled: in.Enabled,
		AllowFile: in.AllowFile, AllowClipboard: in.AllowClipboard,
		MaxSessions: in.MaxSessions, HostIDs: in.HostIDs,
	}
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in userInput
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	if in.MaxSessions <= 0 {
		in.MaxSessions = 2
	}
	id, err := user.Create(s.db, inputToUser(in), in.Password, in.HostIDs)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	writeAudit(s, idFromContext(r), "user.create", in.Username, "", clientIP(r))
	ok(w, map[string]any{"id": id})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "ID 不正确")
		return
	}
	var in userInput
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	if in.MaxSessions <= 0 {
		in.MaxSessions = 2
	}
	if err := user.Update(s.db, id, inputToUser(in), in.Password, in.HostIDs); err != nil {
		writeErr(w, err)
		return
	}
	writeAudit(s, idFromContext(r), "user.update", in.Username, "", clientIP(r))
	ok(w, map[string]any{})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "ID 不正确")
		return
	}
	sess := fromContext(r.Context())
	if sess != nil && sess.UserID == id {
		fail(w, http.StatusBadRequest, "invalid", "不能删除当前登录的账号")
		return
	}
	if err := user.Delete(s.db, id); err != nil {
		writeErr(w, err)
		return
	}
	writeAudit(s, idFromContext(r), "user.delete", strconv.FormatInt(id, 10), "", clientIP(r))
	ok(w, map[string]any{})
}

// ---- 主机管理 -------------------------------------------------------------

func (s *Server) listHosts(w http.ResponseWriter, _ *http.Request) {
	list, err := host.List(s.db)
	if err != nil {
		serverError(w, err)
		return
	}
	ok(w, list)
}

func (s *Server) createHost(w http.ResponseWriter, r *http.Request) {
	h, err := readHost(r)
	if err != nil {
		fail(w, http.StatusBadRequest, "badRequest", err.Error())
		return
	}
	if err := host.Create(s.db, h); err != nil {
		fail(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	writeAudit(s, idFromContext(r), "host.create", h.Name, h.Address, clientIP(r))
	ok(w, map[string]any{"id": h.ID})
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "ID 不正确")
		return
	}
	h, err := readHost(r)
	if err != nil {
		fail(w, http.StatusBadRequest, "badRequest", err.Error())
		return
	}
	if err := host.Update(s.db, id, h); err != nil {
		writeErr(w, err)
		return
	}
	writeAudit(s, idFromContext(r), "host.update", h.Name, h.Address, clientIP(r))
	ok(w, map[string]any{})
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "ID 不正确")
		return
	}
	if err := host.Delete(s.db, id); err != nil {
		writeErr(w, err)
		return
	}
	writeAudit(s, idFromContext(r), "host.delete", strconv.FormatInt(id, 10), "", clientIP(r))
	ok(w, map[string]any{})
}

func readHost(r *http.Request) (host.Host, error) {
	var h host.Host
	if err := readJSON(r, &h); err != nil {
		return h, err
	}
	if h.RDPPort == 0 {
		h.RDPPort = 3389
	}
	if h.SBMPort == 0 {
		h.SBMPort = 445
	}
	if h.Modes == "" {
		h.Modes = "rdp"
	}
	if h.CreatedAt == 0 {
		h.CreatedAt = time.Now().Unix()
	}
	return h, nil
}

// ---- 审计 / 会话 / 设置 --------------------------------------------------

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	uid, _ := strconv.ParseInt(q.Get("user_id"), 10, 64)
	list, err := audit.List(s.db, uid, q.Get("action"), q.Get("q"), limit, offset)
	if err != nil {
		serverError(w, err)
		return
	}
	ok(w, list)
}

// exportAudit 把审计事件导出为 CSV（最多 10000 条）。
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uid, _ := strconv.ParseInt(q.Get("user_id"), 10, 64)
	list, err := audit.List(s.db, uid, q.Get("action"), q.Get("q"), 10000, 0)
	if err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="deskgw-audit.csv"`)
	w.Write([]byte("\xef\xbb\xbf时间,用户,动作,目标,详情,来源IP\n"))
	for _, e := range list {
		row := []string{
			time.Unix(e.TS, 0).Format("2006-01-02 15:04:05"),
			e.Username, e.Action, e.Target, e.Detail, e.ClientIP,
		}
		for i, cell := range row {
			if i > 0 {
				w.Write([]byte(","))
			}
			w.Write([]byte(csvCell(cell)))
		}
		w.Write([]byte("\n"))
	}
	writeAudit(s, idFromContext(r), "audit.export", "", strconv.Itoa(len(list)), clientIP(r))
}

func csvCell(s string) string {
	if !strings.ContainsAny(s, ",\"\n\r") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

type sessionView struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	HostID    int64  `json:"host_id"`
	HostName  string `json:"host_name"`
	ClientIP  string `json:"client_ip"`
	StartedAt int64  `json:"started_at"`
	EndedAt   any    `json:"ended_at"`
	State     string `json:"state"`
	Mode      string `json:"mode"`
	Live      bool   `json:"live"`
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT se.id, COALESCE(u.username,''), se.host_id,
		COALESCE(h.name,''), se.client_ip, se.started_at, se.ended_at, se.state, se.mode
		FROM sessions se LEFT JOIN users u ON u.id=se.user_id
		LEFT JOIN hosts h ON h.id=se.host_id
		ORDER BY se.id DESC LIMIT ?`, limit)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()
	live := s.gateway.LiveIDs()
	out := []sessionView{}
	for rows.Next() {
		var v sessionView
		var ended sql.NullInt64
		if err := rows.Scan(&v.ID, &v.Username, &v.HostID, &v.HostName, &v.ClientIP,
			&v.StartedAt, &ended, &v.State, &v.Mode); err != nil {
			serverError(w, err)
			return
		}
		if ended.Valid {
			v.EndedAt = ended.Int64
		}
		v.Live = live[v.ID]
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		serverError(w, err)
		return
	}
	ok(w, map[string]any{
		"web_sessions": s.auth.ActiveSessions(),
		"sessions":     out,
	})
}

func (s *Server) killSession(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "ID 不正确")
		return
	}
	// 先落 killed 状态并撤销文件令牌，再触发网关关闭。
	// 这样网关异步的 endSession 因 ended_at 已置而不会覆盖状态或重复撤销。
	res, _ := s.db.Exec(`UPDATE sessions SET state='killed', ended_at=? WHERE id=? AND ended_at IS NULL`,
		time.Now().Unix(), id)
	if n, _ := res.RowsAffected(); n > 0 {
		s.fileTokens.RevokeSession(id)
	}
	s.gateway.CloseSession(id)
	writeAudit(s, idFromContext(r), "rdp.kill", strconv.FormatInt(id, 10), "", clientIP(r))
	ok(w, map[string]any{})
}

var allowedSettings = map[string]bool{
	"session_idle_min": true,
	"max_upload_mb":    true,
	"perf.enabled":     false, // M8 启用
	"perf.max_sessions": false,
	"perf.max_per_host": false,
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	out := map[string]string{}
	rows, err := s.db.Query(`SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			serverError(w, err)
			return
		}
		out[k] = v
	}
	ok(w, out)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		serverError(w, err)
		return
	}
	defer tx.Rollback()
	for k, v := range in {
		allowed, exists := allowedSettings[k]
		if !exists || !allowed {
			fail(w, http.StatusBadRequest, "invalid", "设置项 "+k+" 暂不可用")
			return
		}
		if k == "session_idle_min" {
			n, e := strconv.Atoi(v)
			if e != nil || n <= 0 {
				fail(w, http.StatusBadRequest, "invalid", "会话空闲超时须为正整数")
				return
			}
		}
		if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			serverError(w, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		serverError(w, err)
		return
	}
	// 会话空闲超时需在运行时即时生效，而不只是写库。
	if v, exists := in["session_idle_min"]; exists {
		if n, e := strconv.Atoi(v); e == nil {
			s.auth.SetIdle(n)
		}
	}
	writeAudit(s, idFromContext(r), "settings.update", strings.Join(keysOf(in), ","), "", clientIP(r))
	ok(w, map[string]any{})
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---- 工具 -----------------------------------------------------------------

func readJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	return dec.Decode(dst)
}

func writeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, http.StatusNotFound, "notFound", "对象不存在")
		return
	}
	fail(w, http.StatusBadRequest, "invalid", err.Error())
}

func serverError(w http.ResponseWriter, err error) {
	fail(w, http.StatusInternalServerError, "serverError", err.Error())
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": false, "error": map[string]string{"code": code, "message": msg},
	})
}

func ok(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": data})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: name == sessionCookie, Secure: secure, SameSite: http.SameSiteStrictMode,
	})
}

func nullableID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func pathID(r *http.Request, name string) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, name), 10, 64)
}

func idFromContext(r *http.Request) any {
	if s := fromContext(r.Context()); s != nil {
		return s.UserID
	}
	return nil
}

func withSession(ctx context.Context, s *auth.Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

func fromContext(ctx context.Context) *auth.Session {
	s, _ := ctx.Value(sessionKey).(*auth.Session)
	return s
}

func setCSRF(ctx context.Context, tok string) context.Context {
	return context.WithValue(ctx, csrfKey, tok)
}

func csrfFrom(ctx context.Context) string {
	v, _ := ctx.Value(csrfKey).(string)
	return v
}

type csrfCtxKey int

const csrfKey csrfCtxKey = 2

func writeAudit(s *Server, userID any, action, target, detail, ip string) {
	_ = audit.Write(s.db, userID, action, target, detail, ip)
}
