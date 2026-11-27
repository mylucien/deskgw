package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mylucien/deskgw/internal/host"
	"github.com/mylucien/deskgw/internal/perfgw"
	"github.com/mylucien/deskgw/internal/textutil"
)

// wirePerfConsole 把性能模式接到 API：票据、主机信息、会话记录与审计都
// 以回调注入，perfgw 本身不碰数据库。
func (s *Server) wirePerfConsole() {
	c := perfgw.NewConsole(s.perf, perfgw.NewTicketManager(30*time.Second), perfgw.NewLimits(0, 0))
	c.Host = func(id int64) (perfgw.HostInfo, error) {
		h, err := host.Get(s.db, id)
		if err != nil {
			return perfgw.HostInfo{}, err
		}
		key, err := host.PerfKey(s.db, id)
		if err != nil {
			return perfgw.HostInfo{}, err
		}
		return perfgw.HostInfo{
			ID: h.ID, Name: h.Name, OS: h.PerfOS, Modes: h.Modes,
			Enabled: h.Enabled, PerfKey: key,
		}, nil
	}
	c.Begin = func(sid int64) {
		_, _ = s.db.Exec(`UPDATE sessions SET state='active' WHERE id=? AND ended_at IS NULL`, sid)
	}
	c.End = func(sid int64, state, detail string) {
		_, _ = s.db.Exec(`UPDATE sessions SET state=?, ended_at=?, detail=?
			WHERE id=? AND ended_at IS NULL`,
			state, time.Now().Unix(), clipText(detail, 512), sid)
	}
	c.Audit = func(uid int64, action, target, detail, ip string) {
		writeAudit(s, uid, action, target, detail, ip)
	}
	s.perfConsole = c
	s.reloadPerfLimits()
}

// reloadPerfLimits 从 settings 读性能模式的并发上限。没设过就用 perfgw 的默认值。
func (s *Server) reloadPerfLimits() {
	if s.perfConsole == nil {
		return
	}
	s.perfConsole.Limits().Set(
		s.settingInt("perf.max_sessions", 0),
		s.settingInt("perf.max_per_host", 0))
}

// clipText 截断详情，并避开 UTF-8 字符中间。
func clipText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// perfTicket 校验权限、会话名额与主机状态后签发一次性性能模式票据。
func (s *Server) perfTicket(w http.ResponseWriter, r *http.Request) {
	if s.perfConsole == nil {
		fail(w, http.StatusNotFound, "disabled", "性能模式没有启用")
		return
	}
	var in struct {
		HostID int64 `json:"host_id"`
	}
	if err := readJSON(r, &in); err != nil || in.HostID < 1 {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	sess := fromContext(r.Context())
	h, permitted := s.authorizeHost(w, sess, in.HostID)
	if !permitted {
		return
	}
	if !textutil.HasMode(h.Modes, "perf") {
		// 没开性能模式的主机不暴露「它存在但不可用」，与 RDP 那边一致。
		fail(w, http.StatusNotFound, "notFound", "这台主机没有启用性能模式")
		return
	}
	ip := clientIP(r)
	sid, created := s.newPendingSession(w, sess, in.HostID, ip, "perf")
	if !created {
		return
	}
	tok, err := s.perfConsole.Tickets().Issue(sess.UserID, in.HostID, sid, ip)
	if err != nil {
		_, _ = s.db.Exec(`UPDATE sessions SET state='failed', ended_at=? WHERE id=?`,
			time.Now().Unix(), sid)
		serverError(w, err)
		return
	}
	ok(w, map[string]any{"ticket": tok, "session_id": sid, "ws_path": "/ws/perf?ticket=" + tok})
}

// perfWebSocket 把已登录的请求交给性能模式控制台。
func (s *Server) perfWebSocket(w http.ResponseWriter, r *http.Request) {
	if s.perfConsole == nil {
		http.Error(w, "性能模式没有启用", http.StatusNotFound)
		return
	}
	sess := fromContext(r.Context())
	s.perfConsole.Serve(w, r, perfgw.ConsoleClient{
		UserID: sess.UserID, Username: sess.Username, ClientIP: clientIP(r),
	})
}

// perfStatus 返回性能模式的运行状态与待批准列表。证书指纹要写进每台被控端
// 的 server_fp，控制端公钥要写进 [[paired]].key，两者都和监听地址一起给出来，
// 省得管理员去翻日志。
func (s *Server) perfStatus(w http.ResponseWriter, _ *http.Request) {
	if s.perf == nil {
		ok(w, map[string]any{
			"enabled": false, "listen": "", "fingerprint": "", "identity": "", "hosts": []any{},
		})
		return
	}
	list := s.perf.Pending()
	hosts := make([]map[string]any, 0, len(list))
	for _, p := range list {
		hosts = append(hosts, map[string]any{
			"code":       p.Code,
			"name":       p.Name,
			"os":         p.OS,
			"ip":         p.IP,
			"first_seen": p.FirstSeen,
			"last_seen":  p.LastSeen,
		})
	}
	ok(w, map[string]any{
		"enabled":     true,
		"listen":      s.perf.Listen(),
		"fingerprint": s.perf.Fingerprint(),
		"identity":    s.perf.Identity(),
		"hosts":       hosts,
	})
}

// perfApprove 批准一台待批准的被控端：新建主机行或关联已有主机，把控制码换成
// 主机 id，再断开连接让被控端重新注册、从 Registered 里拿到新控制码。
//
// 被控端公钥要等第一次真正握手时才学得到（见 perfgw.StartSession），
// 所以这里只处理「这台机器允许使用」这一层。
func (s *Server) perfApprove(w http.ResponseWriter, r *http.Request) {
	if s.perf == nil {
		fail(w, http.StatusNotFound, "disabled", "性能模式没有启用")
		return
	}
	code, err := strconv.ParseUint(chi.URLParam(r, "code"), 10, 32)
	if err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "控制码不正确")
		return
	}
	p, found := s.perf.PendingByCode(uint32(code))
	if !found {
		fail(w, http.StatusNotFound, "notFound", "没有这条待批准记录，可能已经批准或离线太久")
		return
	}

	var in struct {
		HostID int64  `json:"host_id"`
		Name   string `json:"name"`
		Group  string `json:"group_name"`
		Note   string `json:"note"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "badRequest", err.Error())
		return
	}

	var id int64
	created := false
	if in.HostID > 0 {
		h, err := host.Get(s.db, in.HostID)
		if err != nil {
			fail(w, http.StatusBadRequest, "badRequest", "指定的主机不存在")
			return
		}
		id = h.ID
		// 关联已有主机时把 perf 加进连接方式，否则用户在主机列表里看不到入口。
		if !textutil.HasMode(h.Modes, "perf") {
			h.Modes = strings.Trim(h.Modes+",perf", ",")
			if err := host.Update(s.db, id, h); err != nil {
				fail(w, http.StatusBadRequest, "invalid", userMessage(err))
				return
			}
		}
	} else {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = p.Name
		}
		if name == "" {
			name = "Windows 主机"
		}
		h := host.Host{
			Name: name, Address: p.IP, Modes: "perf", Enabled: true,
			Group: in.Group, Note: in.Note,
		}
		if err := host.Create(s.db, &h); err != nil {
			fail(w, http.StatusBadRequest, "invalid", userMessage(err))
			return
		}
		id, created = h.ID, true
	}

	if err := host.SetPerfMeta(s.db, id, p.Name, p.OS, p.LastSeen); err != nil {
		serverError(w, err)
		return
	}
	if err := s.perf.Approve(uint32(code), id); err != nil {
		// 批准没成功（控制码已经变了、或者主机 id 被占）：把刚建的主机删掉，
		// 否则管理员每重试一次就多一条重复记录，还得手工清理。
		if created {
			_ = host.Delete(s.db, id)
		}
		fail(w, http.StatusConflict, "conflict", userMessage(err))
		return
	}
	writeAudit(s, idFromContext(r), "perf.approve", p.Name, p.IP, clientIP(r))
	ok(w, map[string]any{"host_id": id})
}
