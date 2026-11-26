package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/mylucien/deskgw/internal/host"
)

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
	if in.HostID > 0 {
		h, err := host.Get(s.db, in.HostID)
		if err != nil {
			fail(w, http.StatusBadRequest, "badRequest", "指定的主机不存在")
			return
		}
		id = h.ID
		// 关联已有主机时把 perf 加进连接方式，否则用户在主机列表里看不到入口。
		if !hasMode(h.Modes, "perf") {
			h.Modes = strings.Trim(h.Modes+",perf", ",")
			if err := host.Update(s.db, id, h); err != nil {
				fail(w, http.StatusBadRequest, "invalid", err.Error())
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
			fail(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
		id = h.ID
	}

	if err := host.SetPerfMeta(s.db, id, p.Name, p.OS, p.LastSeen); err != nil {
		serverError(w, err)
		return
	}
	if err := s.perf.Approve(uint32(code), id); err != nil {
		// 主机行已经写好了，但控制码没换：记录还在待批准列表里，管理员可以重试。
		fail(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	writeAudit(s, idFromContext(r), "perf.approve", p.Name, p.IP, clientIP(r))
	ok(w, map[string]any{"host_id": id})
}

// hasMode 判断连接方式里有没有某一项。
func hasMode(modes, want string) bool {
	for _, m := range strings.Split(modes, ",") {
		if strings.TrimSpace(m) == want {
			return true
		}
	}
	return false
}
