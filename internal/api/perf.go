package api

import "net/http"

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
