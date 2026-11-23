package api

import (
	"time"
)

// 僵尸会话清理。
//
// sessions 表中的 pending / active 记录会计入用户的并发配额，但以下路径
// 不会走网关的正常结束流程：用户签发票据后取消、浏览器刷新丢掉了票据、
// 网关进程重启。没有清理时这些记录会永久占用配额，用户看到「已达上限」
// 却没有任何在线连接，后台也无法对它执行强制下线。

const (
	// pendingTTL：签发票据后迟迟没有建立 WebSocket 的宽限时长。
	pendingTTL = 2 * time.Minute
	// staleTTL：状态为 active 但网关内存中没有连接的宽限时长，
	// 覆盖 markActive 与 addLive 之间的毫秒级窗口。
	staleTTL = 5 * time.Minute
	// sweepInterval：后台扫描周期。
	sweepInterval = time.Minute
)

// sweepOnStartup 把上一个进程遗留的未结束会话全部收尾。
// 网关重启后不可能还有存活连接，继续保留只会占用并发配额；
// 新进程的文件令牌表是空的，无需逐条撤销。
func (s *Server) sweepOnStartup() {
	_, _ = s.db.Exec(`UPDATE sessions SET state='stale', ended_at=?
		WHERE ended_at IS NULL AND state IN ('pending','active')`, time.Now().Unix())
}

// sweepStaleSessions 收尾运行期产生的僵尸记录。
func (s *Server) sweepStaleSessions() {
	now := time.Now()
	pendingCutoff := now.Add(-pendingTTL).Unix()
	staleCutoff := now.Add(-staleTTL).Unix()
	rows, err := s.db.Query(`SELECT id, state, started_at FROM sessions
		WHERE ended_at IS NULL AND state IN ('pending','active') AND started_at < ?`, pendingCutoff)
	if err != nil {
		return
	}
	type candidate struct {
		id        int64
		state     string
		startedAt int64
	}
	var list []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.state, &c.startedAt); err == nil {
			list = append(list, c)
		}
	}
	rows.Close()

	live := s.gateway.LiveIDs()
	for _, c := range list {
		if c.state == "active" && (live[c.id] || c.startedAt >= staleCutoff) {
			continue
		}
		s.finishSession(c.id, "timeout")
	}
}

// finishSession 幂等地结束一条记录，并在首次结束时撤销其文件令牌。
func (s *Server) finishSession(id int64, state string) {
	res, err := s.db.Exec(`UPDATE sessions SET state=?, ended_at=? WHERE id=? AND ended_at IS NULL`,
		state, time.Now().Unix(), id)
	if err != nil {
		return
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		s.fileTokens.RevokeSession(id)
		s.uploads.RevokeSession(id)
	}
}

// startSessionSweeper 先同步清理一次遗留记录，再启动周期扫描。
func (s *Server) startSessionSweeper() {
	s.sweepOnStartup()
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.sweepStaleSessions()
		}
	}()
}
