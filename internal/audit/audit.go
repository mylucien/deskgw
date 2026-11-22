// Package audit 记录登录、会话与配置变更事件。
package audit

import (
	"database/sql"
	"time"
)

// Event 是一条审计日志。
type Event struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	UserID   sql.NullInt64 `json:"user_id"`
	Username string `json:"username"`
	Action   string `json:"action"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	ClientIP string `json:"client_ip"`
}

// Write 写入一条事件。
func Write(db *sql.DB, userID any, action, target, detail, clientIP string) error {
	_, err := db.Exec(`INSERT INTO audit_logs (ts, user_id, action, target, detail, client_ip)
		VALUES (?, ?, ?, ?, ?, ?)`, time.Now().Unix(), userID, action, target, detail, clientIP)
	return err
}

// List 按时间倒序返回事件，支持按用户、动作、关键字过滤。
func List(db *sql.DB, userID int64, action, keyword string, limit, offset int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT a.id, a.ts, a.user_id, COALESCE(u.username, ''), a.action, a.target, a.detail, a.client_ip
		FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id WHERE 1=1`
	args := []any{}
	if userID > 0 {
		q += ` AND a.user_id = ?`
		args = append(args, userID)
	}
	if action != "" {
		q += ` AND a.action = ?`
		args = append(args, action)
	}
	if keyword != "" {
		q += ` AND (a.target LIKE ? OR a.detail LIKE ? OR u.username LIKE ?)`
		kw := "%" + keyword + "%"
		args = append(args, kw, kw, kw)
	}
	q += ` ORDER BY a.id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.UserID, &e.Username, &e.Action,
			&e.Target, &e.Detail, &e.ClientIP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Purge 删除超过 retentionDays 天的日志。
func Purge(db *sql.DB, retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 90
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()
	_, err := db.Exec(`DELETE FROM audit_logs WHERE ts < ?`, cutoff)
	return err
}
