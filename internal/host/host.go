// Package host 实现主机清单与私网地址校验。
package host

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"
)

// Host 对应 hosts 表；凭据不落盘。
type Host struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	RDPPort   int    `json:"rdp_port"`
	SBMPort   int    `json:"smb_port"`
	Group     string `json:"group_name"`
	Note      string `json:"note"`
	Enabled   bool   `json:"enabled"`
	Modes     string `json:"modes"`
	PerfName  string `json:"perf_name"`
	PerfOS    string `json:"perf_os"`
	LastSeen  int64  `json:"perf_last_seen"`
	CreatedAt int64  `json:"created_at"`
}

type scanner interface{ Scan(dest ...any) error }

const columns = `id, name, address, rdp_port, smb_port, group_name, note, enabled,
	modes, perf_name, perf_os, perf_last_seen, created_at`

func scanHost(s scanner) (Host, error) {
	var h Host
	var enabled int
	err := s.Scan(&h.ID, &h.Name, &h.Address, &h.RDPPort, &h.SBMPort, &h.Group, &h.Note,
		&enabled, &h.Modes, &h.PerfName, &h.PerfOS, &h.LastSeen, &h.CreatedAt)
	h.Enabled = enabled != 0
	return h, err
}

// List 返回全部主机。
func List(db *sql.DB) ([]Host, error) {
	rows, err := db.Query(`SELECT ` + columns + ` FROM hosts ORDER BY group_name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListByUser 返回指定用户被授权的主机。
func ListByUser(db *sql.DB, userID int64) ([]Host, error) {
	rows, err := db.Query(`SELECT `+columns+` FROM hosts h
		JOIN user_hosts g ON g.host_id = h.id
		WHERE g.user_id = ? AND h.enabled = 1 ORDER BY h.group_name, h.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Get 按 ID 查询主机。
func Get(db *sql.DB, id int64) (Host, error) {
	return scanHost(db.QueryRow(`SELECT `+columns+` FROM hosts WHERE id = ?`, id))
}

// Validate 校验主机字段。地址必须是私网 IP，防止 SSRF。
func Validate(h Host) error {
	if h.ID < 1 || h.ID > 4294967295 {
		return errors.New("主机 ID 须在 1–4294967295 之间（用作被控端控制码）")
	}
	if h.Name == "" || len(h.Name) > 64 {
		return errors.New("主机名称不能为空且不超过 64 字符")
	}
	ip := net.ParseIP(h.Address)
	if ip == nil {
		return errors.New("地址必须是 IP 字面量")
	}
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return errors.New("地址必须属于私网段，公网地址被拒绝")
	}
	if h.RDPPort < 1 || h.RDPPort > 65535 || h.SBMPort < 1 || h.SBMPort > 65535 {
		return errors.New("端口须在 1–65535 之间")
	}
	if h.Modes == "" {
		h.Modes = "rdp"
	}
	for _, m := range splitModes(h.Modes) {
		if m != "rdp" && m != "perf" {
			return errors.New("连接方式只能是 rdp 或 perf")
		}
	}
	return nil
}

func splitModes(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			start = i + 1
			for len(part) > 0 && part[0] == ' ' {
				part = part[1:]
			}
			for len(part) > 0 && part[len(part)-1] == ' ' {
				part = part[:len(part)-1]
			}
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// Create 新增主机。
func Create(db *sql.DB, h Host) error {
	if err := Validate(h); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO hosts
		(id, name, address, rdp_port, smb_port, group_name, note, enabled, modes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.Name, h.Address, h.RDPPort, h.SBMPort, h.Group, h.Note, b(h.Enabled), h.Modes, time.Now().Unix())
	return err
}

// Update 更新主机资料，保留性能模式字段。
func Update(db *sql.DB, id int64, h Host) error {
	if err := Validate(h); err != nil {
		return err
	}
	res, err := db.Exec(`UPDATE hosts SET name=?, address=?, rdp_port=?, smb_port=?,
		group_name=?, note=?, enabled=?, modes=? WHERE id=?`,
		h.Name, h.Address, h.RDPPort, h.SBMPort, h.Group, h.Note, b(h.Enabled), h.Modes, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete 删除主机。
func Delete(db *sql.DB, id int64) error {
	res, err := db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Count 返回主机数。
func Count(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM hosts`).Scan(&n)
	return n, err
}

func b(v bool) int {
	if v {
		return 1
	}
	return 0
}

// Resolve 把主机记录转换成连接目标地址，供后续 RDP 隧道使用。
func Resolve(h Host) string {
	return net.JoinHostPort(h.Address, fmt.Sprint(h.RDPPort))
}
