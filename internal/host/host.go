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
// ID 允许为 0，表示新增时由数据库自动分配。
func Validate(h Host) error {
	if h.ID < 0 || h.ID > 4294967295 {
		return errors.New("主机 ID 须在 1–4294967295 之间（用作被控端控制码）")
	}
	if h.Name == "" || len(h.Name) > 64 {
		return errors.New("主机名称不能为空且不超过 64 字符")
	}
	ip := net.ParseIP(h.Address)
	if ip == nil {
		return errors.New("地址必须是 IP 字面量")
	}
	// 回环、未指定、组播与链路本地地址一律拒绝：网关自身也监听在局域网内，
	// 允许这类地址会让隧道指向网关自己或本地服务，形成 SSRF 跳板。
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return errors.New("地址不能是回环、未指定、组播或链路本地地址")
	}
	// 允许 RFC1918、IPv6 ULA 以及 100.64.0.0/10（CGNAT，Tailscale/ZeroTier 等常用）。
	if !ip.IsPrivate() && !isCGNAT(ip) {
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

// isCGNAT 判断 IPv4 100.64.0.0/10，即运营商级 NAT 段。
// Tailscale 默认使用该段，Go 的 IsPrivate 不包含它。
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 100 && v4[1]&0xC0 == 64
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

// Create 新增主机。ID 为 0 时自动分配（后续可用作被控端控制码）。
func Create(db *sql.DB, h *Host) error {
	if err := Validate(*h); err != nil {
		return err
	}
	var (
		res sql.Result
		err error
	)
	if h.ID == 0 {
		res, err = db.Exec(`INSERT INTO hosts
			(name, address, rdp_port, smb_port, group_name, note, enabled, modes, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.Name, h.Address, h.RDPPort, h.SBMPort, h.Group, h.Note, b(h.Enabled), h.Modes, time.Now().Unix())
	} else {
		res, err = db.Exec(`INSERT INTO hosts
			(id, name, address, rdp_port, smb_port, group_name, note, enabled, modes, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			h.ID, h.Name, h.Address, h.RDPPort, h.SBMPort, h.Group, h.Note, b(h.Enabled), h.Modes, time.Now().Unix())
	}
	if err != nil {
		return err
	}
	if h.ID == 0 {
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		h.ID = id
	}
	if h.ID < 1 || h.ID > 4294967295 {
		return errors.New("主机 ID 超出 1–4294967295 范围")
	}
	return nil
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

// ---- 性能模式字段 ---------------------------------------------------------

// SetPerfMeta 记录被控端自己报的名称、系统与最近在线时间。批准时用名称
// 作为新建主机的默认名，之后每次接入都可以刷新。
func SetPerfMeta(db *sql.DB, id int64, name, os string, lastSeen int64) error {
	_, err := db.Exec(`UPDATE hosts SET perf_name=?, perf_os=?, perf_last_seen=? WHERE id=?`,
		name, os, lastSeen, id)
	return err
}

// PerfKey 返回记录下来的被控端公钥（X25519，32 字节）。没有记录时返回 nil。
func PerfKey(db *sql.DB, id int64) ([]byte, error) {
	var key []byte
	err := db.QueryRow(`SELECT perf_key FROM hosts WHERE id=?`, id).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return key, err
}

// SetPerfKey 记下被控端的公钥。之后这个会话就走 Noise IK，公钥一变就要求
// 重新批准（调用方负责比对）。
func SetPerfKey(db *sql.DB, id int64, key []byte) error {
	_, err := db.Exec(`UPDATE hosts SET perf_key=? WHERE id=?`, key, id)
	return err
}
