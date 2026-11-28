// Package host 实现主机清单与私网地址校验。
package host

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/mylucien/deskgw/internal/textutil"
)

// Host 对应 hosts 表；凭据不落盘。
type Host struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	RDPPort   int    `json:"rdp_port"`
	SMBPort   int    `json:"smb_port"`
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
	err := s.Scan(&h.ID, &h.Name, &h.Address, &h.RDPPort, &h.SMBPort, &h.Group, &h.Note,
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

// Validate 校验主机字段。RDP 目标的地址必须是私网 IP，防止 SSRF。
// ID 允许为 0，表示新增时由数据库自动分配。
func Validate(h Host) error {
	if h.ID < 0 || h.ID > 4294967295 {
		return errors.New("主机 ID 须在 1–4294967295 之间（用作被控端控制码）")
	}
	// 按字符而不是字节判断：提示写的是「64 字符」，中文名按字节算只有 21 字，
	// 用户会觉得限制莫名其妙。
	if h.Name == "" || textutil.RuneLen(h.Name) > 64 {
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
	if h.Modes == "" {
		h.Modes = "rdp"
	}
	perfOnly := h.Modes == "perf"
	// 允许 RFC1918、IPv6 ULA 以及 100.64.0.0/10（CGNAT，Tailscale/ZeroTier 等常用）。
	// 纯性能模式的主机没有网关主动外连的路径（QUIC 由被控端主动接入），
	// 公网地址是正常用法，不该按 RDP 的规则拒掉。
	if !ip.IsPrivate() && !isCGNAT(ip) && !perfOnly {
		return errors.New("地址必须属于私网段；只有「仅性能模式」的主机可以用公网地址")
	}
	if h.RDPPort < 1 || h.RDPPort > 65535 || h.SMBPort < 1 || h.SMBPort > 65535 {
		return errors.New("端口须在 1–65535 之间")
	}
	for _, m := range textutil.SplitList(h.Modes) {
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

// Create 新增主机。ID 为 0 时自动分配（后续可用作被控端控制码）。
//
// 分配方式是「最大 id + 1」并记到 settings.hosts.next_id，不用 SQLite 的
// rowid 复用：删掉最大 id 后下一次插入会重新拿到它，而性能模式的注册表、
// 被控端托盘上的控制码都按这个 id 认人，复用等于把新主机冒充成旧主机。
func Create(db *sql.DB, h *Host) error {
	if err := Validate(*h); err != nil {
		return err
	}
	if h.Modes == "" {
		h.Modes = "rdp"
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	id := h.ID
	if id == 0 {
		if id, err = nextID(tx); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO hosts
		(id, name, address, rdp_port, smb_port, group_name, note, enabled, modes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, h.Name, h.Address, h.RDPPort, h.SMBPort, h.Group, h.Note,
		b(h.Enabled), h.Modes, time.Now().Unix()); err != nil {
		return err
	}
	if h.ID == 0 {
		if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES ('hosts.next_id', ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, strconv.FormatInt(id+1, 10)); err != nil {
			return err
		}
		h.ID = id
	}
	if h.ID < 1 || h.ID > 4294967295 {
		return errors.New("主机 ID 超出 1–4294967295 范围")
	}
	return tx.Commit()
}

// nextID 返回一个从未用过的主机 id。调用方已开事务。
func nextID(tx *sql.Tx) (int64, error) {
	var maxID int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(id),0) FROM hosts`).Scan(&maxID); err != nil {
		return 0, err
	}
	var saved string
	err := tx.QueryRow(`SELECT value FROM settings WHERE key='hosts.next_id'`).Scan(&saved)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	next := maxID + 1
	if n, e := strconv.ParseInt(saved, 10, 64); e == nil && n > next {
		next = n
	}
	return next, nil
}

// Update 更新主机资料，保留性能模式字段。
func Update(db *sql.DB, id int64, h Host) error {
	if err := Validate(h); err != nil {
		return err
	}
	if h.Modes == "" {
		h.Modes = "rdp"
	}
	res, err := db.Exec(`UPDATE hosts SET name=?, address=?, rdp_port=?, smb_port=?,
		group_name=?, note=?, enabled=?, modes=? WHERE id=?`,
		h.Name, h.Address, h.RDPPort, h.SMBPort, h.Group, h.Note, b(h.Enabled), h.Modes, id)
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

// ClearPerfKey 忘掉记录的公钥，让下次会话重新走 Noise XX 学一遍。
//
// 被控端重装系统后会生成新的身份密钥，IK 永远握不上手；批准流程过去只更新
// 名称与时间，公钥还是旧的，等于「提示你去重新批准，但批准没有用」。批准时
// 清掉这一列，下一轮握手就能重新学，不必删主机重建。
func ClearPerfKey(db *sql.DB, id int64) error {
	_, err := db.Exec(`UPDATE hosts SET perf_key=NULL WHERE id=?`, id)
	return err
}

// PerfSecret 返回批准时记下的重连密钥（16 字节）。网关重启后靠它把回来的
// 被控端认回原身份，不用管理员再批准一次。
func PerfSecret(db *sql.DB, id int64) ([]byte, error) {
	var secret []byte
	err := db.QueryRow(`SELECT perf_secret FROM hosts WHERE id=?`, id).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return secret, err
}

// SetPerfSecret 记下（或更新）重连密钥。
func SetPerfSecret(db *sql.DB, id int64, secret []byte) error {
	_, err := db.Exec(`UPDATE hosts SET perf_secret=? WHERE id=?`, secret, id)
	return err
}
