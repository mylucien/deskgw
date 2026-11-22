// Package user 实现 Web 用户与主机授权的持久化。
package user

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/mylucien/deskgw/internal/auth"
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)

// User 对应 users 表。
type User struct {
	ID             int64   `json:"id"`
	Username       string  `json:"username"`
	Role           string  `json:"role"`
	Enabled        bool    `json:"enabled"`
	AllowFile      bool    `json:"allow_file"`
	AllowClipboard bool    `json:"allow_clipboard"`
	MaxSessions    int     `json:"max_sessions"`
	HasTOTP        bool    `json:"has_totp"`
	CreatedAt      int64   `json:"created_at"`
	HostIDs        []int64 `json:"host_ids"`
}

type scanner interface{ Scan(dest ...any) error }

func scanUser(s scanner) (User, error) {
	var u User
	var enabled, file, clip, totp int
	err := s.Scan(&u.ID, &u.Username, &u.Role, &enabled, &file, &clip,
		&u.MaxSessions, &totp, &u.CreatedAt)
	u.Enabled = enabled != 0
	u.AllowFile = file != 0
	u.AllowClipboard = clip != 0
	u.HasTOTP = totp != ""
	return u, err
}

const columns = `id, username, role, enabled, allow_file, allow_clipboard, max_sessions, totp_secret, created_at`

// List 返回全部用户。
func List(db *sql.DB) ([]User, error) {
	rows, err := db.Query(`SELECT ` + columns + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	for i := range out {
		ids, err := grants(db, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].HostIDs = ids
	}
	return out, rows.Err()
}

// Get 按 ID 查询用户。
func Get(db *sql.DB, id int64) (User, error) {
	u, err := scanUser(db.QueryRow(`SELECT `+columns+` FROM users WHERE id = ?`, id))
	if err != nil {
		return u, err
	}
	u.HostIDs, err = grants(db, id)
	return u, err
}

// GetByUsername 按用户名查询用户，同时返回密码哈希。
func GetByUsername(db *sql.DB, username string) (User, string, error) {
	u, err := scanUser(db.QueryRow(`SELECT `+columns+` FROM users WHERE username = ?`, username))
	if err != nil {
		return u, "", err
	}
	var hash string
	if err := db.QueryRow(`SELECT pass_hash FROM users WHERE username = ?`, username).Scan(&hash); err != nil {
		return u, "", err
	}
	return u, hash, nil
}

func grants(db *sql.DB, userID int64) ([]int64, error) {
	rows, err := db.Query(`SELECT host_id FROM user_hosts WHERE user_id = ? ORDER BY host_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Validate 校验用户名与角色。
func Validate(username, role string) error {
	if !usernameRE.MatchString(username) {
		return errors.New("用户名须为 3–32 位字母、数字、点、下划线或连字符")
	}
	if role != "admin" && role != "user" {
		return errors.New("角色只能是 admin 或 user")
	}
	return nil
}

// Create 创建用户。
func Create(db *sql.DB, u User, password string, hostIDs []int64) (int64, error) {
	if err := Validate(u.Username, u.Role); err != nil {
		return 0, err
	}
	if len(password) < 8 {
		return 0, errors.New("密码至少 8 位")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return 0, err
	}
	res, err := db.Exec(`INSERT INTO users
		(username, pass_hash, role, enabled, allow_file, allow_clipboard, max_sessions, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Username, hash, u.Role, b(u.Enabled), b(u.AllowFile), b(u.AllowClipboard),
		u.MaxSessions, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := SetGrants(db, id, hostIDs); err != nil {
		return 0, err
	}
	return id, nil
}

// Update 更新用户资料；password 为空表示不改密码。
func Update(db *sql.DB, id int64, u User, password string, hostIDs []int64) error {
	if err := Validate(u.Username, u.Role); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var res sql.Result
	if password == "" {
		res, err = tx.Exec(`UPDATE users SET username=?, role=?, enabled=?, allow_file=?,
			allow_clipboard=?, max_sessions=? WHERE id=?`,
			u.Username, u.Role, b(u.Enabled), b(u.AllowFile), b(u.AllowClipboard), u.MaxSessions, id)
	} else {
		if len(password) < 8 {
			return errors.New("密码至少 8 位")
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return err
		}
		res, err = tx.Exec(`UPDATE users SET username=?, pass_hash=?, role=?, enabled=?,
			allow_file=?, allow_clipboard=?, max_sessions=? WHERE id=?`,
			u.Username, hash, u.Role, b(u.Enabled), b(u.AllowFile), b(u.AllowClipboard), u.MaxSessions, id)
		if err != nil {
			return err
		}
	}
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
	if _, err := tx.Exec(`DELETE FROM user_hosts WHERE user_id = ?`, id); err != nil {
		return err
	}
	for _, hid := range hostIDs {
		if _, err := tx.Exec(`INSERT INTO user_hosts (user_id, host_id) VALUES (?, ?)`, id, hid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetGrants 重设用户可访问的主机列表。
func SetGrants(db *sql.DB, userID int64, hostIDs []int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM user_hosts WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, hid := range hostIDs {
		if _, err := tx.Exec(`INSERT INTO user_hosts (user_id, host_id) VALUES (?, ?)`, userID, hid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Delete 删除用户。
func Delete(db *sql.DB, id int64) error {
	res, err := db.Exec(`DELETE FROM users WHERE id = ?`, id)
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

// Count 返回用户数，用于首次启动引导。
func Count(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func b(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ErrNotFound 是通用不存在错误。
var ErrNotFound = sql.ErrNoRows

// FormatErr 把数据库错误转成用户可读信息。
func FormatErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("对象不存在")
	}
	return err
}
