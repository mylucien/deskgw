// Package store 负责 SQLite 数据库打开与 schema 迁移。
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const schemaVersion = 3

// Store 包装数据库连接。
type Store struct {
	DB *sql.DB
}

// Open 打开（或创建）数据库并执行迁移。
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("创建数据目录失败: %w", err)
		}
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate() error {
	var v int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v > schemaVersion {
		return fmt.Errorf("数据库版本 %d 高于程序支持版本 %d", v, schemaVersion)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if v < 1 {
		for _, stmt := range schemaV1 {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("执行 schema v1 失败: %w", err)
			}
		}
		if _, err := tx.Exec("PRAGMA user_version = 1"); err != nil {
			return err
		}
	}
	if v < 2 {
		for _, stmt := range schemaV2 {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("执行 schema v2 失败: %w", err)
			}
		}
		if _, err := tx.Exec("PRAGMA user_version = 2"); err != nil {
			return err
		}
	}
	if v < 3 {
		for _, stmt := range schemaV3 {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("执行 schema v3 失败: %w", err)
			}
		}
		if _, err := tx.Exec("PRAGMA user_version = 3"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var schemaV1 = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		pass_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		enabled INTEGER NOT NULL DEFAULT 1,
		allow_file INTEGER NOT NULL DEFAULT 1,
		allow_clipboard INTEGER NOT NULL DEFAULT 1,
		max_sessions INTEGER NOT NULL DEFAULT 2,
		totp_secret TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		address TEXT NOT NULL,
		rdp_port INTEGER NOT NULL DEFAULT 3389,
		smb_port INTEGER NOT NULL DEFAULT 445,
		group_name TEXT NOT NULL DEFAULT '',
		note TEXT NOT NULL DEFAULT '',
		enabled INTEGER NOT NULL DEFAULT 1,
		modes TEXT NOT NULL DEFAULT 'rdp',
		perf_key BLOB,
		perf_secret BLOB,
		perf_name TEXT NOT NULL DEFAULT '',
		perf_os TEXT NOT NULL DEFAULT '',
		perf_last_seen INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS user_hosts (
		user_id INTEGER NOT NULL,
		host_id INTEGER NOT NULL,
		PRIMARY KEY (user_id, host_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		host_id INTEGER NOT NULL,
		client_ip TEXT NOT NULL DEFAULT '',
		started_at INTEGER NOT NULL,
		ended_at INTEGER,
		state TEXT NOT NULL DEFAULT 'active',
		mode TEXT NOT NULL DEFAULT 'rdp'
	)`,
	`CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		user_id INTEGER,
		action TEXT NOT NULL,
		target TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		client_ip TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS perf_pending (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL DEFAULT '',
		os TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '',
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state)`,
}

// schemaV2 补齐高频查询的索引：
//   - 并发配额检查按 (user_id, state) 计数；
//   - 僵尸会话清理按 (state, ended_at) 扫描；
//   - 审计页按用户或动作过滤。
var schemaV2 = []string{
	`CREATE INDEX IF NOT EXISTS idx_sessions_user_state ON sessions(user_id, state)`,
	`CREATE INDEX IF NOT EXISTS idx_sessions_open ON sessions(state, ended_at)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)`,
}

// schemaV3 给会话补上结束原因。
//
// ALTER TABLE 不能重复执行，所以只能放在独立版本里靠 user_version 控制；
// 新建的库同样会走这一步（V1 建表时不带该列）。
var schemaV3 = []string{
	`ALTER TABLE sessions ADD COLUMN detail TEXT NOT NULL DEFAULT ''`,
}
