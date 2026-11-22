// Package config 从环境变量读取网关配置。OpenWrt 的 init 脚本把 UCI 选项映射为这些变量。
package config

import (
	"os"
	"strconv"
	"strings"
)

// Config 是网关运行参数。
type Config struct {
	Listen          string
	RedirectListen  string
	CertFile        string
	KeyFile         string
	CertNames       []string
	DataDir         string
	DBPath          string
	InitialPassword string
	CookieSecure    bool
	SessionIdleMin  int
	MaxUploadMB     int
}

// Load 读取环境变量，未设置时使用默认值。
func Load() Config {
	c := Config{
		Listen:          env("DESKGW_LISTEN", "0.0.0.0:8443"),
		RedirectListen:  os.Getenv("DESKGW_REDIRECT_LISTEN"),
		CertFile:        env("DESKGW_CERT", ""),
		KeyFile:         env("DESKGW_KEY", ""),
		DataDir:         env("DESKGW_DATA_DIR", "/etc/deskgw"),
		InitialPassword: os.Getenv("DESKGW_INITIAL_PASSWORD"),
		CookieSecure:    envBool("DESKGW_COOKIE_SECURE", true),
		SessionIdleMin:  envInt("DESKGW_SESSION_IDLE_MIN", 30),
		MaxUploadMB:     envInt("DESKGW_MAX_UPLOAD_MB", 2048),
	}
	names := os.Getenv("DESKGW_CERT_NAMES")
	if names == "" {
		names = "localhost,127.0.0.1"
	}
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			c.CertNames = append(c.CertNames, n)
		}
	}
	if c.CertFile == "" || c.KeyFile == "" {
		c.CertFile = c.DataDir + "/server.crt"
		c.KeyFile = c.DataDir + "/server.key"
	}
	if p := os.Getenv("DESKGW_DB"); p != "" {
		c.DBPath = p
	} else {
		c.DBPath = c.DataDir + "/data.db"
	}
	return c
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v, err := strconv.Atoi(os.Getenv(k))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
