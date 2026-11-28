// deskgw：OpenWrt Web 远程桌面网关。当前实现 RDP 隧道、多标签会话与 SMB 文件网关。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mylucien/deskgw/internal/api"
	"github.com/mylucien/deskgw/internal/audit"
	"github.com/mylucien/deskgw/internal/auth"
	"github.com/mylucien/deskgw/internal/config"
	"github.com/mylucien/deskgw/internal/host"
	"github.com/mylucien/deskgw/internal/perfgw"
	"github.com/mylucien/deskgw/internal/store"
	"github.com/mylucien/deskgw/internal/user"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := run(config.Load()); err != nil {
		log.Fatalf("deskgw: %v", err)
	}
}

func run(cfg config.Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("创建数据目录: %w", err)
	}
	// 默认目录在 /etc（OpenWrt 上是 overlay）：审计、会话、SQLite 的 WAL 会持续
	// 写闪存，长期运行对 eMMC/闪存不友好。不改默认值——老用户升级后数据会
	// 「消失」——但必须在启动日志里留一句，否则只有打开 LuCI 才知道能改。
	if cfg.DataDir == "/etc/deskgw" {
		log.Printf("提示: 数据目录是默认值 /etc/deskgw（overlay 上，会持续写闪存）；" +
			"长期运行建议改到外部存储，例如 /mnt/usb/deskgw，并让它先于本服务挂载")
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := ensureInitialUser(st.DB, cfg); err != nil {
		return err
	}
	// 把 UCI 的值作为「首次默认值」写进数据库。之后以数据库为准：
	// 两个来源各存一份、谁优先说不清，正是「后台保存过一次，LuCI 就永远失效」
	// 这类问题的根源。现在语义明确：UCI 只在没有数据库记录时生效。
	seedSettings(st.DB, cfg)
	certFile, keyFile, err := ensureCert(cfg)
	if err != nil {
		return err
	}
	if fp, err := certFingerprint(certFile); err == nil {
		log.Printf("deskgw 证书 SHA-256 指纹: %s", fp)
	}

	// 性能模式可选：端口占用或证书损坏时只记日志，不影响 RDP 与文件功能。
	var perf *perfgw.Server
	if cfg.PerfEnabled {
		perfSrv, err := perfgw.New(cfg)
		if err != nil {
			log.Printf("警告: 性能模式未启动: %v", err)
		} else {
			perf = perfSrv
			// 第一次握手学到的被控端公钥记下来，之后走 Noise IK。
			perf.OnPeerKey(func(code uint32, pub []byte) {
				if err := host.SetPerfKey(st.DB, int64(code), pub); err != nil {
					log.Printf("性能模式：记录被控端公钥失败（主机 %d）: %v", code, err)
				}
			})
			// 批准结果与重连密钥落库：网关重启后被控端带着控制码回来时能直接
			// 认回身份，不用再批准一遍。
			perf.OnAdopt(func(code uint32, secret [16]byte) bool {
				want, err := host.PerfSecret(st.DB, int64(code))
				return err == nil && len(want) == len(secret) &&
					subtle.ConstantTimeCompare(want, secret[:]) == 1
			})
			perf.OnApproved(func(hostID int64, secret [16]byte) {
				if err := host.SetPerfSecret(st.DB, hostID, secret[:]); err != nil {
					log.Printf("性能模式：记录重连密钥失败（主机 %d）: %v", hostID, err)
				}
			})
			perf.OnSecret(func(hostID uint32, secret [16]byte) {
				if err := host.SetPerfSecret(st.DB, int64(hostID), secret[:]); err != nil {
					log.Printf("性能模式：更新重连密钥失败（主机 %d）: %v", hostID, err)
				}
			})
			perf.OnRegister(func(p perfgw.Pending) {
				_ = audit.Write(st.DB, nil, "perf.host_register", p.Name, p.IP, p.IP)
			})
			perf.OnOnline(func(code uint32, name, os string, lastSeen int64) {
				if err := host.SetPerfMeta(st.DB, int64(code), name, os, lastSeen); err != nil {
					log.Printf("性能模式：更新最近在线失败（主机 %d）: %v", code, err)
				}
			})
			perf.Start()
			defer perf.Close()
			log.Printf("性能模式已启动: %s（被控端的 server_fp 填 %s，[[paired]].key 填 %s）",
				perf.Listen(), perf.Fingerprint(), perf.Identity())
		}
	}

	// 审计日志保留 90 天，每 24 小时清理一次过期记录。
	go func() {
		_ = audit.Purge(st.DB, 90)
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for range t.C {
			if err := audit.Purge(st.DB, 90); err != nil {
				log.Printf("清理审计日志失败: %v", err)
			}
		}
	}()

	mgr := auth.NewManager(cfg.SessionIdleMin)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.New(st.DB, mgr, cfg, perf),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", cfg.Listen, err)
	}
	errCh := make(chan error, 2)
	go func() {
		log.Printf("deskgw HTTPS 已启动: https://%s", cfg.Listen)
		errCh <- srv.ServeTLS(ln, certFile, keyFile)
	}()

	if cfg.RedirectListen != "" {
		// 跳转只是便利功能：端口被占、权限不足时只记日志，不能让整个网关退出。
		// 原实现把它接进 errCh，80 端口被 LuCI（uhttpd）占用时服务就起不来。
		redir := &http.Server{
			Addr: cfg.RedirectListen,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 端口一律取 HTTPS 的实际监听端口，不能沿用请求里的端口：
				// HTTP 跳转监听 8080 时，请求 Host 是 :8080，而 HTTPS 在 :8443。
				host := r.Host
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				host = strings.Trim(host, "[]")
				if _, port, err := net.SplitHostPort(cfg.Listen); err == nil && port != "" && port != "443" {
					// JoinHostPort 会给 IPv6 补方括号；手工拼字符串会得到
					// https://fe80::1:8443 这种无法解析的地址。
					host = net.JoinHostPort(host, port)
				} else if strings.Contains(host, ":") {
					host = "[" + host + "]"
				}
				http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Printf("deskgw HTTP 跳转已启动: %s", cfg.RedirectListen)
			if err := redir.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("警告: HTTP 跳转监听失败（不影响主服务）: %v", err)
			}
		}()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = redir.Shutdown(ctx)
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("收到 %s，正在退出", s)
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// seedSettings 在设置表里补齐缺失项，值取自 UCI（经环境变量传入）。
// 已存在的键不动：管理员在后台改过之后，重启不能把值又拉回 UCI 的旧值。
func seedSettings(db *sql.DB, cfg config.Config) {
	defaults := map[string]string{
		"session_idle_min":  strconv.Itoa(cfg.SessionIdleMin),
		"max_upload_mb":     strconv.Itoa(cfg.MaxUploadMB),
		"perf.max_sessions": "2",
		"perf.max_per_host": "1",
	}
	for k, v := range defaults {
		if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO NOTHING`, k, v); err != nil {
			log.Printf("警告: 写入默认设置 %s 失败: %v", k, err)
		}
	}
}

// ensureInitialUser 在没有用户时创建初始管理员。
func ensureInitialUser(db *sql.DB, cfg config.Config) error {
	n, err := user.Count(db)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	password := cfg.InitialPassword
	if password == "" {
		password = auth.RandomToken(12)
	}
	u := user.User{
		Username: "admin", Role: "admin", Enabled: true,
		AllowFile: true, AllowClipboard: true, MaxSessions: 2,
	}
	if _, err := user.Create(db, u, password, nil); err != nil {
		return err
	}
	if cfg.InitialPassword == "" {
		p := filepath.Join(cfg.DataDir, "initial-password.txt")
		if err := os.WriteFile(p, []byte(password+"\n"), 0o600); err != nil {
			log.Printf("警告: 无法保存初始密码: %v", err)
		}
		// 不把明文密码写进 syslog / 串口控制台：日志常被转发到远端或留在闪存里。
		log.Printf("已创建初始管理员 admin，初始密码见 %s（首次登录后请立即修改）", p)
	}
	return nil
}

// ensureCert 在证书缺失时生成自签 ECDSA P-256 证书。
// 若现有证书是本程序生成的自签证书，而 DESKGW_CERT_NAMES 已经变化，
// 则重新签发，使 LuCI 里修改证书名称后重启即可生效。
// 用户自备的证书（非自签或 CN 不是 deskgw）不会被覆盖。
func ensureCert(cfg config.Config) (string, string, error) {
	if fileExists(cfg.CertFile) && fileExists(cfg.KeyFile) {
		cert, err := loadCert(cfg.CertFile)
		if err != nil {
			// 证书损坏或格式不受支持：让 TLS 启动时报错，不擅自覆盖用户文件。
			return cfg.CertFile, cfg.KeyFile, nil
		}
		if !isOwnCert(cert) || certCovers(cert, cfg.CertNames) {
			return cfg.CertFile, cfg.KeyFile, nil
		}
		log.Printf("证书名称已变更，重新生成自签证书: %v", cfg.CertNames)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "deskgw"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range cfg.CertNames {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(cfg.CertFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(cfg.KeyFile,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}
	return cfg.CertFile, cfg.KeyFile, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("证书格式不正确")
	}
	return x509.ParseCertificate(block.Bytes)
}

// isOwnCert 判断证书是否由本程序自动生成（自签且 CN=deskgw）。
func isOwnCert(cert *x509.Certificate) bool {
	return cert.Subject.CommonName == "deskgw" && cert.Issuer.String() == cert.Subject.String()
}

// certCovers 检查证书的 SAN 是否覆盖所有配置的域名/IP。
func certCovers(cert *x509.Certificate, names []string) bool {
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			found := false
			for _, have := range cert.IPAddresses {
				if have.Equal(ip) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
			continue
		}
		found := false
		for _, have := range cert.DNSNames {
			if strings.EqualFold(have, n) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func certFingerprint(path string) (string, error) {
	cert, err := loadCert(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Size() > 0
}
