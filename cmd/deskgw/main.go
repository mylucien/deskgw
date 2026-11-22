// deskgw：OpenWrt Web 远程桌面网关。M1 提供登录、用户/主机管理与基础前端。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"syscall"
	"time"

	"github.com/mylucien/deskgw/internal/api"
	"github.com/mylucien/deskgw/internal/auth"
	"github.com/mylucien/deskgw/internal/config"
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
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := ensureInitialUser(st.DB, cfg); err != nil {
		return err
	}
	certFile, keyFile, err := ensureCert(cfg)
	if err != nil {
		return err
	}
	if fp, err := certFingerprint(certFile); err == nil {
		log.Printf("deskgw 证书 SHA-256 指纹: %s", fp)
	}

	mgr := auth.NewManager(cfg.SessionIdleMin)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.New(st.DB, mgr, cfg),
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
		go func() {
			redir := &http.Server{
				Addr: cfg.RedirectListen,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					host := r.Host
					if h, _, err := net.SplitHostPort(host); err == nil {
						_, port, _ := net.SplitHostPort(cfg.Listen)
						host = net.JoinHostPort(h, port)
					}
					http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
				}),
				ReadHeaderTimeout: 5 * time.Second,
			}
			log.Printf("deskgw HTTP 跳转已启动: %s", cfg.RedirectListen)
			errCh <- redir.ListenAndServe()
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
		log.Printf("初始管理员 admin 密码: %s（另存于 %s）", password, p)
	}
	return nil
}

// ensureCert 在证书缺失时生成自签 ECDSA P-256 证书。
func ensureCert(cfg config.Config) (string, string, error) {
	if fileExists(cfg.CertFile) && fileExists(cfg.KeyFile) {
		return cfg.CertFile, cfg.KeyFile, nil
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

func certFingerprint(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("证书格式不正确")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
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
