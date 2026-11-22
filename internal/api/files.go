package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/mylucien/deskgw/internal/filegw"
	"github.com/mylucien/deskgw/internal/host"
	"github.com/mylucien/deskgw/internal/user"
)

const fileTokenHeader = "X-File-Token"

// fileContext 是一次文件请求的已校验上下文。
type fileContext struct {
	userID    int64
	host      host.Host
	sessionID int64
	creds     filegw.Credentials
}

// resolveFile 校验文件令牌、用户权限、主机授权，并取出目标主机。
// 每次文件操作都重新校验，确保权限撤销即时生效。
func (s *Server) resolveFile(w http.ResponseWriter, r *http.Request) (*fileContext, bool) {
	secret := r.Header.Get(fileTokenHeader)
	ip := clientIP(r)
	uid, hostID, sid, creds, err := s.fileTokens.Resolve(secret, ip)
	if err != nil {
		fail(w, http.StatusUnauthorized, "fileToken", "文件令牌无效或已过期")
		return nil, false
	}
	u, err := user.Get(s.db, uid)
	if err != nil || !u.Enabled || !u.AllowFile {
		fail(w, http.StatusForbidden, "forbidden", "当前用户无权使用文件传输")
		return nil, false
	}
	h, err := host.Get(s.db, hostID)
	if err != nil || !h.Enabled {
		fail(w, http.StatusNotFound, "notFound", "主机不存在或已停用")
		return nil, false
	}
	var active int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id=? AND user_id=? AND state IN ('pending','active')`,
		sid, uid).Scan(&active); err != nil || active == 0 {
		fail(w, http.StatusUnauthorized, "session", "关联的远程会话已结束")
		return nil, false
	}
	return &fileContext{userID: uid, host: h, sessionID: sid, creds: creds}, true
}

// createFileToken 用 RDP 连接时输入的凭据签发短期文件令牌。
func (s *Server) createFileToken(w http.ResponseWriter, r *http.Request) {
	sess := fromContext(r.Context())
	var in struct {
		SessionID int64  `json:"session_id"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		Domain    string `json:"domain"`
	}
	if err := readJSON(r, &in); err != nil || in.SessionID < 1 ||
		in.Username == "" || in.Password == "" {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	var hostID, ownerID int64
	var state string
	if err := s.db.QueryRow(`SELECT host_id, state, user_id FROM sessions WHERE id=?`, in.SessionID).
		Scan(&hostID, &state, &ownerID); err != nil {
		fail(w, http.StatusNotFound, "notFound", "会话不存在")
		return
	}
	if ownerID != sess.UserID || (state != "pending" && state != "active") {
		fail(w, http.StatusForbidden, "forbidden", "会话无效")
		return
	}
	u, err := user.Get(s.db, sess.UserID)
	if err != nil || !u.AllowFile {
		fail(w, http.StatusForbidden, "forbidden", "当前用户无权使用文件传输")
		return
	}
	tok, err := s.fileTokens.Issue(sess.UserID, hostID, in.SessionID, clientIP(r),
		filegw.Credentials{Username: in.Username, Password: in.Password, Domain: in.Domain})
	if err != nil {
		serverError(w, err)
		return
	}
	writeAudit(s, sess.UserID, "file.token", strconv.FormatInt(hostID, 10),
		strconv.FormatInt(in.SessionID, 10), clientIP(r))
	ok(w, map[string]any{"token": tok})
}

// openShare 解析共享名并连接，返回调用方负责关闭的 Conn。
func (s *Server) openShare(w http.ResponseWriter, fc *fileContext, shareName string) (*filegw.Conn, string, bool) {
	share, err := filegw.NormalizeShare(shareName)
	if err != nil {
		fail(w, http.StatusBadRequest, "badShare", err.Error())
		return nil, "", false
	}
	conn, err := filegw.Connect(fc.host.Address, fc.host.SBMPort, share, fc.creds)
	if err != nil {
		fail(w, http.StatusBadGateway, "smb", err.Error())
		return nil, "", false
	}
	return conn, share, true
}

// listFiles 列出目录。
func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	fc, ok := s.resolveFile(w, r)
	if !ok {
		return
	}
	dir, err := filegw.NormalizePath(r.URL.Query().Get("path"))
	if err != nil {
		fail(w, http.StatusBadRequest, "badPath", err.Error())
		return
	}
	conn, _, ok := s.openShare(w, fc, r.URL.Query().Get("share"))
	if !ok {
		return
	}
	defer conn.Close()
	entries, err := conn.List(dir)
	if err != nil {
		fail(w, http.StatusBadGateway, "smb", err.Error())
		return
	}
	ok(w, entries)
}

// uploadFile 接收分片字节流，按 offset 写入（断点续传）。
func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) {
	fc, ok := s.resolveFile(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	name, err := filegw.NormalizePath(q.Get("path"))
	if err != nil || name == "" {
		fail(w, http.StatusBadRequest, "badPath", "文件名不合法")
		return
	}
	offset, err := strconv.ParseInt(q.Get("offset"), 10, 64)
	if err != nil || offset < 0 {
		fail(w, http.StatusBadRequest, "badRequest", "分片偏移不合法")
		return
	}
	limit := int64(s.settingInt("max_upload_mb", 2048)) << 20
	conn, share, ok := s.openShare(w, fc, q.Get("share"))
	if !ok {
		return
	}
	defer conn.Close()
	f, err := conn.OpenWrite(name, offset)
	if err != nil {
		fail(w, http.StatusBadGateway, "smb", err.Error())
		return
	}
	written, err := io.Copy(f, io.LimitReader(r.Body, limit+1))
	cerr := f.Close()
	if written > limit {
		fail(w, http.StatusRequestEntityTooLarge, "tooLarge", "分片超过单文件上限")
		return
	}
	if err != nil {
		fail(w, http.StatusBadGateway, "smb", err.Error())
		return
	}
	if cerr != nil {
		fail(w, http.StatusBadGateway, "smb", cerr.Error())
		return
	}
	writeAudit(s, fc.userID, "file.upload", fmt.Sprintf(`\%s\%s\%s`, fc.host.Address, share, name),
		fmt.Sprintf("offset=%d bytes=%d", offset, written), clientIP(r))
	ok(w, map[string]any{"written": written, "offset": offset + written})
}

// downloadFile 流式下载，支持 HTTP Range。
func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request) {
	fc, ok := s.resolveFile(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	name, err := filegw.NormalizePath(q.Get("path"))
	if err != nil || name == "" {
		fail(w, http.StatusBadRequest, "badPath", "文件名不合法")
		return
	}
	conn, share, ok := s.openShare(w, fc, q.Get("share"))
	if !ok {
		return
	}
	defer conn.Close()
	info, err := conn.Stat(name)
	if err != nil || info.IsDir() {
		fail(w, http.StatusNotFound, "notFound", "文件不存在")
		return
	}
	f, err := conn.OpenRead(name)
	if err != nil {
		fail(w, http.StatusBadGateway, "smb", err.Error())
		return
	}
	defer f.Close()

	start, end, size := int64(0), info.Size()-1, info.Size()
	status := http.StatusOK
	if rng := r.Header.Get("Range"); strings.HasPrefix(rng, "bytes=") {
		if p := strings.Split(strings.TrimPrefix(rng, "bytes="), "-"); len(p) == 2 {
			if v, e := strconv.ParseInt(p[0], 10, 64); e == nil && v >= 0 && v < size {
				start = v
				if p[1] != "" {
					if e2, e := strconv.ParseInt(p[1], 10, 64); e == nil && e2 >= start && e2 < size {
						end = e2
					}
				}
				status = http.StatusPartialContent
			}
		}
	}
	if start > 0 {
		if _, err := f.Seek(start, 0); err != nil {
			fail(w, http.StatusBadGateway, "smb", err.Error())
			return
		}
	}
	length := end - start + 1
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlPath(name))
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	if status == http.StatusPartialContent {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, io.LimitReader(f, length))
	writeAudit(s, fc.userID, "file.download", fmt.Sprintf(`\%s\%s\%s`, fc.host.Address, share, name),
		fmt.Sprintf("range=%d-%d", start, end), clientIP(r))
}

// fileMutation 处理 mkdir / rename / delete。
func (s *Server) fileMutation(w http.ResponseWriter, r *http.Request, kind string) {
	fc, ok := s.resolveFile(w, r)
	if !ok {
		return
	}
	var in struct {
		Share   string `json:"share"`
		Path    string `json:"path"`
		NewPath string `json:"new_path"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	p, err := filegw.NormalizePath(in.Path)
	if err != nil || p == "" {
		fail(w, http.StatusBadRequest, "badPath", "路径不合法")
		return
	}
	conn, share, ok := s.openShare(w, fc, in.Share)
	if !ok {
		return
	}
	defer conn.Close()
	target := fmt.Sprintf(`\%s\%s\%s`, fc.host.Address, share, p)
	switch kind {
	case "mkdir":
		err = conn.Mkdir(p)
	case "delete":
		err = conn.Remove(p)
	case "rename":
		np, e := filegw.NormalizePath(in.NewPath)
		if e != nil || np == "" {
			fail(w, http.StatusBadRequest, "badPath", "新路径不合法")
			return
		}
		err = conn.Rename(p, np)
		target += " -> " + np
	}
	if err != nil {
		fail(w, http.StatusBadGateway, "smb", err.Error())
		return
	}
	writeAudit(s, fc.userID, "file."+kind, target, "", clientIP(r))
	ok(w, map[string]any{})
}

// urlPath 对文件名做 URL 编码，供 Content-Disposition 使用。
func urlPath(name string) string {
	var b strings.Builder
	for _, c := range []byte(name) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

// settingInt 读取整数型设置。
func (s *Server) settingInt(key string, def int) int {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
