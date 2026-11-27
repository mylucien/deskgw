package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/mylucien/deskgw/internal/filegw"
	"github.com/mylucien/deskgw/internal/host"
	"github.com/mylucien/deskgw/internal/textutil"
	"github.com/mylucien/deskgw/internal/user"
)

const fileTokenHeader = "X-File-Token"

// copyBufPool 提供下载用的 1MiB 缓冲。
//
// 一次 SMB2 READ 能取回的数据量受协商的 MaxReadSize 限制（Windows 通常
// 1MiB）。net/http 的 ResponseWriter 实现了 ReaderFrom，内部只用 32KiB
// 缓冲循环读取；对 SMB 这种「一次 Read 一次网络往返」的后端，等于每 32KiB
// 就多一个 RTT。自己给缓冲后往返次数降到 1/32。
//
// 并发下载数受 filegw 的连接名额约束（24），池中同时存活的缓冲不会超过
// 24MiB，对路由器内存是可控的。
var copyBufPool = sync.Pool{
	New: func() any { return make([]byte, 1<<20) },
}

// writerOnly 只暴露 Write，把 http.ResponseWriter 的 ReadFrom 藏起来：
// io.CopyBuffer 遇到实现了 ReaderFrom 的目标会忽略传入的缓冲区。
type writerOnly struct{ io.Writer }

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
	return s.resolveFileOpt(w, r, false)
}

// resolveFileOpt 在 allowQuery 为真时也接受 ?ft= 形式的令牌。
// 仅用于下载：浏览器原生下载无法附加自定义请求头，而把整个文件读进
// 内存（blob）会让大文件失败，所以下载改用短期令牌放在查询串里。
//
// 这里**不用 401**：前端的全局拦截把 401 当作「登录态失效」并整页跳转登录，
// 而文件令牌过期、关联会话结束都是文件面板自己的事。用 403/410 表达，
// 让前端就地提示并重新换取令牌，不会把用户所有标签页的远程会话一起弄断。
func (s *Server) resolveFileOpt(w http.ResponseWriter, r *http.Request, allowQuery bool) (*fileContext, bool) {
	secret := r.Header.Get(fileTokenHeader)
	if secret == "" && allowQuery {
		secret = r.URL.Query().Get("ft")
	}
	if secret == "" {
		fail(w, http.StatusForbidden, "fileToken", "文件令牌无效或已过期，请重新启用文件传输")
		return nil, false
	}
	ip := clientIP(r)
	uid, hostID, sid, creds, err := s.fileTokens.Resolve(secret, ip)
	if err != nil {
		fail(w, http.StatusForbidden, "fileToken", "文件令牌无效或已过期，请重新启用文件传输")
		return nil, false
	}
	// 一次查询取齐用户、主机、授权与会话状态。原实现每请求 4 次查库
	// （用户 + 授权 + 主机 + 会话计数），上传时每个分片都重复一遍，
	// 而数据库只有一条连接，分片请求会互相排队。
	var fc fileContext
	var enabled, allowFile, hostEnabled, granted, active int
	var role string
	err = s.db.QueryRow(`SELECT u.id, u.role, u.enabled, u.allow_file,
			h.id, h.name, h.address, h.rdp_port, h.smb_port, h.enabled,
			(SELECT COUNT(*) FROM user_hosts WHERE user_id=u.id AND host_id=h.id),
			(SELECT COUNT(*) FROM sessions WHERE id=? AND user_id=u.id AND state IN ('pending','active'))
		FROM users u, hosts h WHERE u.id=? AND h.id=?`, sid, uid, hostID).
		Scan(&fc.userID, &role, &enabled, &allowFile,
			&fc.host.ID, &fc.host.Name, &fc.host.Address, &fc.host.RDPPort, &fc.host.SMBPort, &hostEnabled,
			&granted, &active)
	if err != nil {
		fail(w, http.StatusGone, "session", "关联的远程会话已结束")
		return nil, false
	}
	if enabled == 0 || allowFile == 0 {
		fail(w, http.StatusForbidden, "forbidden", "当前用户无权使用文件传输")
		return nil, false
	}
	if hostEnabled == 0 {
		fail(w, http.StatusNotFound, "notFound", "主机不存在或已停用")
		return nil, false
	}
	// 授权必须每次重查：管理员撤销授权后，旧令牌不应继续可用。
	// 会话检查同样如此，否则「强制下线」后文件令牌还能读文件。
	if role != "admin" && granted == 0 {
		fail(w, http.StatusForbidden, "forbidden", "主机授权已撤销，请重新登录后再试")
		return nil, false
	}
	if active == 0 {
		fail(w, http.StatusGone, "session", "关联的远程会话已结束")
		return nil, false
	}
	fc.sessionID = sid
	fc.creds = creds
	return &fc, true
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
		filegw.Credentials{Username: in.Username, Password: []byte(in.Password), Domain: in.Domain})
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
	conn, err := filegw.Connect(fc.host.Address, fc.host.SMBPort, share, fc.creds)
	if err != nil {
		smbError(w, err)
		return nil, "", false
	}
	return conn, share, true
}

// smbError 把 SMB 侧错误映射成状态码。
//
// 并发达上限是「稍后重试」，不是网关坏了：原来一律回 502，监控和用户都会
// 误以为是目标主机的问题。503 + Retry-After 才能让前端知道该等一会儿。
func smbError(w http.ResponseWriter, err error) {
	if errors.Is(err, filegw.ErrTooManyConns) {
		w.Header().Set("Retry-After", "5")
		fail(w, http.StatusServiceUnavailable, "busy", "文件连接数已达上限，请稍后重试")
		return
	}
	fail(w, http.StatusBadGateway, "smb", err.Error())
}

// listFiles 列出目录。
func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	fc, valid := s.resolveFile(w, r)
	if !valid {
		return
	}
	dir, err := filegw.NormalizePath(r.URL.Query().Get("path"))
	if err != nil {
		fail(w, http.StatusBadRequest, "badPath", err.Error())
		return
	}
	conn, _, valid := s.openShare(w, fc, r.URL.Query().Get("share"))
	if !valid {
		return
	}
	defer conn.Close()
	entries, err := conn.List(dir)
	if err != nil {
		smbError(w, err)
		return
	}
	ok(w, entries)
}

// maxUploadBytes 返回单文件上传上限（字节）。
func (s *Server) maxUploadBytes() int64 {
	return int64(s.settingInt("max_upload_mb", s.cfg.MaxUploadMB)) << 20
}

// beginUpload 建立分片上传会话：整条上传复用一条 SMB 连接，
// 避免每 4MiB 分片重新拨号 + NTLM 认证，也保证零字节文件能被创建。
func (s *Server) beginUpload(w http.ResponseWriter, r *http.Request) {
	fc, valid := s.resolveFile(w, r)
	if !valid {
		return
	}
	var in struct {
		Share     string `json:"share"`
		Path      string `json:"path"`
		Size      int64  `json:"size"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	name, err := filegw.NormalizePath(in.Path)
	if err != nil || name == "" {
		fail(w, http.StatusBadRequest, "badPath", "文件名不合法")
		return
	}
	if in.Size < 0 {
		fail(w, http.StatusBadRequest, "badRequest", "文件大小不合法")
		return
	}
	if in.Size > s.maxUploadBytes() {
		fail(w, http.StatusRequestEntityTooLarge, "tooLarge", "文件超过单文件上限")
		return
	}
	share, err := filegw.NormalizeShare(in.Share)
	if err != nil {
		fail(w, http.StatusBadRequest, "badShare", err.Error())
		return
	}
	up, exists, err := filegw.BeginUpload(fc.host.Address, fc.host.SMBPort, share, name, in.Size, fc.creds)
	if err != nil {
		up.Close()
		smbError(w, err)
		return
	}
	// 同名文件不再静默覆盖：确认动作交给前端，服务端只负责拒绝与放行。
	if exists && !in.Overwrite {
		up.Close()
		fail(w, http.StatusConflict, "exists", "目标文件已存在，确认覆盖后重试")
		return
	}
	id, err := s.uploads.Add(up, fc.userID, fc.host.ID, fc.sessionID)
	if err != nil {
		up.Close()
		if errors.Is(err, filegw.ErrTooManyUploads) {
			fail(w, http.StatusTooManyRequests, "tooManyUploads", err.Error())
			return
		}
		serverError(w, err)
		return
	}
	ok(w, map[string]any{"upload_id": id, "size": in.Size})
}

// uploadChunk 把一个分片写入已建立的上传会话。
func (s *Server) uploadChunk(w http.ResponseWriter, r *http.Request) {
	fc, valid := s.resolveFile(w, r)
	if !valid {
		return
	}
	id := r.URL.Query().Get("upload_id")
	offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err != nil || offset < 0 {
		fail(w, http.StatusBadRequest, "badRequest", "分片偏移不合法")
		return
	}
	up, found := s.uploads.Get(id, fc.userID, fc.sessionID)
	if !found {
		fail(w, http.StatusNotFound, "upload", "上传会话不存在或已过期")
		return
	}
	limit := s.maxUploadBytes()
	if offset >= limit {
		fail(w, http.StatusRequestEntityTooLarge, "tooLarge", "分片偏移超过单文件上限")
		return
	}
	allowed := limit - offset
	if r.ContentLength > allowed {
		fail(w, http.StatusRequestEntityTooLarge, "tooLarge", "文件超过单文件上限")
		return
	}
	if offset != up.Offset() {
		// 带上服务端当前偏移：前端据此从正确位置续传，而不是整条作废。
		failWith(w, http.StatusConflict, "uploadOffset", "分片偏移不连续",
			map[string]any{"offset": up.Offset()})
		return
	}
	written, err := up.WriteChunk(offset, r.Body, allowed)
	if err != nil {
		if errors.Is(err, filegw.ErrUploadOffset) {
			failWith(w, http.StatusConflict, "uploadOffset", "分片偏移不连续",
				map[string]any{"offset": up.Offset()})
			return
		}
		smbError(w, err)
		return
	}
	// 只有恰好写满剩余额度时才需要探测是否有第 allowed+1 个字节；
	// 探测只读不写，保证不会越界多写一个字节。
	if written == allowed {
		var probe [1]byte
		if n, _ := r.Body.Read(probe[:]); n > 0 {
			fail(w, http.StatusRequestEntityTooLarge, "tooLarge", "文件超过单文件上限")
			return
		}
	}
	ok(w, map[string]any{"written": written, "offset": offset + written})
}

// finishUpload 结束上传并记录一条审计（而不是每个分片一条）。
func (s *Server) finishUpload(w http.ResponseWriter, r *http.Request) {
	fc, valid := s.resolveFile(w, r)
	if !valid {
		return
	}
	var in struct {
		UploadID string `json:"upload_id"`
		// Path 与 Share 只为兼容旧前端而保留，审计一律使用 begin 时记录的值，
		// 否则调用方可以随便填一个路径来伪造审计记录。
		Path  string `json:"path"`
		Share string `json:"share"`
	}
	if err := readJSON(r, &in); err != nil || in.UploadID == "" {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	up, found := s.uploads.Get(in.UploadID, fc.userID, fc.sessionID)
	if !found {
		fail(w, http.StatusNotFound, "upload", "上传会话不存在或已过期")
		return
	}
	size := up.Offset()
	// begin 时声明过大小就必须收满：缺一片也提交，落盘的是一个看起来正常
	// 实则被截断的文件，比直接报错危险得多。
	if want := up.Size(); want >= 0 && size != want {
		failWith(w, http.StatusConflict, "uploadIncomplete",
			"上传未完成，请从断点继续", map[string]any{"size": size, "expect": want})
		return
	}
	// 关掉临时文件并改名到目标路径。失败时临时文件会被清理，目标文件保持原样。
	if err := up.Commit(); err != nil {
		s.uploads.Drop(in.UploadID)
		smbError(w, err)
		return
	}
	s.uploads.Drop(in.UploadID)
	writeAudit(s, fc.userID, "file.upload",
		fmt.Sprintf(`\%s\%s\%s`, fc.host.Address, up.ShareName(), up.TargetPath()),
		fmt.Sprintf("bytes=%d", size), clientIP(r))
	ok(w, map[string]any{"bytes": size})
}

// abortUpload 放弃上传并释放 SMB 连接。
func (s *Server) abortUpload(w http.ResponseWriter, r *http.Request) {
	fc, valid := s.resolveFile(w, r)
	if !valid {
		return
	}
	var in struct {
		UploadID string `json:"upload_id"`
	}
	if err := readJSON(r, &in); err != nil || in.UploadID == "" {
		fail(w, http.StatusBadRequest, "badRequest", "请求格式不正确")
		return
	}
	if _, found := s.uploads.Get(in.UploadID, fc.userID, fc.sessionID); found {
		s.uploads.Drop(in.UploadID)
	}
	ok(w, map[string]any{})
}

// uploadFile 接收单个分片（兼容旧接口）。新前端应使用 begin/chunk/finish，
// 以便复用 SMB 连接并且只在上传结束时记一条审计。
func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) {
	fc, valid := s.resolveFile(w, r)
	if !valid {
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
	// 默认值来自 UCI 的 max_upload_mb（经环境变量传入），
	// 后台保存过设置后以数据库为准。
	limit := s.maxUploadBytes()
	// 总量上限按 offset 计算：分片可续传，但任何一片都不得让文件突破总上限。
	if offset >= limit {
		fail(w, http.StatusRequestEntityTooLarge, "tooLarge", "分片偏移超过单文件上限")
		return
	}
	allowed := limit - offset
	// Content-Length 已知时提前拒绝，超限请求不建立 SMB 连接、不写盘。
	if r.ContentLength > allowed {
		fail(w, http.StatusRequestEntityTooLarge, "tooLarge", "文件超过单文件上限")
		return
	}
	conn, share, valid := s.openShare(w, fc, q.Get("share"))
	if !valid {
		return
	}
	defer conn.Close()
	f, err := conn.OpenWrite(name, offset)
	if err != nil {
		smbError(w, err)
		return
	}
	// 严格只允许写 allowed 字节：不再用 allowed+1 探测，避免多写一个字节。
	written, err := io.Copy(f, io.LimitReader(r.Body, allowed))
	cerr := f.Close()
	if written == allowed {
		var probe [1]byte
		if n, _ := r.Body.Read(probe[:]); n > 0 {
			fail(w, http.StatusRequestEntityTooLarge, "tooLarge", "文件超过单文件上限")
			return
		}
	}
	if err != nil {
		smbError(w, err)
		return
	}
	if cerr != nil {
		smbError(w, cerr)
		return
	}
	writeAudit(s, fc.userID, "file.upload", fmt.Sprintf(`\%s\%s\%s`, fc.host.Address, share, name),
		fmt.Sprintf("offset=%d bytes=%d", offset, written), clientIP(r))
	ok(w, map[string]any{"written": written, "offset": offset + written})
}

// downloadFile 流式下载，支持 HTTP Range。
func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request) {
	fc, valid := s.resolveFileOpt(w, r, true)
	if !valid {
		return
	}
	q := r.URL.Query()
	name, err := filegw.NormalizePath(q.Get("path"))
	if err != nil || name == "" {
		fail(w, http.StatusBadRequest, "badPath", "文件名不合法")
		return
	}
	conn, share, valid := s.openShare(w, fc, q.Get("share"))
	if !valid {
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
		smbError(w, err)
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
			smbError(w, err)
			return
		}
	}
	length := end - start + 1
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	// 只取最后一段：带目录的名字会优先于前端的 a.download，Chrome 会把
	// "docs\a.txt" 存成 docs_a.txt，用户看到的是被改过的文件名。
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlPath(textutil.BaseName(name)))
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	if status == http.StatusPartialContent {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	}
	w.WriteHeader(status)
	buf := copyBufPool.Get().([]byte)
	_, _ = io.CopyBuffer(writerOnly{w}, io.LimitReader(f, length), buf)
	copyBufPool.Put(buf)
	writeAudit(s, fc.userID, "file.download", fmt.Sprintf(`\%s\%s\%s`, fc.host.Address, share, name),
		fmt.Sprintf("range=%d-%d", start, end), clientIP(r))
}

// fileMutation 处理 mkdir / rename / delete。
func (s *Server) fileMutation(w http.ResponseWriter, r *http.Request, kind string) {
	fc, valid := s.resolveFile(w, r)
	if !valid {
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
	conn, share, valid := s.openShare(w, fc, in.Share)
	if !valid {
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
		smbError(w, err)
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
