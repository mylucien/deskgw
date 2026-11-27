// Package httpx 放几个跨包共用的 HTTP 小工具。
package httpx

import (
	"net/http"
	"strings"
)

// SameOrigin 只接受同源的 http(s) 页面发起的 WebSocket 握手。
//
// 校验 scheme 可挡住 file://、chrome-extension:// 等非 Web 来源；
// TLS 直连时还要求 Origin 必须是 https，避免从明文页面借道。
// 浏览器不允许脚本伪造 Origin，因此这一条是 CSRF 的主要防线。
func SameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// 非浏览器客户端（命令行、探活）不带 Origin，交给票据与登录态把关。
		return true
	}
	i := strings.Index(origin, "://")
	if i < 0 {
		return false
	}
	scheme := strings.ToLower(origin[:i])
	if scheme != "http" && scheme != "https" {
		return false
	}
	if r.TLS != nil && scheme != "https" {
		return false
	}
	return strings.EqualFold(origin[i+3:], r.Host)
}
