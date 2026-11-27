package httpx

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		tls    bool
		want   bool
	}{
		{"无 Origin（命令行/探活）", "192.168.1.1:8443", "", true, true},
		{"https 同源", "192.168.1.1:8443", "https://192.168.1.1:8443", true, true},
		{"http 同源（未启 TLS）", "192.168.1.1:8443", "http://192.168.1.1:8443", false, true},
		{"主机名大小写不敏感", "Router.LAN:8443", "https://router.lan:8443", true, true},
		{"其他站点", "192.168.1.1:8443", "https://evil.example", true, false},
		{"端口不同", "192.168.1.1:8443", "https://192.168.1.1:8444", true, false},
		{"TLS 下要求 https", "192.168.1.1:8443", "http://192.168.1.1:8443", true, false},
		{"非 http(s) 来源", "192.168.1.1:8443", "file://x", true, false},
		{"缺少 scheme", "192.168.1.1:8443", "192.168.1.1:8443", true, false},
		{"null 来源", "192.168.1.1:8443", "null", true, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/ws/rdp", nil)
		r.Host = c.host
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if got := SameOrigin(r); got != c.want {
			t.Errorf("%s: SameOrigin = %v, want %v", c.name, got, c.want)
		}
	}
}
