package host_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mylucien/deskgw/internal/host"
	"github.com/mylucien/deskgw/internal/store"
)

func base() host.Host {
	return host.Host{
		Name: "office-pc", Address: "192.168.1.10",
		RDPPort: 3389, SBMPort: 445, Enabled: true, Modes: "rdp",
	}
}

func TestValidateAddress(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
		why  string
	}{
		{"192.168.1.10", true, "RFC1918"},
		{"10.0.0.5", true, "RFC1918"},
		{"172.16.5.4", true, "RFC1918"},
		{"100.64.1.2", true, "CGNAT（Tailscale 默认段）"},
		{"100.127.255.254", true, "CGNAT 上边界"},
		{"fd00::1", true, "IPv6 ULA"},
		{"127.0.0.1", false, "回环"},
		{"::1", false, "IPv6 回环"},
		{"0.0.0.0", false, "未指定"},
		{"224.0.0.1", false, "组播"},
		{"169.254.1.1", false, "链路本地"},
		{"100.128.0.1", false, "CGNAT 之外的 100/8"},
		{"8.8.8.8", false, "公网地址"},
		{"1.1.1.1", false, "公网地址"},
		{"example.local", false, "非 IP 字面量"},
		{"192.168.1.10/24", false, "带掩码"},
	}
	for _, c := range cases {
		h := base()
		h.Address = c.addr
		err := host.Validate(h)
		if c.ok && err != nil {
			t.Errorf("%s (%s) 应通过，实际报错: %v", c.addr, c.why, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s (%s) 应被拒绝", c.addr, c.why)
		}
	}
}

func TestValidateFields(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*host.Host)
		valid bool
	}{
		{"默认值合法", func(h *host.Host) {}, true},
		{"ID 为 0 表示自动分配", func(h *host.Host) { h.ID = 0 }, true},
		{"ID 上限内", func(h *host.Host) { h.ID = 4294967295 }, true},
		{"ID 越界", func(h *host.Host) { h.ID = 4294967296 }, false},
		{"ID 为负", func(h *host.Host) { h.ID = -1 }, false},
		{"名称为空", func(h *host.Host) { h.Name = "" }, false},
		{"名称过长", func(h *host.Host) { h.Name = strings.Repeat("a", 65) }, false},
		{"RDP 端口为 0", func(h *host.Host) { h.RDPPort = 0 }, false},
		{"RDP 端口越界", func(h *host.Host) { h.RDPPort = 65536 }, false},
		{"SMB 端口越界", func(h *host.Host) { h.SBMPort = 70000 }, false},
		{"方式未知", func(h *host.Host) { h.Modes = "vnc" }, false},
		{"多方式带空格", func(h *host.Host) { h.Modes = "rdp, perf" }, true},
	}
	for _, c := range cases {
		h := base()
		c.mut(&h)
		err := host.Validate(h)
		if c.valid && err != nil {
			t.Errorf("%s 应通过，实际: %v", c.name, err)
		}
		if !c.valid && err == nil {
			t.Errorf("%s 应被拒绝", c.name)
		}
	}
}

func openDB(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestCreateAutoAssignID(t *testing.T) {
	st := openDB(t)
	first := base()
	if err := host.Create(st.DB, &first); err != nil {
		t.Fatalf("新增主机失败: %v", err)
	}
	if first.ID < 1 {
		t.Fatalf("未回填自增 ID: %d", first.ID)
	}

	second := base()
	second.Name = "office-pc-2"
	second.Address = "10.0.0.6"
	if err := host.Create(st.DB, &second); err != nil {
		t.Fatalf("新增第二台主机失败: %v", err)
	}
	if second.ID == first.ID {
		t.Fatalf("两台主机拿到了同一个 ID: %d", second.ID)
	}

	got, err := host.Get(st.DB, first.ID)
	if err != nil {
		t.Fatalf("读取主机失败: %v", err)
	}
	if got.Name != "office-pc" || got.Modes != "rdp" || !got.Enabled {
		t.Fatalf("读取结果不符: %+v", got)
	}
}

func TestCreateWithExplicitID(t *testing.T) {
	st := openDB(t)
	h := base()
	h.ID = 91001
	if err := host.Create(st.DB, &h); err != nil {
		t.Fatalf("指定 ID 新增失败: %v", err)
	}
	dup := base()
	dup.ID = 91001
	if err := host.Create(st.DB, &dup); err == nil {
		t.Fatal("重复 ID 应报错")
	}
}

func TestDeleteMissingReturnsNoRows(t *testing.T) {
	st := openDB(t)
	if err := host.Delete(st.DB, 424242); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("删除不存在的主机应返回 sql.ErrNoRows，实际 %v", err)
	}
}

func TestResolveJoinsPort(t *testing.T) {
	h := base()
	if got := host.Resolve(h); got != "192.168.1.10:3389" {
		t.Fatalf("Resolve 结果不符: %s", got)
	}
}
