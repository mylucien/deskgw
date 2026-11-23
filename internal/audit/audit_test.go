package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mylucien/deskgw/internal/store"
)

func openTestDB(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestClipKeepsShortString(t *testing.T) {
	if got := clip("短字符串", maxTarget); got != "短字符串" {
		t.Fatalf("未超长的字符串不应被改动: %q", got)
	}
}

func TestClipTruncatesASCII(t *testing.T) {
	got := clip(strings.Repeat("a", maxDetail+100), maxDetail)
	if len(got) != maxDetail {
		t.Fatalf("ASCII 截断长度应为 %d，实际 %d", maxDetail, len(got))
	}
}

// 截断点落在多字节字符中间时必须回退，不能留下半个 UTF-8 字符。
func TestClipKeepsUTF8Boundary(t *testing.T) {
	s := strings.Repeat("测", 100) // 每个字符 3 字节，共 300 字节
	got := clip(s, 256)           // 256 不是 3 的倍数
	if !utf8.ValidString(got) {
		t.Fatalf("截断结果不是合法 UTF-8: %q", got)
	}
	if len(got) > 256 {
		t.Fatalf("截断结果超长: %d", len(got))
	}
	if len(got) < 253 {
		t.Fatalf("截断过多，只保留 %d 字节", len(got))
	}
	if got != s[:len(got)] {
		t.Fatal("截断结果应为原串前缀")
	}
}

// 目标字段超长时不应把整条审计写失败，只是被截断。
func TestWriteClipsLongFields(t *testing.T) {
	st := openTestDB(t)
	long := strings.Repeat("x", 4096)
	if err := Write(st.DB, nil, "test.clip", long, long, "127.0.0.1"); err != nil {
		t.Fatalf("写入审计失败: %v", err)
	}
	var target, detail string
	if err := st.DB.QueryRow(`SELECT target, detail FROM audit_logs ORDER BY id DESC LIMIT 1`).
		Scan(&target, &detail); err != nil {
		t.Fatalf("读取审计失败: %v", err)
	}
	if len(target) != maxTarget {
		t.Fatalf("target 应被截断到 %d，实际 %d", maxTarget, len(target))
	}
	if len(detail) != maxDetail {
		t.Fatalf("detail 应被截断到 %d，实际 %d", maxDetail, len(detail))
	}
}
