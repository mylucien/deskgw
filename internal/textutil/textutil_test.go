package textutil

import "testing"

func TestClipKeepsUTF8Boundary(t *testing.T) {
	// "汉" 占 3 字节：max=4 时必须只留一个完整汉字，不能切出半个。
	if got := Clip("汉字", 4); got != "汉" {
		t.Fatalf("Clip = %q, want 汉", got)
	}
	if got := Clip("abc", 2); got != "ab" {
		t.Fatalf("Clip = %q, want ab", got)
	}
	if got := Clip("abc", 10); got != "abc" {
		t.Fatalf("不应截断，得到 %q", got)
	}
	if got := Clip("abc", 0); got != "abc" {
		t.Fatalf("max<=0 视为不限，得到 %q", got)
	}
}

func TestRunesCountsCharacters(t *testing.T) {
	if got := Runes("汉ab", 2); got != "汉a" {
		t.Fatalf("Runes = %q, want 汉a", got)
	}
	if got := Runes("汉ab", 10); got != "汉ab" {
		t.Fatalf("不应截断，得到 %q", got)
	}
	if got := Runes("汉ab", 0); got != "" {
		t.Fatalf("n<=0 应返回空，得到 %q", got)
	}
	if RuneLen("汉ab") != 3 {
		t.Fatalf("RuneLen 应为 3")
	}
}

func TestBaseName(t *testing.T) {
	cases := map[string]string{
		`C:\Users\a.txt`: "a.txt",
		"/var/log/x":     "x",
		"plain.txt":      "plain.txt",
		`dir\`:           "",
	}
	for in, want := range cases {
		if got := BaseName(in); got != want {
			t.Fatalf("BaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHasMode(t *testing.T) {
	if !HasMode("rdp,perf", "perf") || !HasMode("rdp", "rdp") {
		t.Fatal("应命中")
	}
	if HasMode("rdp,perf", "vnc") || HasMode("", "rdp") {
		t.Fatal("不应命中")
	}
	// 不能把 "perf" 当成 "perfx" 的子串。
	if HasMode("perfx", "perf") {
		t.Fatal("不能按子串匹配")
	}
}
