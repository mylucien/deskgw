package filegw_test

import (
	"errors"
	"testing"

	"github.com/mylucien/deskgw/internal/filegw"
)

func TestNormalizeShare(t *testing.T) {
	ok := map[string]string{
		"":        "C$",
		"C$":      "C$",
		"D$":      "D$",
		"docs":    "docs",
		"a.b-c_1": "a.b-c_1",
	}
	for in, want := range ok {
		got, err := filegw.NormalizeShare(in)
		if err != nil || got != want {
			t.Errorf("NormalizeShare(%q) = %q, %v；期望 %q", in, got, err, want)
		}
	}
	bad := []string{".", "..", "a b", "a/b", "a\\b", "x:y", "长" + "name"}
	for _, in := range bad {
		if _, err := filegw.NormalizeShare(in); !errors.Is(err, filegw.ErrBadShare) {
			t.Errorf("NormalizeShare(%q) 应被拒绝，实际 %v", in, err)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	ok := map[string]string{
		"":            "",
		"/":           "",
		"\\":          "",
		"Documents":   "Documents",
		"/Documents/": "Documents",
		"a/b/c.txt":   `a\b\c.txt`,
		`a\b\c.txt`:   `a\b\c.txt`,
		"a//b":        `a\b`,
		"./a/./b":     `a\b`,
		"  a/b  ":     `a\b`,
	}
	for in, want := range ok {
		got, err := filegw.NormalizePath(in)
		if err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v；期望 %q", in, got, err, want)
		}
	}

	bad := []string{
		"..",
		"../etc/passwd",
		"a/../../b",
		`a\..\b`,
		`\\server\share`,
		`C:\Windows`,
		`c:/windows`,
		"a/\x00/b",
		`a\b:c`,
		`a\*.txt`,
		`a\?.txt`,
		`a\"b`,
		`a\<b`,
		`a\>b`,
		`a\|b`,
	}
	for _, in := range bad {
		if _, err := filegw.NormalizePath(in); !errors.Is(err, filegw.ErrBadPath) {
			t.Errorf("NormalizePath(%q) 应被拒绝，实际 %v", in, err)
		}
	}
}
