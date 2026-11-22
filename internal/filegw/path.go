package filegw

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrBadShare 表示共享名不合法。
	ErrBadShare = errors.New("共享名不合法")
	// ErrBadPath 表示路径不合法或包含路径穿越。
	ErrBadPath = errors.New("路径不合法")
)

var shareRE = regexp.MustCompile(`^[A-Za-z0-9_$.-]{1,64}$`)

// NormalizeShare 校验共享名。默认 C$，管理共享为 C$ / D$。
// 拒绝 "." / ".."：它们只是相对目录记号，不是合法共享名。
func NormalizeShare(share string) (string, error) {
	if share == "" {
		share = "C$"
	}
	if share == "." || share == ".." || !shareRE.MatchString(share) {
		return "", ErrBadShare
	}
	return share, nil
}

// NormalizePath 把相对路径规范化为 SMB 反斜杠形式，拒绝绝对路径与 .. 穿越。
// 前端可以传 / 或 \ 作为分隔符；返回的路径不含前导分隔符。
func NormalizePath(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", ErrBadPath
	}
	p = strings.ReplaceAll(p, "/", "\\")
	p = strings.TrimSpace(p)
	if p == "" {
		return "", nil
	}
	if strings.HasPrefix(p, "\\\\") || (len(p) >= 2 && p[1] == ':') {
		return "", ErrBadPath
	}
	p = strings.TrimPrefix(p, "\\")
	parts := strings.Split(p, "\\")
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			return "", ErrBadPath
		}
		if strings.ContainsRune(seg, ':') || strings.ContainsRune(seg, '*') ||
			strings.ContainsRune(seg, '?') || strings.ContainsRune(seg, '"') ||
			strings.ContainsRune(seg, '<') || strings.ContainsRune(seg, '>') ||
			strings.ContainsRune(seg, '|') {
			return "", ErrBadPath
		}
		out = append(out, seg)
	}
	if len(out) == 0 {
		return "", nil
	}
	return strings.Join(out, "\\"), nil
}
