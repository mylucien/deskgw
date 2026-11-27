// Package textutil 放几处共用的字符串截断与路径处理。
//
// 截断在审计、会话详情、被控端名称里都要用；之前 auth、api、perfgw、tunnel
// 各写了一份，边界条件（UTF-8 半字符）改一处漏三处，统一到这里。
package textutil

import "strings"

// Clip 把 s 截断到至多 max 字节，并回退到 UTF-8 字符边界。
// 用于落库字段与日志：长度上限按存储字节算，但不能切出半个汉字。
func Clip(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// Runes 把 s 截断到至多 n 个字符（不是字节）。
// 界面显示用这个：中文名按字数限制才符合用户对「64 字符」的预期。
func Runes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// RuneLen 返回字符数。
func RuneLen(s string) int { return len([]rune(s)) }

// BaseName 取路径的最后一段，同时认 Windows 与 Unix 分隔符。
// 下载响应头里的文件名只能用它：带目录的名字会被浏览器清洗成 docs_a.txt。
func BaseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// SplitList 拆逗号分隔的列表，去掉空项与首尾空格。
func SplitList(s string) []string {
	out := []string{}
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// HasMode 判断逗号分隔的连接方式里是否包含 want。
func HasMode(modes, want string) bool {
	for _, m := range SplitList(modes) {
		if m == want {
			return true
		}
	}
	return false
}
