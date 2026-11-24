package filegw

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

// 隐藏共享被安全软件重置时，错误里必须带上可操作的原因，而不是只有 reset。
func TestMountErrorHintsHiddenShare(t *testing.T) {
	raw := errors.New("connection error: read tcp 192.168.1.1:53914->192.168.1.213:445: read: connection reset by peer")

	got := mountError("C$", raw).Error()

	if !strings.HasPrefix(got, "挂载共享失败: ") {
		t.Fatalf("前缀不对: %s", got)
	}
	if !strings.Contains(got, "横向渗透防护") {
		t.Fatalf("缺少安全软件提示: %s", got)
	}
	if !strings.Contains(got, "C$") {
		t.Fatalf("缺少共享名: %s", got)
	}
}

// 普通共享被重置时不能提隐藏共享，避免误导。
func TestMountErrorGenericReset(t *testing.T) {
	got := mountError("共享", syscall.ECONNRESET).Error()

	if strings.Contains(got, "横向渗透防护") {
		t.Fatalf("普通共享不该出现隐藏共享提示: %s", got)
	}
	if !strings.Contains(got, "安全软件拦截") {
		t.Fatalf("缺少通用提示: %s", got)
	}
}

// 非连接类错误保持原样，不附加猜测。
func TestMountErrorKeepsOtherErrors(t *testing.T) {
	got := mountError("C$", errors.New("STATUS_BAD_NETWORK_NAME")).Error()

	if strings.Contains(got, "横向渗透防护") || strings.Contains(got, "安全软件拦截") {
		t.Fatalf("不该给非连接错误加提示: %s", got)
	}
	if !strings.Contains(got, "STATUS_BAD_NETWORK_NAME") {
		t.Fatalf("原始错误丢失: %s", got)
	}
}
