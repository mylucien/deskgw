package perfgw

// 会话名额与上行速率限制（对应设计文档 4.10 的「限额」一节）。
//
// 名额不落库：被控端在线状态本来就在内存里，网关重启后所有会话都已经断了，
// 落库只会留下一堆要清理的过期记录。

import (
	"errors"
	"sync"
	"time"
)

var (
	// errHostBusy 表示这台被控端已经有会话了。
	errHostBusy = errors.New("这台主机已有会话")
	// errFull 表示性能模式的全局名额已满。
	errFull = errors.New("性能模式会话已满")
	// errRate 表示上行消息超过速率限制。
	errRate = errors.New("上行消息太快")
)

const (
	// 默认值与 4.10 一致：全局 2 个、每台主机 1 个。
	defaultMaxSessions = 2
	defaultMaxPerHost  = 1
	// 上限只用于防止后台填出离谱的值把内存撑爆。
	hardMaxSessions = 32
	hardMaxPerHost  = 8
)

// Limits 是性能模式的并发名额。零值不可用，用 NewLimits 构造。
type Limits struct {
	mu      sync.Mutex
	max     int
	perHost int
	total   int
	hosts   map[int64]int
}

// NewLimits 构造名额表，参数不合法时退回默认值。
func NewLimits(max, perHost int) *Limits {
	l := &Limits{hosts: map[int64]int{}}
	l.Set(max, perHost)
	return l
}

// Set 修改上限。已经占用的名额不受影响，新限额立即对后续连接生效。
//
// 超出硬上限时夹到硬上限，而不是退回默认值：后台填了 9 就悄悄变成 1，
// 管理员只会看到「每台主机仍然只能开一个」却查不到原因。
func (l *Limits) Set(max, perHost int) {
	if max <= 0 {
		max = defaultMaxSessions
	}
	if max > hardMaxSessions {
		max = hardMaxSessions
	}
	if perHost <= 0 {
		perHost = defaultMaxPerHost
	}
	if perHost > hardMaxPerHost {
		perHost = hardMaxPerHost
	}
	if perHost > max {
		perHost = max
	}
	l.mu.Lock()
	l.max, l.perHost = max, perHost
	l.mu.Unlock()
}

// acquire 占一个名额。失败时返回 errHostBusy 或 errFull。
func (l *Limits) acquire(hostID int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.max {
		return errFull
	}
	if l.hosts[hostID] >= l.perHost {
		return errHostBusy
	}
	l.total++
	l.hosts[hostID]++
	return nil
}

// release 归还名额。调用方必须成对，这里仍做一次兜底：计数一旦变负，
// acquire 的 total >= max 会永远不成立，等于限额彻底失效。
func (l *Limits) release(hostID int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total <= 0 || l.hosts[hostID] <= 0 {
		return
	}
	l.total--
	if n := l.hosts[hostID] - 1; n > 0 {
		l.hosts[hostID] = n
	} else {
		delete(l.hosts, hostID)
	}
}

// counts 返回当前占用数与每台主机的明细，供状态接口与测试使用。
func (l *Limits) counts() (int, map[int64]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[int64]int, len(l.hosts))
	for k, v := range l.hosts {
		out[k] = v
	}
	return l.total, out
}

// rateLimiter 是上行消息的令牌桶：每秒补 600 个，桶容量 600。
//
// 正常输入（键鼠、Ack、心跳）每秒最多几十条；到几百条说明客户端异常或被
// 滥用，直接丢这条消息并让调用方计一次违规，而不是写进被控端。
const (
	ratePerSec = 600
	rateBurst  = 600
)

type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{tokens: rateBurst, last: time.Now()}
}

// allow 取一个令牌，取不到返回 false。
func (l *rateLimiter) allow() bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens += now.Sub(l.last).Seconds() * ratePerSec
	if l.tokens > rateBurst {
		l.tokens = rateBurst
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
