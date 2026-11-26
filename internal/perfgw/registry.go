package perfgw

import (
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	// errNoCode 表示待批准的控制码已经分不出来（实际上不可能发生）。
	errNoCode = errors.New("控制码已用尽")
	// errNoPending 表示这个控制码不在待批准列表里（可能已经批准过，或者已经离线太久）。
	errNoPending = errors.New("没有这条待批准记录")
	// errHostIDUsed 表示要换成的主机 id 已经被别的记录占着。
	errHostIDUsed = errors.New("主机 id 已被占用")
)

// pendingCodeBase 是待批准被控端使用的控制码起点。hosts.id 从 1 开始自增，
// 两者不会撞在一起。批准之后被控端重新注册时换成真正的主机 id。
const pendingCodeBase = 0x4000_0000

// pendingCodeSpan 是一次分配最多尝试的控制码个数，防止极端情况下死循环。
const pendingCodeSpan = 1 << 20

// pending 是一个已经接入、但还没被管理员批准的被控端。
type pending struct {
	code      uint32
	name      string
	os        string
	ip        string
	firstSeen int64
	lastSeen  int64
	secret    [16]byte
	online    bool
	// approved 表示已经批准、控制码换成了 hosts.id。记录留着是为了让被控端
	// 带着旧控制码重连时还能认出它；它不再出现在待批准列表里。
	approved bool
}

// registry 保存在线被控端的待批准记录。这些记录只在内存里：被控端断线之后
// 本来就要重新注册，网关重启后也会重新出现，落到数据库只会留下过期的条目。
type registry struct {
	mu      sync.Mutex
	entries map[uint32]*pending
	// alias 是旧控制码到新控制码的映射：批准之后被控端还没收到新控制码，
	// 它下次注册带的还是旧的那个。
	alias map[uint32]uint32
	next  uint32
}

func newRegistry() *registry {
	return &registry{
		entries: map[uint32]*pending{},
		alias:   map[uint32]uint32{},
		next:    pendingCodeBase,
	}
}

// claim 按上一次的控制码与密钥找回记录；对不上就新分配一个控制码。
//
// adopt 用于进程重启之后：内存表是空的，但批准结果在数据库里，凭控制码
// （= 主机 id）与重连密钥就能认回原来的身份，不必让管理员重新批准一遍。
// 它可能查库，所以只在持锁之外调用。
// 返回值 created 表示这是一条新记录（用于写 perf.host_register 审计）。
func (g *registry) claim(rc *reclaim, name, os, ip string, now int64, adopt func(uint32, [16]byte) bool) (*pending, bool, error) {
	// 名称与系统由对端填写，最长可以到一条信令帧的上限。截断到 64 个字符：
	// 界面显示足够，也不至于让一批未批准的连接把路由器的内存占满。
	name, os = clip(name, 64), clip(os, 64)
	if rc != nil {
		if p := g.reclaim(rc, name, os, ip, now); p != nil {
			return p, false, nil
		}
		if rc.code < pendingCodeBase && adopt != nil && adopt(rc.code, rc.secret) {
			if p := g.adopt(rc, name, os, ip, now); p != nil {
				return p, false, nil
			}
		}
	}
	g.mu.Lock()
	code := g.alloc()
	if code == 0 {
		g.mu.Unlock()
		return nil, false, errNoCode
	}
	secret, err := newSecret()
	if err != nil {
		g.mu.Unlock()
		return nil, false, err
	}
	p := &pending{
		code: code, name: name, os: os, ip: ip,
		firstSeen: now, lastSeen: now, secret: secret, online: true,
	}
	g.entries[code] = p
	out := *p
	g.mu.Unlock()
	return &out, true, nil
}

// reclaim 在内存表里按控制码与密钥找回记录；对不上返回 nil。
func (g *registry) reclaim(rc *reclaim, name, os, ip string, now int64) *pending {
	g.mu.Lock()
	defer g.mu.Unlock()
	code := rc.code
	if a, ok := g.alias[code]; ok {
		code = a
	}
	p, ok := g.entries[code]
	if !ok || p.secret != rc.secret {
		return nil
	}
	p.name, p.os, p.ip = name, os, ip
	p.lastSeen = now
	p.online = true
	out := *p
	return &out
}

// adopt 把数据库里已批准的主机放回内存表。
func (g *registry) adopt(rc *reclaim, name, os, ip string, now int64) *pending {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p, ok := g.entries[rc.code]; ok {
		// 并发注册抢到了同一个码：只认同一个密钥。
		if p.secret != rc.secret {
			return nil
		}
		p.online, p.lastSeen = true, now
		out := *p
		return &out
	}
	p := &pending{
		code: rc.code, name: name, os: os, ip: ip, secret: rc.secret,
		firstSeen: now, lastSeen: now, online: true, approved: true,
	}
	g.entries[rc.code] = p
	out := *p
	return &out
}

// alloc 找一个还没用过的控制码。调用方已持有锁。
func (g *registry) alloc() uint32 {
	for i := 0; i < pendingCodeSpan; i++ {
		code := g.next
		g.next++
		if g.next < pendingCodeBase {
			g.next = pendingCodeBase
		}
		if _, used := g.entries[code]; !used {
			return code
		}
	}
	return 0
}

// setSecret 换上新的重连密钥。
func (g *registry) setSecret(code uint32, secret [16]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p, ok := g.entries[code]; ok {
		p.secret = secret
	}
}

// drop 删掉记录（被控端换了控制码）。
func (g *registry) drop(code uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.dropLocked(code)
}

// dropLocked 删掉记录以及指向它的别名。调用方已持有锁。
func (g *registry) dropLocked(code uint32) {
	delete(g.entries, code)
	for from, to := range g.alias {
		if to == code {
			delete(g.alias, from)
		}
	}
}

// approve 把待批准记录换成正式主机：控制码改成 hosts.id，密钥不变，
// 旧控制码留作别名。调用方随后要断开这条连接，让被控端带着旧控制码重连、
// 从 Registered 里拿到新控制码。
func (g *registry) approve(code, hostID uint32) ([16]byte, error) {
	if hostID == 0 || hostID >= pendingCodeBase {
		return [16]byte{}, errNoCode
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.entries[code]
	if !ok || p.approved {
		return [16]byte{}, errNoPending
	}
	if other, used := g.entries[hostID]; used && other != p {
		return [16]byte{}, errHostIDUsed
	}
	delete(g.entries, code)
	p.code = hostID
	p.approved = true
	p.online = false
	g.entries[hostID] = p
	g.alias[code] = hostID
	return p.secret, nil
}

// get 按控制码取一条记录（用来在批准前读出名称、系统与来源地址）。
func (g *registry) get(code uint32) (pending, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if a, ok := g.alias[code]; ok {
		code = a
	}
	p, ok := g.entries[code]
	if !ok {
		return pending{}, false
	}
	return *p, true
}

// setOnline 记录这个控制码当前是否还有连接。离线记录保留一段时间，
// 便于被控端短时间重连时取回同一个控制码。
func (g *registry) setOnline(code uint32, online bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p, ok := g.entries[code]; ok {
		p.online = online
		if online {
			p.lastSeen = time.Now().Unix()
		}
	}
}

// reap 删掉离线超过 ttl 秒的记录，返回删掉的条数。
func (g *registry) reap(now, ttl int64) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for code, p := range g.entries {
		if !p.online && now-p.lastSeen > ttl {
			g.dropLocked(code)
			n++
		}
	}
	return n
}

// list 按首次接入时间返回待批准列表。
func (g *registry) list() []pending {
	g.mu.Lock()
	out := make([]pending, 0, len(g.entries))
	for _, p := range g.entries {
		if p.approved {
			continue
		}
		out = append(out, *p)
	}
	g.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].firstSeen != out[j].firstSeen {
			return out[i].firstSeen < out[j].firstSeen
		}
		return out[i].code < out[j].code
	})
	return out
}

// newSecret 生成 16 字节的重连密钥。
func newSecret() ([16]byte, error) {
	var s [16]byte
	if _, err := rand.Read(s[:]); err != nil {
		return s, err
	}
	return s, nil
}

// clip 把字符串按字符（不是字节）截断到 n 个。
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
