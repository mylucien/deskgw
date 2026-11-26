package perfgw

import (
	"crypto/rand"
	"errors"
	"sort"
	"sync"
	"time"
)

// errNoCode 表示待批准的控制码已经分不出来（实际上不可能发生）。
var errNoCode = errors.New("控制码已用尽")

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
}

// registry 保存在线被控端的待批准记录。这些记录只在内存里：被控端断线之后
// 本来就要重新注册，网关重启后也会重新出现，落到数据库只会留下过期的条目。
type registry struct {
	mu      sync.Mutex
	entries map[uint32]*pending
	next    uint32
}

func newRegistry() *registry {
	return &registry{entries: map[uint32]*pending{}, next: pendingCodeBase}
}

// claim 按上一次的控制码与密钥找回记录；对不上就新分配一个控制码。
func (g *registry) claim(rc *reclaim, name, os, ip string, now int64) (*pending, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if rc != nil {
		if p, ok := g.entries[rc.code]; ok && p.secret == rc.secret {
			p.name, p.os, p.ip = name, os, ip
			p.lastSeen = now
			p.online = true
			out := *p
			return &out, nil
		}
	}
	code := g.alloc()
	if code == 0 {
		return nil, errNoCode
	}
	secret, err := newSecret()
	if err != nil {
		return nil, err
	}
	p := &pending{
		code: code, name: name, os: os, ip: ip,
		firstSeen: now, lastSeen: now, secret: secret, online: true,
	}
	g.entries[code] = p
	out := *p
	return &out, nil
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
	delete(g.entries, code)
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
			delete(g.entries, code)
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
