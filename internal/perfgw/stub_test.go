package perfgw

// 本机联调用的「假被控端」：真实走 QUIC、信令、端到端握手与密文收发。
//
// 生产代码只实现 Noise 的发起方（路由器就是控制端），这里为了在本机把整条
// 链路跑起来，反着写一份响应方，再按 airhand-link 的 host 侧时序接上。
// 只支持 IK 与 XX，不做配对，只用于测试。

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ---- Noise 响应方 ---------------------------------------------------------

// stubResponder 是响应方（被控端）的握手状态，与 noiseInitiator 对称。
type stubResponder struct {
	sym     noiseSym
	static  *ecdh.PrivateKey
	eph     *ecdh.PrivateKey
	peerEph *ecdh.PublicKey
	peerKey *ecdh.PublicKey
	xx      bool
	epoch   int
}

// newStubIKResponder 准备 IK。IK 的预消息是 `<- s`：响应方把握手自己的
// static 公钥混进握手哈希，与发起方混入对端公钥是同一件事。
func newStubIKResponder(static *ecdh.PrivateKey, prologue []byte) *stubResponder {
	h := &stubResponder{static: static}
	h.sym.init(noiseProtocolIK)
	h.sym.mixHash(prologue)
	h.sym.mixHash(static.PublicKey().Bytes())
	return h
}

func newStubXXResponder(static *ecdh.PrivateKey, prologue []byte) *stubResponder {
	h := &stubResponder{static: static, xx: true}
	h.sym.init(noiseProtocolXX)
	h.sym.mixHash(prologue)
	return h
}

func (h *stubResponder) genEphemeral() error {
	if h.eph != nil {
		return nil
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	h.eph = k
	return nil
}

// readMessage1 解开 e[, es, s, ss] 与负载。
func (h *stubResponder) readMessage1(msg []byte) ([]byte, error) {
	if h.epoch != 0 {
		return nil, errNoise
	}
	if len(msg) < noiseKeyLen {
		return nil, errNoise
	}
	peerEph, err := ecdh.X25519().NewPublicKey(msg[:noiseKeyLen])
	if err != nil {
		return nil, errNoise
	}
	h.peerEph = peerEph
	rest := msg[noiseKeyLen:]
	h.sym.mixHash(msg[:noiseKeyLen])

	if !h.xx {
		// es：响应方的 static 与发起方的临时密钥。
		es, err := dh(h.static, peerEph)
		if err != nil {
			return nil, err
		}
		h.sym.mixKey(es)
		if len(rest) < noiseKeyLen+noiseTagLen {
			return nil, errNoise
		}
		raw, err := h.sym.decryptAndHash(rest[:noiseKeyLen+noiseTagLen])
		if err != nil {
			return nil, err
		}
		if len(raw) != noiseKeyLen {
			return nil, errNoise
		}
		pub, err := ecdh.X25519().NewPublicKey(raw)
		if err != nil {
			return nil, errNoise
		}
		h.peerKey = pub
		rest = rest[noiseKeyLen+noiseTagLen:]
		ss, err := dh(h.static, pub)
		if err != nil {
			return nil, err
		}
		h.sym.mixKey(ss)
	}

	payload, err := h.sym.decryptAndHash(rest)
	if err != nil {
		return nil, err
	}
	h.epoch = 1
	return payload, nil
}

// writeMessage2 发出 e[, ee, s, es] 与负载。
func (h *stubResponder) writeMessage2(payload []byte) ([]byte, error) {
	if h.epoch != 1 {
		return nil, errNoise
	}
	if err := h.genEphemeral(); err != nil {
		return nil, err
	}
	msg := make([]byte, 0, noiseMaxMsg)
	ephPub := h.eph.PublicKey().Bytes()
	msg = append(msg, ephPub...)
	h.sym.mixHash(ephPub)

	ee, err := dh(h.eph, h.peerEph)
	if err != nil {
		return nil, err
	}
	h.sym.mixKey(ee)

	if h.xx {
		ks, err := h.sym.encryptAndHash(h.static.PublicKey().Bytes())
		if err != nil {
			return nil, err
		}
		msg = append(msg, ks...)
		es, err := dh(h.static, h.peerEph)
		if err != nil {
			return nil, err
		}
		h.sym.mixKey(es)
	} else {
		se, err := dh(h.eph, h.peerKey)
		if err != nil {
			return nil, err
		}
		h.sym.mixKey(se)
	}

	body, err := h.sym.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	msg = append(msg, body...)
	h.epoch = 2
	return msg, nil
}

// readMessage3 是 XX 的第三条：s 与负载。
func (h *stubResponder) readMessage3(msg []byte) ([]byte, error) {
	if !h.xx || h.epoch != 2 {
		return nil, errNoise
	}
	if len(msg) < noiseKeyLen+noiseTagLen {
		return nil, errNoise
	}
	raw, err := h.sym.decryptAndHash(msg[:noiseKeyLen+noiseTagLen])
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, errNoise
	}
	h.peerKey = pub
	se, err := dh(h.eph, pub)
	if err != nil {
		return nil, err
	}
	h.sym.mixKey(se)
	payload, err := h.sym.decryptAndHash(msg[noiseKeyLen+noiseTagLen:])
	if err != nil {
		return nil, err
	}
	h.epoch = 3
	return payload, nil
}

func (h *stubResponder) done() bool {
	if h.xx {
		return h.epoch == 3
	}
	return h.epoch == 2
}

func (h *stubResponder) handshakeHash() []byte {
	out := make([]byte, noiseHashLen)
	copy(out, h.sym.h[:])
	return out
}

func (h *stubResponder) finish() (i2r, r2i []byte, err error) {
	if !h.done() {
		return nil, nil, errNoise
	}
	i2r, r2i = h.sym.split()
	h.sym.wipe()
	h.eph = nil
	h.epoch = 0
	return i2r, r2i, nil
}

// ---- 被控端的会话密钥 -----------------------------------------------------

// stubKeys 是被控端视角的会话密钥：send 走响应方 → 发起方。
type stubKeys struct {
	ctrl [2][keyLen]byte // [0] 收（i2r）、[1] 发（r2i）
	dg   [2][keyLen]byte
	bulk [2][keyLen]byte // 大块通道：剪贴板、光标图像
}

func stubDerive(hash, i2r, r2i []byte) *stubKeys {
	return &stubKeys{
		ctrl: [2][keyLen]byte{
			deriveKey(hash, i2r, labelControl),
			deriveKey(hash, r2i, labelControl),
		},
		dg: [2][keyLen]byte{
			deriveKey(hash, i2r, labelDatagram),
			deriveKey(hash, r2i, labelDatagram),
		},
		bulk: [2][keyLen]byte{
			deriveKey(hash, i2r, labelBulk),
			deriveKey(hash, r2i, labelBulk),
		},
	}
}

// openStub 解开密封单元并核对计数，联调时要确认两侧的计数严格连续。
func openStub(key [keyLen]byte, want uint64, data []byte) ([]byte, error) {
	if len(data) < sealOverhead {
		return nil, errNoise
	}
	got := binary.LittleEndian.Uint64(data[len(data)-8:])
	if got != want {
		return nil, fmt.Errorf("计数 %d，期望 %d", got, want)
	}
	return openSealed(key, data)
}

// stubSession 是一个会话在被控端侧的状态。数据报是整条连接共用的，必须按
// 会话号分拣，否则前一个会话的读者会把后一个会话的数据报抢走。
type stubSession struct {
	sid  uint64
	keys *stubKeys
	conn *quic.Conn

	mu       sync.Mutex
	dgRecv   uint64
	dgSend   uint64
	bulkSend uint64
}

// ---- 假被控端 -------------------------------------------------------------

// stubHost 是一条被控端连接的生命周期：注册、等 Incoming、开会话。
type stubHost struct {
	addr        string
	name        string
	static      *ecdh.PrivateKey
	fingerprint string

	mu       sync.Mutex
	conn     *quic.Conn
	code     uint32
	secret   [16]byte
	sessions map[uint64]*stubSession
	// lanes 是连接级 accept 循环按会话号投递的流（控制流、大块流）。
	lanes map[uint64]chan stubLane
	// approved 收到正式控制码（= 主机 id）时写入。
	approved chan uint32
	// registered 每次注册成功（含重连）通知一次。
	registered chan struct{}
	// hellos / inputs / pongs 收集服务端转发过来的东西，供测试断言。
	hellos chan []byte
	inputs chan []byte
	// bulks 是大块通道上收到的明文（剪贴板等），按到达顺序。
	bulks chan []byte
	pongs chan uint64
	// errs 记录会话里的错误（测试结束时检查）。
	errs chan error
}

func newStubHost(addr, name, fingerprint string) (*stubHost, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &stubHost{
		addr: addr, name: name, static: k, fingerprint: fingerprint,
		sessions:   map[uint64]*stubSession{},
		approved:   make(chan uint32, 4),
		registered: make(chan struct{}, 8),
		hellos:     make(chan []byte, 8),
		inputs:     make(chan []byte, 16),
		bulks:      make(chan []byte, 8),
		pongs:      make(chan uint64, 8),
		errs:       make(chan error, 16),
	}, nil
}

// run 一直连着服务端：连接被服务端关掉（批准之后换码）就带着旧控制码重连，
// ctx 取消就退出。
func (h *stubHost) run(ctx context.Context) {
	for {
		if err := h.dialOnce(ctx); err != nil && ctx.Err() == nil {
			h.report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (h *stubHost) dialOnce(ctx context.Context) error {
	conn, err := quic.DialAddr(ctx, h.addr, &tls.Config{
		NextProtos: []string{alpn},
		MinVersion: tls.VersionTLS13,
		// 被控端按指纹固定证书；联调时只比指纹，不做域名校验。
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("没有证书")
			}
			sum := sha256.Sum256(raw[0])
			if got := hex.EncodeToString(sum[:]); got != h.fingerprint {
				return fmt.Errorf("证书指纹不符：%s", got)
			}
			return nil
		},
	}, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("连接服务端: %w", err)
	}
	h.mu.Lock()
	h.conn = conn
	h.sessions = map[uint64]*stubSession{}
	h.lanes = map[uint64]chan stubLane{}
	h.mu.Unlock()
	defer conn.CloseWithError(0, "")
	go h.routeDatagrams(ctx, conn)
	go h.routeStreams(ctx, conn)

	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	// ClientHello 与 Register 紧跟发出，不等回答（被控端的做法）。
	if err := writeFrame(st, stubHelloFrame(h.name)); err != nil {
		return err
	}
	if _, err := readFrame(st, maxSignalMsg); err != nil {
		return err
	}
	if err := writeFrame(st, h.registerFrame()); err != nil {
		return err
	}
	reg, err := readFrame(st, maxSignalMsg)
	if err != nil {
		return err
	}
	code, secret, err := parseStubRegistered(reg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	old := h.code
	h.code, h.secret = code, secret
	h.mu.Unlock()
	select {
	case h.registered <- struct{}{}:
	default:
	}
	if old != 0 && code != old {
		select {
		case h.approved <- code:
		default:
		}
	}

	// 信令流上剩下的是 Incoming；连接断开时这里返回。
	for {
		frame, err := readFrame(st, maxSignalMsg)
		if err != nil {
			// 服务端批准之后会主动断开，让被控端带着旧控制码重连取新码；
			// 这不是错误。
			var appErr *quic.ApplicationError
			if errors.As(err, &appErr) {
				return nil
			}
			return err
		}
		sid, init, err := parseStubIncoming(frame)
		if err != nil {
			continue
		}
		go h.serveSession(ctx, conn, sid, init)
	}
}

func (h *stubHost) registerFrame() []byte {
	h.mu.Lock()
	code, secret := h.code, h.secret
	h.mu.Unlock()
	var w cbWriter
	w.array(2)
	w.uint(msgRegister)
	w.array(3)
	if code == 0 {
		w.null()
	} else {
		w.array(2)
		w.uint(uint64(code))
		w.bytes(secret[:])
	}
	w.boolean(true)  // keep：重连时保留原来的控制码
	w.boolean(false) // rekey：本机没有换控制码
	return w.b
}

// serveSession 走完一个会话的端到端握手，之后发 Hello、回 Pong。
// stubLane 是连接级 accept 循环投递给某个会话的一条单向流（会话头已经读掉）。
type stubLane struct {
	rs   *quic.ReceiveStream
	lane uint8
}

func (h *stubHost) serveSession(ctx context.Context, conn *quic.Conn, sid uint64, init []byte) {
	lanes := make(chan stubLane, 8)
	h.mu.Lock()
	h.lanes[sid] = lanes
	h.mu.Unlock()
	// 注册要留到会话真正结束（readLanes 退出）再删：serveSession 启动完
	// 几个读循环就返回了，后面的流还要靠这张表找过来。

	pattern, noiseMsg, err := parseStubInit(init)
	if err != nil {
		h.report(err)
		return
	}
	ctrl, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		h.report(err)
		return
	}
	// 被控端先开本端控制流，再在流上握手：这是 airhand 的时序。
	if _, err := ctrl.Write(sessionHeader(sid, laneControl)); err != nil {
		h.report(err)
		return
	}

	var responder *stubResponder
	switch pattern {
	case patternKnown:
		responder = newStubIKResponder(h.static, airhandPrologue(patternKnown))
	case patternFirst:
		responder = newStubXXResponder(h.static, airhandPrologue(patternFirst))
	default:
		h.report(fmt.Errorf("不认识的握手模式 %d", pattern))
		return
	}
	if _, err := responder.readMessage1(noiseMsg); err != nil {
		h.report(fmt.Errorf("解开握手第 1 条: %w", err))
		return
	}
	msg2, err := responder.writeMessage2(nil)
	if err != nil {
		h.report(err)
		return
	}
	takeKeys := func() *stubKeys {
		hh := responder.handshakeHash()
		i2r, r2i, err := responder.finish()
		if err != nil {
			h.report(err)
			return nil
		}
		return stubDerive(hh, i2r, r2i)
	}
	writeReply := func(pairs ...stubPair) error {
		var w cbWriter
		w.mapN(len(pairs))
		for _, p := range pairs {
			w.uint(p.key)
			w.bytes(p.val)
		}
		return writeFrame(ctrl, w.b)
	}

	var keys *stubKeys
	var in *quic.ReceiveStream
	if pattern == patternKnown {
		// IK：第 2 条与决定一起发。
		if keys = takeKeys(); keys == nil {
			return
		}
		if err := writeReply(
			stubPair{2, msg2},
			stubPair{3, seal(keys.ctrl[1], 0, stubVerdict())},
		); err != nil {
			h.report(err)
			return
		}
	} else {
		// XX：先发第 2 条，等控制端的第 3 条，再发决定。
		if err := writeReply(stubPair{2, msg2}); err != nil {
			h.report(err)
			return
		}
	}

	// 控制端的控制流：XX 时握手要用它读第 3 条，IK 时直接读 Confirm。
	// 先到的其它通道（大块）留到握手之后处理。
	var early []stubLane
	deadline := time.After(stepTimeout)
	for in == nil {
		select {
		case l := <-lanes:
			if l.lane == laneControl {
				in = l.rs
			} else {
				early = append(early, l)
			}
		case <-deadline:
			h.report(fmt.Errorf("等控制流超时"))
			return
		case <-ctx.Done():
			return
		}
	}
	if pattern == patternFirst {
		finish, err := readFrame(in, maxControlMsg)
		if err != nil {
			h.report(err)
			return
		}
		noise3, err := parseStubFinish(finish)
		if err != nil {
			h.report(err)
			return
		}
		if _, err := responder.readMessage3(noise3); err != nil {
			h.report(fmt.Errorf("解开握手第 3 条: %w", err))
			return
		}
		if keys = takeKeys(); keys == nil {
			return
		}
		if err := writeReply(stubPair{3, seal(keys.ctrl[1], 0, stubVerdict())}); err != nil {
			h.report(err)
			return
		}
	}

	// Confirm 是控制端在控制通道上发的第一帧密文，计数 0。
	confirm, err := readFrame(in, maxControlMsg)
	if err != nil {
		h.report(err)
		return
	}
	plain, err := openStub(keys.ctrl[0], 0, confirm)
	if err != nil {
		h.report(fmt.Errorf("解开 Confirm: %w", err))
		return
	}
	if len(plain) != 1 || plain[0] != 0xa0 {
		h.report(fmt.Errorf("Confirm 不是空映射: %x", plain))
		return
	}

	// Hello 是控制通道上被控端 → 控制端的第一帧明文，计数 1（0 给了决定）。
	hello := stubHello(h.name)
	if err := writeFrame(ctrl, seal(keys.ctrl[1], 1, hello)); err != nil {
		h.report(err)
		return
	}
	select {
	case h.hellos <- hello:
	default:
	}

	go h.readControl(ctx, sid, in, keys)
	for _, l := range early {
		if l.lane == laneBulk {
			go h.readBulk(l.rs, keys)
		} else {
			l.rs.CancelRead(0)
		}
	}
	go h.readLanes(ctx, sid, lanes, keys)
	h.mu.Lock()
	h.sessions[sid] = &stubSession{sid: sid, keys: keys, conn: conn}
	h.mu.Unlock()
}

func (h *stubHost) readControl(ctx context.Context, sid uint64, in *quic.ReceiveStream, keys *stubKeys) {
	defer func() {
		h.mu.Lock()
		delete(h.sessions, sid)
		h.mu.Unlock()
	}()
	var n uint64 = 1
	for {
		_ = in.SetReadDeadline(time.Now().Add(60 * time.Second))
		frame, err := readFrame(in, maxControlMsg)
		if err != nil {
			return
		}
		plain, err := openStub(keys.ctrl[0], n, frame)
		if err != nil {
			h.report(fmt.Errorf("解开上行控制帧（计数 %d）: %w", n, err))
			return
		}
		n++
		select {
		case h.inputs <- plain:
		default:
		}
	}
}

// routeStreams 是整条连接唯一的单向流接受者：读会话头，按会话号投递给对应
// 会话。与控制流分开做，避免多个会话的 accept 互相抢流。
func (h *stubHost) routeStreams(ctx context.Context, conn *quic.Conn) {
	for {
		st, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		var hdr [sessionHeaderLen]byte
		// 读会话头要设超时：quic-go 的接收流在纯阻塞读上可能不唤醒（设了
		// deadline 才会把已到的数据交给读者）。
		_ = st.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(st, hdr[:]); err != nil {
			continue
		}
		sid, lane, err := decodeSessionHeader(hdr[:])
		if err != nil {
			st.CancelRead(0)
			continue
		}
		// 会话可能还没登记（Incoming 与流是前后脚到的）。
		var ch chan stubLane
		for i := 0; i < 50; i++ {
			h.mu.Lock()
			ch = h.lanes[sid]
			h.mu.Unlock()
			if ch != nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if ch == nil {
			st.CancelRead(0)
			continue
		}
		select {
		case ch <- stubLane{rs: st, lane: lane}:
		default:
			st.CancelRead(0)
		}
	}
}

// readLanes 收本会话后续开的大块流。
func (h *stubHost) readLanes(ctx context.Context, sid uint64, lanes chan stubLane, keys *stubKeys) {
	defer func() {
		h.mu.Lock()
		delete(h.lanes, sid)
		h.mu.Unlock()
	}()
	for {
		select {
		case l := <-lanes:
			if l.lane == laneBulk {
				go h.readBulk(l.rs, keys)
			} else {
				l.rs.CancelRead(0)
			}
		case <-ctx.Done():
			return
		}
	}
}

// readBulk 读一条大块流上的长度前缀帧并解密，交给测试。
func (h *stubHost) readBulk(st *quic.ReceiveStream, keys *stubKeys) {
	var n uint64
	for {
		_ = st.SetReadDeadline(time.Now().Add(60 * time.Second))
		frame, err := readFrame(st, maxBulkMsg)
		if err != nil {
			return
		}
		plain, err := openStub(keys.bulk[0], n, frame)
		if err != nil {
			h.report(fmt.Errorf("解开上行大块帧（计数 %d）: %w", n, err))
			return
		}
		n++
		select {
		case h.bulks <- plain:
		default:
		}
	}
}

// sendBulk 让假被控端在一条新的大块流上发一条消息（剪贴板），发给当前唯一的会话。
func (h *stubHost) sendBulk(ctx context.Context, plain []byte) error {
	h.mu.Lock()
	var s *stubSession
	// 取会话号最大的那条：前面的会话可能还没从表里清掉，它的连接已经关了。
	for sid, v := range h.sessions {
		if s == nil || sid > s.sid {
			s = v
		}
	}
	h.mu.Unlock()
	if s == nil {
		return fmt.Errorf("没有活跃会话")
	}
	sid := s.sid
	st, err := s.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	body := seal(s.keys.bulk[1], s.bulkSend, plain)
	s.bulkSend++
	s.mu.Unlock()
	// 会话头、长度前缀、正文一次写完：分几次小写在 quic-go 上对端读不齐。
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(body)))
	buf := make([]byte, 0, sessionHeaderLen+4+len(body))
	buf = append(buf, sessionHeader(sid, laneBulk)...)
	buf = append(buf, prefix[:]...)
	buf = append(buf, body...)
	if _, err := st.Write(buf); err != nil {
		return err
	}
	return st.Close()
}

// routeDatagrams 是整条连接唯一的数据报读者：按会话号交给对应会话，
// 与真实被控端的 Router 一致。
func (h *stubHost) routeDatagrams(ctx context.Context, conn *quic.Conn) {
	for {
		raw, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(raw) < 9 || raw[8] != kindControlDatagram {
			continue
		}
		sid := binary.LittleEndian.Uint64(raw[:8])
		h.mu.Lock()
		s := h.sessions[sid]
		h.mu.Unlock()
		if s == nil {
			continue
		}
		s.mu.Lock()
		plain, err := openStub(s.keys.dg[0], s.dgRecv, raw[9:])
		if err == nil {
			s.dgRecv++
		}
		s.mu.Unlock()
		if err != nil {
			h.report(fmt.Errorf("解开数据报（会话 %d）: %w", sid, err))
			continue
		}
		t, ok := parseStubPing(plain)
		if !ok {
			continue
		}
		var pong cbWriter
		pong.array(2)
		pong.uint(0)
		pong.array(1)
		pong.uint(t)
		s.mu.Lock()
		body := seal(s.keys.dg[1], s.dgSend, pong.b)
		s.dgSend++
		s.mu.Unlock()
		out := make([]byte, 9, 9+len(body))
		binary.LittleEndian.PutUint64(out[:8], sid)
		out[8] = kindControlDatagram
		if err := conn.SendDatagram(append(out, body...)); err != nil {
			h.report(err)
			return
		}
		select {
		case h.pongs <- t:
		default:
		}
	}
}

func (h *stubHost) report(err error) {
	select {
	case h.errs <- err:
	default:
	}
}

// stubPair 是 HandshakeReply 里的一个键值对。
type stubPair struct {
	key uint64
	val []byte
}

// ---- 编码与解析（与 airhand-proto 的 minicbor 写法对齐） -------------------

// stubHelloFrame 是 ClientHello：`[版本, 角色, 名称, 系统]`。
func stubHelloFrame(name string) []byte {
	var w cbWriter
	w.array(4)
	w.uint(signalVersion)
	w.uint(roleHost)
	w.text(name)
	w.text("Windows 11")
	return w.b
}

// stubVerdict 是接受这次会话的决定：`[版本]`。
func stubVerdict() []byte {
	var w cbWriter
	w.array(1)
	w.uint(sessionVersion)
	return w.b
}

// parseStubRegistered 读 Registered：`[1, [控制码, 重连密钥]]`。
func parseStubRegistered(b []byte) (uint32, [16]byte, error) {
	var secret [16]byte
	r := newCBReader(b)
	n, err := r.array()
	if err != nil || n < 2 {
		return 0, secret, errCBOR
	}
	kind, err := r.uint()
	if err != nil || kind != msgRegistered {
		return 0, secret, errCBOR
	}
	if _, err := r.array(); err != nil {
		return 0, secret, err
	}
	code, err := r.uint()
	if err != nil {
		return 0, secret, err
	}
	raw, err := r.bytes()
	if err != nil || len(raw) != 16 {
		return 0, secret, errCBOR
	}
	copy(secret[:], raw)
	return uint32(code), secret, nil
}

// parseStubIncoming 读 `[3, [会话号, 对端, 观测地址, 握手第 1 条]]`，只取会话号与 init。
func parseStubIncoming(b []byte) (uint64, []byte, error) {
	r := newCBReader(b)
	n, err := r.array()
	if err != nil || n < 2 {
		return 0, nil, errCBOR
	}
	kind, err := r.uint()
	if err != nil || kind != 3 {
		return 0, nil, errCBOR
	}
	if _, err := r.array(); err != nil {
		return 0, nil, err
	}
	sid, err := r.uint()
	if err != nil {
		return 0, nil, err
	}
	if err := r.skip(); err != nil { // 对端
		return 0, nil, err
	}
	if err := r.skip(); err != nil { // 观测到的地址
		return 0, nil, err
	}
	init, err := r.bytes()
	if err != nil {
		return 0, nil, err
	}
	return sid, init, nil
}

// parseStubInit 读 HandshakeInit：map {模式, SPAKE2, Noise 第 1 条}。
func parseStubInit(b []byte) (uint64, []byte, error) {
	r := newCBReader(b)
	n, err := r.mapLen()
	if err != nil {
		return 0, nil, err
	}
	var pattern uint64
	var noiseMsg []byte
	for i := 0; i < n; i++ {
		key, err := r.uint()
		if err != nil {
			return 0, nil, err
		}
		switch key {
		case 0:
			if pattern, err = r.uint(); err != nil {
				return 0, nil, err
			}
		case 1:
			if err := r.skip(); err != nil {
				return 0, nil, err
			}
		case 2:
			if noiseMsg, err = r.bytes(); err != nil {
				return 0, nil, err
			}
		default:
			if err := r.skip(); err != nil {
				return 0, nil, err
			}
		}
	}
	return pattern, noiseMsg, nil
}

// parseStubFinish 读 HandshakeFinish：`[Noise 第 3 条]`。
func parseStubFinish(b []byte) ([]byte, error) {
	r := newCBReader(b)
	if n, err := r.array(); err != nil || n < 1 {
		return nil, errCBOR
	}
	return r.bytes()
}

// stubHello 构造 HostMsg::Hello：`[1, [名称, 系统, 版本, 显示器, 当前, 编码, 平台, 触摸, 操作, 显示, 路数]]`。
func stubHello(name string) []byte {
	var w cbWriter
	w.array(2)
	w.uint(1) // HostMsg::Hello
	w.array(11)
	w.text(name)
	w.text("Windows 11")
	w.text("0.4.0")
	w.array(1) // displays
	w.array(7)
	w.uint(0)
	w.text("DISPLAY1")
	w.uint(0)
	w.uint(0)
	w.uint(1920)
	w.uint(1080)
	w.boolean(true)
	w.uint(0) // current_display
	w.array(0)
	w.uint(0) // platform: Windows
	w.boolean(false)
	w.array(0)
	w.array(1)
	w.uint(0)
	w.uint(1) // streams
	return w.b
}

// parseStubPing 读控制数据报 Ping：`[0, [t]]`。
func parseStubPing(b []byte) (uint64, bool) {
	r := newCBReader(b)
	if n, err := r.array(); err != nil || n < 2 {
		return 0, false
	}
	if kind, err := r.uint(); err != nil || kind != 0 {
		return 0, false
	}
	if _, err := r.array(); err != nil {
		return 0, false
	}
	t, err := r.uint()
	if err != nil {
		return 0, false
	}
	return t, true
}
