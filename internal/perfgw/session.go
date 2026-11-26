package perfgw

// 会话通道：9 字节会话头、长度前缀帧、Incoming 信令，以及从 Incoming 到
// 「控制端发出 Confirm」这一段。
//
// 时序（对着 airhand-link 的 host/streams.rs 与 secure.rs 读出来的）：
//
//	路由器                                  被控端
//	  ── Incoming(init = Noise 第 1 条) ──▶
//	                                         开本端控制流（9 字节头）
//	  ◀────── 控制流上的 HandshakeReply ──────
//	  ── HandshakeFinish（只有 XX）──────────▶
//	  ◀────── HandshakeReply（加密的决定）───
//	  ── Confirm（控制通道第一帧密文）──────▶  解开才在托盘显示这个控制端
//
// Confirm 之前被控端不显示、也不提醒本机用户，所以这里失败就整个会话失败，
// 没有「先连上再说」的余地。

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// 通道号，与 airhand_proto::SessionLane::number() 一致。
	laneControl = 0
	laneBulk    = 1
	// laneVideo0 是第 0 路画面，之后每路加一；laneFile 是文件通道（不用）。
	laneVideo0 = 2
	laneFile   = laneVideo0 + videoStreams
	laneCount  = laneFile + 1

	// 各通道一帧负载的上限，含加密开销、不含长度前缀。
	maxControlMsg = 64 << 10
	maxBulkMsg    = 2 << 20
	// maxVideoMsg 是一帧画面的上限：32 MiB 的包再加上密封单元的开销。
	maxVideoMsg = 32<<20 + sealOverhead

	// sessionHeaderLen 是每条单向流开头的会话头：会话号 u64 小端 | 通道号 u8。
	sessionHeaderLen = 9

	// stepTimeout 是握手里每一步的上限，被控端的 STEP_TIMEOUT 也是 15 秒。
	stepTimeout = 15 * time.Second
)

var (
	// errLane 表示会话头里的通道号不认识（被控端升级后加了新通道，交给上层丢弃）。
	errLane = errors.New("会话头的通道号不认识")
	// errSession 表示会话头跟当前会话对不上。
	errSession = errors.New("会话头不属于这个会话")
	// errHostOffline 表示要连的被控端现在不在线。
	errHostOffline = errors.New("被控端不在线")
	// errNotApproved 表示这台被控端还没批准，不允许任何用户连上去。
	errNotApproved = errors.New("被控端还没有批准")
)

// sessionHeader 写出一条单向流开头的 9 字节会话头。
func sessionHeader(sessionID uint64, lane uint8) []byte {
	out := make([]byte, sessionHeaderLen)
	binary.LittleEndian.PutUint64(out[:8], sessionID)
	out[8] = lane
	return out
}

// decodeSessionHeader 读会话头。通道号不在 0..6 之间时返回 errLane。
func decodeSessionHeader(b []byte) (sessionID uint64, lane uint8, err error) {
	if len(b) < sessionHeaderLen {
		return 0, 0, errSession
	}
	sessionID = binary.LittleEndian.Uint64(b[:8])
	lane = b[8]
	if lane >= laneCount {
		return sessionID, lane, errLane
	}
	return sessionID, lane, nil
}

// readSessionHeader 从流开头读会话头，并核对它确实是这个会话的这条通道。
func readSessionHeader(r io.Reader, sessionID uint64, lane uint8) error {
	var b [sessionHeaderLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return fmt.Errorf("读会话头: %w", err)
	}
	gotID, gotLane, err := decodeSessionHeader(b[:])
	if err != nil {
		return err
	}
	if gotID != sessionID || gotLane != lane {
		return fmt.Errorf("%w：会话号 %d、通道 %d", errSession, gotID, gotLane)
	}
	return nil
}

// sessionPeer 是被控端在 Incoming 里看到的对端（控制端）信息，只用于显示。
type sessionPeer struct {
	name string
	ip   net.IP
}

// writeAddr 写一个 IpAddr：`[0, 4 字节]` 或 `[1, 16 字节]`，与 minicbor 的
// 实现一致。IPv4-in-IPv6 形态（::ffff:a.b.c.d）按 IPv4 写。
func (w *cbWriter) addr(ip net.IP) error {
	if v4 := ip.To4(); v4 != nil {
		w.array(2)
		w.uint(0)
		w.bytes(v4)
		return nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return errors.New("地址不合法")
	}
	w.array(2)
	w.uint(1)
	w.bytes(v6)
	return nil
}

// sockaddr 写一个 SocketAddr：`[0|1, [地址字节, 端口]]`。注意与 IpAddr 不同 ——
// minicbor 把 IpAddr 编成 `[0|1, 地址字节]`，SocketAddr 再多一层数组，端口在里面。
func (w *cbWriter) sockaddr(ip net.IP, port uint16) error {
	if v4 := ip.To4(); v4 != nil {
		w.array(2)
		w.uint(0)
		w.array(2)
		w.bytes(v4)
		w.uint(uint64(port))
		return nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return errors.New("地址不合法")
	}
	w.array(2)
	w.uint(1)
	w.array(2)
	w.bytes(v6)
	w.uint(uint64(port))
	return nil
}

// encodeIncoming 写 ServerMsg::Incoming：`[3, [会话号, [名称, 地址], [地址, 端口], 握手第 1 条]]`。
// 字段顺序与 airhand-proto 的 signal.rs 一致；编号是线上的类型，不能改。
func encodeIncoming(sessionID uint64, peer sessionPeer, observed *net.UDPAddr, init []byte) ([]byte, error) {
	if observed == nil {
		return nil, errors.New("没有对端地址")
	}
	var w cbWriter
	w.array(2)
	w.uint(3)
	w.array(4)
	w.uint(sessionID)

	w.array(2)
	w.text(peer.name)
	if err := w.addr(peer.ip); err != nil {
		return nil, err
	}

	if err := w.sockaddr(observed.IP, uint16(observed.Port)); err != nil {
		return nil, err
	}

	w.bytes(init)
	return w.b, nil
}

// sessionWire 是建立会话时要用的三条流。
//
// ctrlIn 要等 Incoming 发出去、被控端才会开，所以给的是回调而不是现成的流；
// 回调返回后由调用方负责关闭。
type sessionWire struct {
	// signal 发一条信令消息。给函数而不是 io.Writer，是因为一条消息要整帧写：
	// writeFrame 分「长度前缀」「负载」两次写，接成 io.Writer 就会被别的消息插进去。
	signal  func(payload []byte) error
	ctrlOut io.Writer
	// accept 拿到被控端开的控制流，以及用完之后的清理函数。
	accept func() (io.Reader, func(), error)
}

// startSession 发 Incoming、在被控端开的控制流上走完握手、发出 Confirm，
// 返回会话密钥。返回之后路由器就不再需要这些密钥（除了测试用的自检）。
func startSession(sessionID uint64, hs *handshake, peer sessionPeer, observed *net.UDPAddr, w sessionWire) (*sessionKeys, error) {
	init, err := hs.start()
	if err != nil {
		return nil, err
	}
	incoming, err := encodeIncoming(sessionID, peer, observed, init)
	if err != nil {
		return nil, err
	}
	if err := w.signal(incoming); err != nil {
		return nil, fmt.Errorf("发送 Incoming: %w", err)
	}

	// 本端控制流的会话头先写：XX 的被控端在这一步之后才等它。
	if _, err := w.ctrlOut.Write(sessionHeader(sessionID, laneControl)); err != nil {
		return nil, fmt.Errorf("写控制流的会话头: %w", err)
	}

	ctrlIn, release, err := w.accept()
	if err != nil {
		return nil, err
	}
	defer release()
	if err := readSessionHeader(ctrlIn, sessionID, laneControl); err != nil {
		return nil, err
	}

	reply, err := readFrame(ctrlIn, maxControlMsg)
	if err != nil {
		return nil, fmt.Errorf("读被控端的握手回答: %w", err)
	}
	finish, err := hs.reply(reply)
	if err != nil {
		return nil, err
	}
	if finish != nil {
		if err := writeFrame(w.ctrlOut, finish); err != nil {
			return nil, fmt.Errorf("发送 HandshakeFinish: %w", err)
		}
	}
	if hs.pattern() == patternFirst {
		verdict, err := readFrame(ctrlIn, maxControlMsg)
		if err != nil {
			return nil, fmt.Errorf("读被控端的决定: %w", err)
		}
		if err := hs.verdictReply(verdict); err != nil {
			return nil, err
		}
	}

	keys, err := hs.keys()
	if err != nil {
		return nil, err
	}
	// Confirm 是控制通道上第一帧密文，计数 0；被控端解开它才会显示这个控制端。
	// 之后的帧（浏览器发的输入）从计数 1 接着往下。
	if err := writeFrame(w.ctrlOut, seal(keys.control[0], 0, confirmMessage())); err != nil {
		return nil, fmt.Errorf("发送 Confirm: %w", err)
	}
	return keys, nil
}

// session 是一个已经握手完成的会话。密钥交给浏览器之后路由器就不再需要它们，
// 只留下控制流用于转发；这里先保留，等转发层接上来。
type session struct {
	id   uint64
	host *hostConn
	keys *sessionKeys
	// ctrl 是本端开的控制流：已经有会话头与 Confirm，之后是浏览器发来的密文帧。
	ctrl *quic.SendStream
}

// StartSession 让指定控制码的被控端开一个会话：发 Incoming、走完端到端握手、
// 发出 Confirm。peerKey 是被控端已批准的公钥，nil 表示还没记录过（走 Noise XX，
// 由调用方把这次学到的公钥存下来）。
func (s *Server) StartSession(code uint32, peer sessionPeer, intro controllerIntro, peerKey *ecdh.PublicKey) (*session, error) {
	s.cmu.Lock()
	hc := s.conns[code]
	s.cmu.Unlock()
	if hc == nil {
		return nil, errHostOffline
	}
	// 批准之前任何用户都不能用：控制码还是待批准区间的，直接拒绝。
	if p, ok := s.reg.get(code); !ok || !p.approved {
		return nil, errNotApproved
	}
	observed, ok := hc.conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("被控端地址不可用")
	}

	// XX 有两个往返，给整段握手留三倍的单步时间。
	deadline := time.Now().Add(3 * stepTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), 3*stepTimeout)
	defer cancel()
	ctrl, err := hc.conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("开控制流: %w", err)
	}
	_ = ctrl.SetWriteDeadline(deadline)
	done := false
	defer func() {
		_ = ctrl.SetWriteDeadline(time.Time{})
		if !done {
			// 握手中途失败：这条流上没有会话了，别让被控端挂着。
			ctrl.CancelWrite(1)
		}
	}()

	sid := s.sid.Add(1)
	hs := newHandshake(s.id, peerKey, intro)
	keys, err := startSession(sid, hs, peer, observed, sessionWire{
		signal:  hc.sendSignal,
		ctrlOut: ctrl,
		accept: func() (io.Reader, func(), error) {
			ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
			defer cancel()
			rs, err := hc.conn.AcceptUniStream(ctx)
			if err != nil {
				return nil, nil, fmt.Errorf("被控端没有开控制流: %w", err)
			}
			_ = rs.SetReadDeadline(deadline)
			return rs, func() { rs.CancelRead(0) }, nil
		},
	})
	if err != nil {
		return nil, err
	}
	done = true
	// 第一次（XX）握手顺手学到被控端公钥：记进 hosts.perf_key，下次就走 IK。
	// 公钥变了说明被控端重装过或者有人在冒充，由调用方决定要不要重新批准。
	if peerKey == nil && s.onPeer != nil && hs.noise.peerKey != nil {
		s.onPeer(code, hs.noise.peerKey.Bytes())
	}
	log.Printf("性能模式：会话 %d 建立（%s，安全码 %s）", sid, hc.name, keys.safety)
	return &session{id: sid, host: hc, keys: keys, ctrl: ctrl}, nil
}
