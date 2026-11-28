package perfgw

// 密文转发：被控端的单向流与数据报搬到浏览器 WebSocket，反向亦然。
//
// 路由器不解析画面，也不解析控制消息：流里是长度前缀加密封单元，整段原样
// 转给浏览器，由浏览器按 4.11 的 frames.ts 切开解密。这里只做三件事——
// 给每条流编号、在消息前面加转发头、在队列满时丢整帧而不是丢半帧。

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mylucien/deskgw/internal/textutil"
	"github.com/quic-go/quic-go"
)

// reasonMax 是关闭帧原因的上限：协议规定 123 字节，留 3 字节余量。
const reasonMax = 120

const (
	// 与浏览器之间的二进制帧类型。首字节是类型，其余按类型解释（4.10）。
	frameDownStream   = 0x01 // 下行流数据：类型 | 通道 | 流序号 u32 | 标志 | 数据
	frameDownDatagram = 0x02 // 下行数据报：类型 | 种类 | 密封单元
	frameUpStream     = 0x11 // 上行流数据：类型 | 通道 | 数据
	frameUpDatagram   = 0x12 // 上行数据报：类型 | 种类 | 密封单元

	// 下行流数据的标志位。
	streamFin  = 1 << 0 // 这条流到此结束
	streamDrop = 1 << 1 // 整帧被路由器丢弃，浏览器应清掉这条流的组装状态

	// downHeader 是下行流数据帧的固定头：类型、通道、流序号、标志。
	downHeader = 7

	// downChunk 是每次转发的字节数。一帧画面最大 32MiB，按 64KiB 切成 512 块，
	// 既能摊平内存峰值，也不至于把 WebSocket 消息发得过碎。
	downChunk = 64 << 10

	// 写队列的暂定上限（4.10）：超过之后视频丢帧，控制通道断开会话。
	queueBytes = 32 << 20
	queueItems = 1024

	// videoDropLimit 是视频持续拥塞多久之后断开整个会话。一直丢帧说明浏览器
	// 那边根本消费不动，留着只会让路由器一直读、一直丢。
	videoDropLimit = 10 * time.Second

	// datagramMax 是单个会话数据报的上限，含 9 字节会话头（4.9）。
	datagramMax = 1000

	// kindControlDatagram 是唯一转发的数据报种类：0 是声音，不做。
	kindControlDatagram = 1

	// upHeader 是上行帧的固定头：类型，加上通道号或种类。
	upHeader = 2
	// datagramHeader 是下行数据报帧的固定头：类型、种类。
	datagramHeader = 2

	// streamIdle 是一条下行流允许的最长静默时间。被控端每帧都会把流写完，
	// 卡住不走说明对端已经异常，取消读取把名额让出来。
	streamIdle = 30 * time.Second
	// writeTimeout 是单次 WebSocket 写入与单次 QUIC 写入的上限。
	writeTimeout = 30 * time.Second
)

var (
	// errQueueFull 表示写队列已经排满，非视频数据不能再等。
	errQueueFull = errors.New("转发队列已满")
	// errUpLane 表示浏览器往不允许的通道发数据（目前只允许控制通道）。
	errUpLane = errors.New("上行只允许控制通道")
	// errUpSize 表示上行消息超过单条上限。
	errUpSize = errors.New("上行消息超长")
)

// outFrame 是一条待写出的 WebSocket 消息。
type outFrame struct {
	text bool
	data []byte
	// recycle 在写完（或确定不再写）之后调用，把整块缓冲还给池子。视频块走
	// 池子：一帧 32MiB 按 64KiB 切，MIPS 小路由上每次分配都会加重 GC。
	recycle func()
}

// framePool 复用下行流数据块。缓冲大小固定为 downHeader+downChunk，恰好装下
// 一块最大的转发帧；用完由 sink 归还。
var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, downHeader+downChunk)
		return &b
	},
}

// sink 是单会话的 WebSocket 写队列。
//
// gorilla 不允许并发写，所以所有消息都进队列，由一个 goroutine 单独写出。
// 队列按字节数与条数双重限制：视频可以丢，控制通道不能丢——后者超限直接
// 结束会话，避免一条卡住的 WebSocket 把路由器的内存拖垮。
type sink struct {
	ws   *websocket.Conn
	out  chan outFrame
	done chan struct{}
	once sync.Once

	mu     sync.Mutex
	bytes  int
	err    error
	reason string
}

func newSink(ws *websocket.Conn) *sink {
	return &sink{ws: ws, out: make(chan outFrame, queueItems), done: make(chan struct{})}
}

// push 把一条消息放进队列。droppable 为 true 时队列满就返回 false，交给
// 调用方决定丢帧；否则结束整个会话。
func (s *sink) push(f outFrame, droppable bool) bool {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return false
	}
	if s.bytes+len(f.data) > queueBytes {
		s.mu.Unlock()
		if droppable {
			return false
		}
		s.fail(errQueueFull)
		return false
	}
	s.bytes += len(f.data)
	s.mu.Unlock()

	select {
	case s.out <- f:
		return true
	default:
		s.release(len(f.data))
		if droppable {
			return false
		}
		s.fail(errQueueFull)
		return false
	}
}

func (s *sink) release(n int) {
	s.mu.Lock()
	s.bytes -= n
	s.mu.Unlock()
}

// fail 记下写失败的原因并让会话收尾。
func (s *sink) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	s.stop("写入浏览器失败")
}

// stop 停止接收新消息；已经排队的消息仍会写完，浏览器才看得到 ended。
func (s *sink) stop(reason string) {
	s.once.Do(func() {
		s.mu.Lock()
		s.reason = reason
		s.mu.Unlock()
		close(s.done)
	})
}

// err 返回第一个写失败的原因。
func (s *sink) errReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err.Error()
	}
	return s.reason
}

// run 是唯一的写者，直到 done 关闭并排空队列。
func (s *sink) run() {
	defer s.close()
	for {
		select {
		case f := <-s.out:
			if !s.write(f) {
				return
			}
		case <-s.done:
			for {
				select {
				case f := <-s.out:
					if !s.write(f) {
						return
					}
				default:
					return
				}
			}
		}
	}
}

func (s *sink) write(f outFrame) bool {
	defer func() {
		if f.recycle != nil {
			f.recycle()
		}
	}()
	_ = s.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	var err error
	if f.text {
		err = s.ws.WriteMessage(websocket.TextMessage, f.data)
	} else {
		err = s.ws.WriteMessage(websocket.BinaryMessage, f.data)
	}
	s.release(len(f.data))
	if err != nil {
		s.fail(err)
		return false
	}
	return true
}

// close 用正常的关闭帧结束 WebSocket，让浏览器能读到原因。
func (s *sink) close() {
	s.mu.Lock()
	reason := s.reason
	s.mu.Unlock()
	_ = s.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, textutil.Clip(reason, reasonMax)),
		time.Now().Add(5*time.Second))
	_ = s.ws.Close()
}

// relay 把一条已建立的会话在 QUIC 与浏览器之间搬字节。
type relay struct {
	sess *session
	sid  uint64
	conn *quic.Conn
	sink *sink
	lim  *rateLimiter

	// seq 给被控端开的每条下行流编号；0 固定给控制通道的常驻流。
	seq atomic.Uint32

	// dropSince 是这一轮持续丢帧的起点（unix 纳秒），0 表示当前没在丢。
	dropSince atomic.Int64
	stopOnce  sync.Once
	reason    string

	mu      sync.Mutex
	streams map[*quic.ReceiveStream]struct{}

	// bulk 是本端往被控端的大块通道，第一次要发剪贴板时才开（单向流，
	// 会话头只在开头写一次）。之后一直是这条流。
	bulkMu sync.Mutex
	bulk   *quic.SendStream
}

func newRelay(sess *session, ws *websocket.Conn, lim *rateLimiter) *relay {
	if lim == nil {
		lim = newRateLimiter()
	}
	return &relay{
		sess: sess, sid: sess.id, conn: sess.conn, sink: newSink(ws), lim: lim,
		streams: map[*quic.ReceiveStream]struct{}{},
	}
}

// run 启动两个方向的转发，直到 WebSocket 关闭。返回后浏览器侧已经断开，
// 调用方可以收尾（写会话记录、审计）。
func (r *relay) run() {
	go r.sink.run()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go r.readControl()
	go r.readDatagrams(ctx)
	go r.acceptStreams(ctx)

	<-r.sink.done
	// 浏览器侧先断了：取消所有读取，别让 goroutine 挂在 QUIC 流上。
	r.cancelReads()
	r.sess.close()
}

// stop 结束会话，reason 会作为 ended 消息发给浏览器。可被多处并发调用。
func (r *relay) stop(reason string) {
	r.stopOnce.Do(func() {
		r.reason = reason
		ended, _ := json.Marshal(map[string]any{"type": "ended", "reason": reason})
		r.sink.push(outFrame{text: true, data: ended}, false)
		log.Printf("性能模式：会话 %d 结束：%s", r.sid, reason)
		r.sink.stop(reason)
	})
}

// sendJSON 往浏览器发一条文本消息（pong 之类）。
func (r *relay) sendJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	r.sink.push(outFrame{text: true, data: b}, false)
}

// endReason 返回会话结束的原因，供写会话记录与审计用。
func (r *relay) endReason() string {
	if r.reason != "" {
		return r.reason
	}
	return r.sink.errReason()
}

// cancelReads 取消本会话开的所有流，不影响这台被控端上的其他会话。
func (r *relay) cancelReads() {
	r.sess.ctrl.CancelWrite(0)
	if rs, ok := r.sess.ctrlIn.(*quic.ReceiveStream); ok {
		rs.CancelRead(0)
	}
	r.mu.Lock()
	for rs := range r.streams {
		rs.CancelRead(0)
	}
	r.streams = map[*quic.ReceiveStream]struct{}{}
	r.mu.Unlock()
	r.bulkMu.Lock()
	if r.bulk != nil {
		r.bulk.CancelWrite(0)
		r.bulk = nil
	}
	r.bulkMu.Unlock()
}

// ---- 被控端 → 浏览器 -------------------------------------------------------

// readControl 转发控制通道：握手之后被控端发的 Hello、Displays、Cursor 等
// 都在这一条流上，密文帧带长度前缀，原样交给浏览器。
func (r *relay) readControl() {
	r.forward(r.sess.ctrlIn, laneControl, 0, false)
}

// acceptStreams 处理被控端后续开的单向流。每帧画面一条流，大块通道常驻
// 一条（剪贴板、光标图像）；分拣已经由 hostConn.demux 按会话号做完，
// 这里只按通道分流。
func (r *relay) acceptStreams(ctx context.Context) {
	for {
		select {
		case st := <-r.sess.streams:
			switch {
			case st.lane == laneBulk:
				// 剪贴板、光标图像：一条流挂整个会话，不能丢（丢了浏览器会
				// 一直等长度前缀后面那半截），也不能设读超时 —— 会话空闲几小时
				// 是常态，原来那句 24 小时的期限会让长会话的剪贴板与光标通道
				// 无声失效。控制通道握手后同样清掉了 deadline，这里保持一致。
				r.track(st.rs)
				go func() {
					defer r.untrack(st.rs)
					r.forward(st.rs, laneBulk, r.seq.Add(1), false)
				}()
			case st.lane >= laneVideo0 && st.lane < laneFile:
				r.track(st.rs)
				go r.forward(st.rs, st.lane, r.seq.Add(1), true)
			default:
				// 控制通道的常驻流只有握手时那一条，文件通道不用。
				st.rs.CancelRead(0)
			}
		case <-ctx.Done():
			return
		}
	}
}

// forward 把一条流原样搬到浏览器：读多少发多少，末尾发一个结束标志。
//
// 视频流按帧短命，读超时就取消；控制通道要挂整个会话，不能设读超时
// （连接级的心跳与空闲超时负责发现失联），否则空闲几十秒就自己断了。
func (r *relay) forward(rd io.Reader, lane uint8, seq uint32, droppable bool) {
	rs, timed := rd.(*quic.ReceiveStream)
	if timed && droppable {
		defer r.untrack(rs)
	}
	buf := make([]byte, downChunk)
	for {
		if timed && droppable {
			_ = rs.SetReadDeadline(time.Now().Add(streamIdle))
		}
		n, err := rd.Read(buf)
		if n > 0 {
			if !r.pushStream(lane, seq, 0, buf[:n], droppable) {
				// 半帧已经在路上了，必须让浏览器把这条流的组装状态清掉，
				// 否则它会一直等一个永远不来的结尾。
				r.pushStream(lane, seq, streamDrop|streamFin, nil, true)
				if timed {
					rs.CancelRead(0)
				}
				r.noteDrop()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				r.pushStream(lane, seq, streamFin, nil, droppable)
				r.dropSince.Store(0)
				if lane == laneControl {
					// 控制通道收尾就是被控端结束了这个会话。
					r.stop("被控端关闭了会话")
				}
			} else if lane == laneControl {
				r.stop("控制通道断开")
			}
			return
		}
	}
}

// pushStream 发一块下行流数据。flags 为 0 表示这是流中间的普通块。
//
// 缓冲从池子取，队列满被丢弃时立刻归还；成功入队的由 sink 在写完后归还。
func (r *relay) pushStream(lane uint8, seq uint32, flags uint8, data []byte, droppable bool) bool {
	fp := framePool.Get().(*[]byte)
	buf := (*fp)[:downHeader+len(data)]
	buf[0] = frameDownStream
	buf[1] = lane
	binary.LittleEndian.PutUint32(buf[2:6], seq)
	buf[6] = flags
	copy(buf[downHeader:], data)
	if !r.sink.push(outFrame{data: buf, recycle: func() { framePool.Put(fp) }}, droppable) {
		framePool.Put(fp)
		return false
	}
	return true
}

// readDatagrams 转发控制数据报（Ping/Pong、Ack、Lost、Report 都在里面）。
//
// ReceiveDatagram 是整条 QUIC 连接共享的：同一台被控端上开两个会话时，如果每个
// relay 各自读，谁先读到谁拿走，会话号不对的那条就被当成杂包丢掉。Pong/Ack/Report
// 会随机落到错误的会话上，RTT 与码率自适应随之失灵。所以真正的读者只有一个
// （hostConn.readDatagrams），这里按会话号从分发通道里取。
func (r *relay) readDatagrams(ctx context.Context) {
	ch := r.sess.host.subscribeDatagram(r.sid)
	defer r.sess.host.unsubscribeDatagram(r.sid)
	for {
		select {
		case sealed, ok := <-ch:
			if !ok {
				return
			}
			f := make([]byte, datagramHeader+len(sealed))
			f[0] = frameDownDatagram
			f[1] = kindControlDatagram
			copy(f[datagramHeader:], sealed)
			if !r.sink.push(outFrame{data: f}, false) {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// ---- 浏览器 → 被控端 -------------------------------------------------------

// upStream 把浏览器的一块密文写进对应的上行通道。控制通道的会话头在握手时
// 已经写过，大块通道按需开流；浏览器无法指定会话号，也就无法写进别的会话。
func (r *relay) upStream(lane uint8, data []byte) error {
	switch lane {
	case laneControl:
		return r.upControl(data)
	case laneBulk:
		return r.upBulk(data)
	}
	return errUpLane
}

func (r *relay) upControl(data []byte) error {
	if len(data) == 0 || len(data) > maxControlMsg {
		return errUpSize
	}
	if !r.lim.allow() {
		return errRate
	}
	_ = r.sess.ctrl.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := r.sess.ctrl.Write(data); err != nil {
		r.stop("写入被控端失败")
		return err
	}
	return nil
}

// upBulk 写大块通道。第一条消息时开一条单向流并写上会话头，之后复用。
func (r *relay) upBulk(data []byte) error {
	if len(data) == 0 || len(data) > maxBulkMsg {
		return errUpSize
	}
	if !r.lim.allow() {
		return errRate
	}
	r.bulkMu.Lock()
	defer r.bulkMu.Unlock()
	if r.bulk == nil {
		ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
		st, err := r.conn.OpenUniStreamSync(ctx)
		cancel()
		if err != nil {
			r.stop("打开大块通道失败")
			return err
		}
		r.bulk = st
		// 会话头与第一条消息一起写：分两次小写时对端只 accept 到流、读不到数据。
		buf := make([]byte, 0, sessionHeaderLen+len(data))
		buf = append(buf, sessionHeader(r.sid, laneBulk)...)
		buf = append(buf, data...)
		_ = st.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := st.Write(buf); err != nil {
			log.Printf("写大块通道失败: %v", err)
			r.stop("写入大块通道失败")
			// 与下面的分支一致：坏流不能留着，否则后续每次写入都打在
			// 同一条已经废掉的流上。
			r.bulk = nil
			return err
		}
		return nil
	}
	_ = r.bulk.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := r.bulk.Write(data); err != nil {
		r.stop("写入大块通道失败")
		r.bulk = nil
		return err
	}
	return nil
}

// upDatagram 转发浏览器发出的控制数据报，自己补上 9 字节会话头。
func (r *relay) upDatagram(kind uint8, sealed []byte) error {
	if kind != kindControlDatagram {
		return errUpLane
	}
	if len(sealed) == 0 || len(sealed)+sessionHeaderLen > datagramMax {
		return errUpSize
	}
	if !r.lim.allow() {
		return errRate
	}
	buf := make([]byte, sessionHeaderLen+len(sealed))
	binary.LittleEndian.PutUint64(buf[:8], r.sid)
	buf[8] = kind
	copy(buf[sessionHeaderLen:], sealed)
	if err := r.conn.SendDatagram(buf); err != nil {
		r.stop("发送数据报失败")
		return err
	}
	return nil
}

// noteDrop 记录一次丢帧。持续丢超过 videoDropLimit 就结束会话：说明浏览器
// 根本消费不动，继续转发只会白烧路由器。
func (r *relay) noteDrop() {
	now := time.Now().UnixNano()
	if r.dropSince.Load() == 0 {
		r.dropSince.CompareAndSwap(0, now)
	}
	if first := r.dropSince.Load(); first != 0 && now-first > int64(videoDropLimit) {
		r.stop("视频持续拥塞")
	}
}

func (r *relay) track(rs *quic.ReceiveStream) {
	r.mu.Lock()
	r.streams[rs] = struct{}{}
	r.mu.Unlock()
}

func (r *relay) untrack(rs *quic.ReceiveStream) {
	r.mu.Lock()
	delete(r.streams, rs)
	r.mu.Unlock()
}
