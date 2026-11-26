package perfgw

// 转发层的逐字节测试：帧头、丢帧路径、上行限制。
//
// 真的 QUIC 连接在 relay 之外的集成测试里，这里只用字节读写把格式钉住。

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// drain 读一条 sink 队列里的消息，超时算失败。
func drain(t *testing.T, s *sink) outFrame {
	t.Helper()
	select {
	case f := <-s.out:
		return f
	case <-time.After(time.Second):
		t.Fatal("队列里没有消息")
		return outFrame{}
	}
}

// TestPushStreamLayout 钉住下行流数据的帧头：类型 | 通道 | 流序号 u32 | 标志。
func TestPushStreamLayout(t *testing.T) {
	r := &relay{sink: newSink(nil)}
	if ok := r.pushStream(laneVideo0, 0x01020304, 0, []byte("abc"), true); !ok {
		t.Fatal("普通块应当入队")
	}
	f := drain(t, r.sink)
	if f.text {
		t.Fatal("流数据必须是二进制帧")
	}
	if len(f.data) != downHeader+3 {
		t.Fatalf("帧长不对: %d", len(f.data))
	}
	if f.data[0] != frameDownStream || f.data[1] != laneVideo0 {
		t.Fatalf("类型或通道不对: % x", f.data[:2])
	}
	if got := binary.LittleEndian.Uint32(f.data[2:6]); got != 0x01020304 {
		t.Fatalf("流序号不对: %#x", got)
	}
	if f.data[6] != 0 {
		t.Fatalf("普通块的标志应当是 0: %d", f.data[6])
	}
	if string(f.data[downHeader:]) != "abc" {
		t.Fatalf("数据不对: %q", f.data[downHeader:])
	}
}

// TestForwardChunksAndFin 一帧被切成多块时，最后要补一个结束标志。
func TestForwardChunksAndFin(t *testing.T) {
	r := &relay{sink: newSink(nil)}
	payload := bytes.Repeat([]byte{0x5a}, downChunk+10)
	go r.forward(bytes.NewReader(payload), laneVideo0, 7, true)

	first := drain(t, r.sink)
	if len(first.data) != downHeader+downChunk {
		t.Fatalf("第一块长度不对: %d", len(first.data))
	}
	second := drain(t, r.sink)
	if len(second.data) != downHeader+10 {
		t.Fatalf("第二块长度不对: %d", len(second.data))
	}
	fin := drain(t, r.sink)
	if len(fin.data) != downHeader || fin.data[6]&streamFin == 0 {
		t.Fatalf("没有收到结束标志: % x", fin.data)
	}
	if got := binary.LittleEndian.Uint32(fin.data[2:6]); got != 7 {
		t.Fatalf("结束帧的流序号不对: %d", got)
	}
}

// TestPushQueueLimits 队列满时：视频丢弃、控制通道让整个会话失败。
func TestPushQueueLimits(t *testing.T) {
	s := newSink(nil)
	for i := 0; i < queueItems; i++ {
		if !s.push(outFrame{data: []byte{0}}, true) {
			t.Fatalf("第 %d 条就被拒了", i)
		}
	}
	if s.push(outFrame{data: []byte{0}}, true) {
		t.Fatal("队列满了还接受视频帧")
	}
	if s.err != nil {
		t.Fatal("丢视频帧不应结束会话")
	}
	if s.push(outFrame{data: []byte{0}}, false) {
		t.Fatal("队列满了还接受控制消息")
	}
	if !errors.Is(s.err, errQueueFull) {
		t.Fatalf("控制通道超限应当结束会话: %v", s.err)
	}
	select {
	case <-s.done:
	default:
		t.Fatal("结束会话后 done 应当关闭")
	}
}

// TestSinkByteLimit 按字节限制也要生效：一条 32MiB 的消息不能无限堆。
func TestSinkByteLimit(t *testing.T) {
	s := newSink(nil)
	big := make([]byte, queueBytes/2+1)
	if !s.push(outFrame{data: big}, true) {
		t.Fatal("第一条应当入队")
	}
	if s.push(outFrame{data: big}, true) {
		t.Fatal("超过字节上限还接受")
	}
}

// TestStopSendsEnded 结束会话时浏览器要先收到 ended，再看到关闭帧。
func TestStopSendsEnded(t *testing.T) {
	r := &relay{sink: newSink(nil)}
	r.stop("测试结束")
	f := drain(t, r.sink)
	if !f.text {
		t.Fatal("ended 必须是文本帧")
	}
	var m struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(f.data, &m); err != nil {
		t.Fatalf("ended 不是合法 JSON: %v", err)
	}
	if m.Type != "ended" || m.Reason != "测试结束" {
		t.Fatalf("ended 内容不对: %+v", m)
	}
	// 重复调用只发一条。
	r.stop("再来一次")
	select {
	case f := <-r.sink.out:
		t.Fatalf("重复 stop 又发了一条: %+v", f)
	default:
	}
}

// TestUpStreamRejects 上行只允许控制通道，且不能超过一帧上限。
func TestUpStreamRejects(t *testing.T) {
	r := &relay{sink: newSink(nil), lim: newRateLimiter()}
	if err := r.upStream(laneVideo0, []byte{1}); !errors.Is(err, errUpLane) {
		t.Fatalf("上行视频通道应当被拒: %v", err)
	}
	if err := r.upStream(laneControl, make([]byte, maxControlMsg+1)); !errors.Is(err, errUpSize) {
		t.Fatalf("超长消息应当被拒: %v", err)
	}
	if err := r.upStream(laneControl, nil); !errors.Is(err, errUpSize) {
		t.Fatalf("空消息应当被拒: %v", err)
	}
	if err := r.upDatagram(0, []byte{1}); !errors.Is(err, errUpLane) {
		t.Fatalf("声音数据报不应转发: %v", err)
	}
	if err := r.upDatagram(kindControlDatagram, make([]byte, datagramMax)); !errors.Is(err, errUpSize) {
		t.Fatalf("超长数据报应当被拒: %v", err)
	}
}

// TestUpRateLimit 上行令牌桶用完后要拒绝，避免一条连接打满 CPU。
func TestUpRateLimit(t *testing.T) {
	l := newRateLimiter()
	for i := 0; i < rateBurst; i++ {
		if !l.allow() {
			t.Fatalf("第 %d 个令牌就被拒了", i)
		}
	}
	if l.allow() {
		t.Fatal("令牌用完还放行")
	}
}

// TestNoteDropLimit 视频持续拥塞超过 10 秒要结束会话；中间恢复过就重新计时。
func TestNoteDropLimit(t *testing.T) {
	r := &relay{sink: newSink(nil)}
	r.noteDrop()
	select {
	case <-r.sink.done:
		t.Fatal("刚开始丢帧就断会话")
	default:
	}
	// 把起点往前挪 11 秒，模拟持续拥塞。
	r.dropSince.Store(time.Now().Add(-11 * time.Second).UnixNano())
	r.noteDrop()
	select {
	case <-r.sink.done:
	default:
		t.Fatal("持续拥塞 11 秒仍未断会话")
	}
	if r.endReason() != "视频持续拥塞" {
		t.Fatalf("结束原因不对: %s", r.endReason())
	}
}

// TestDecodeSessionHeader 上行帧里的通道号必须落在已知范围，避免浏览器
// 用伪造的通道号捅到别的逻辑。
func TestDecodeSessionHeaderLanes(t *testing.T) {
	_, lane, err := decodeSessionHeader(sessionHeader(1, laneFile))
	if err != nil || lane != laneFile {
		t.Fatalf("文件通道应当可解析: %d %v", lane, err)
	}
	if _, _, err := decodeSessionHeader(sessionHeader(1, laneCount)); !errors.Is(err, errLane) {
		t.Fatalf("越界通道号应当报错: %v", err)
	}
	if _, _, err := decodeSessionHeader([]byte{1, 2}); !errors.Is(err, errSession) {
		t.Fatalf("短会话头应当报错: %v", err)
	}
}
