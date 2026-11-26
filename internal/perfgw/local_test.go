package perfgw

// 本机联调：真实起 QUIC 监听与 WebSocket 控制台，用一个假被控端走完整条链路。
//
// 覆盖的东西：
//   - 被控端注册 → 待批准 → 批准 → 换码重连；
//   - 第一次会话走 Noise XX（还没记录公钥），第二次走 IK；
//   - 控制通道的密文帧、计数连续、Hello 下发与上行控制消息；
//   - 控制数据报 Ping / Pong。
//
// 跑法：go test ./internal/perfgw/ -run TestLocalRelay -v

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/mylucien/deskgw/internal/config"
)

func TestLocalRelay(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(config.Config{
		PerfListen:   "127.0.0.1:0",
		PerfCert:     filepath.Join(dir, "perf.crt"),
		PerfKey:      filepath.Join(dir, "perf.key"),
		PerfIdentity: filepath.Join(dir, "perf_identity"),
	})
	if err != nil {
		t.Fatalf("启动性能模式: %v", err)
	}
	srv.Start()
	defer srv.Close()

	// 第一次（XX）握手学到的公钥要记下来，第二次走 IK。
	var mu sync.Mutex
	var learned []byte
	srv.OnPeerKey(func(code uint32, pub []byte) {
		mu.Lock()
		learned = append([]byte(nil), pub...)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host, err := newStubHost(srv.Listen(), "PC-1", srv.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	go host.run(ctx)

	select {
	case <-host.registered:
	case err := <-host.errs:
		t.Fatalf("注册失败: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("被控端没有注册")
	}
	pending := srv.Pending()
	if len(pending) != 1 {
		t.Fatalf("待批准列表应当有 1 条，实际 %d", len(pending))
	}
	if pending[0].Name != "PC-1" {
		t.Fatalf("待批准记录的名称不对: %+v", pending[0])
	}

	const hostID = 7
	if err := srv.Approve(pending[0].Code, hostID); err != nil {
		t.Fatalf("批准失败: %v", err)
	}
	select {
	case code := <-host.approved:
		if code != hostID {
			t.Fatalf("批准后应当拿到控制码 %d，实际 %d", hostID, code)
		}
	case err := <-host.errs:
		t.Fatalf("重连失败: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("批准之后没有重连")
	}
	if n := len(srv.Pending()); n != 0 {
		t.Fatalf("批准之后待批准列表应当清空，实际 %d", n)
	}

	// 控制台接入点：票据、主机信息、会话记录都按 API 层的方式注入。
	tickets := NewTicketManager(30 * time.Second)
	console := NewConsole(srv, tickets, NewLimits(2, 1))
	console.Host = func(id int64) (HostInfo, error) {
		if id != hostID {
			return HostInfo{}, errBadHost
		}
		mu.Lock()
		key := learned
		mu.Unlock()
		return HostInfo{ID: hostID, Name: "PC-1", OS: "Windows 11", Modes: "perf", Enabled: true, PerfKey: key}, nil
	}
	console.Begin = func(int64) {}
	console.End = func(int64, string, string) {}
	console.Audit = func(int64, string, string, string, string) {}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/perf", func(w http.ResponseWriter, r *http.Request) {
		console.Serve(w, r, ConsoleClient{UserID: 1, Username: "admin", ClientIP: "127.0.0.1"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// ---- 第一次会话：XX（还没有记录被控端公钥）----
	ws1, keys1 := dialConsole(t, ts.URL, tickets, hostID)
	hello1 := readHello(t, ws1, keys1)
	if !strings.Contains(string(hello1), "PC-1") {
		t.Fatalf("Hello 里没有主机名: %x", hello1)
	}
	ws1.Close()

	// 握手成功后公钥应当已经记下来。
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(learned)
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("XX 握手之后没有记录被控端公钥")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 等上一条会话把名额放开。
	time.Sleep(200 * time.Millisecond)

	// ---- 第二次会话：IK（已有公钥）----
	ws2, keys2 := dialConsole(t, ts.URL, tickets, hostID)
	defer ws2.Close()
	readHello(t, ws2, keys2)

	// 上行控制通道：Audio(enabled=true) 的 CBOR 是 82 08 81 f5。
	audio := []byte{0x82, 0x08, 0x81, 0xf5}
	audioSealed := seal(mustKey(t, keys2.ControlSend), 1, audio)
	up := make([]byte, upHeader, upHeader+4+len(audioSealed))
	up[0] = frameUpStream
	up[1] = laneControl
	up = binary.LittleEndian.AppendUint32(up, uint32(len(audioSealed)))
	up = append(up, audioSealed...)
	if err := ws2.WriteMessage(websocket.BinaryMessage, up); err != nil {
		t.Fatalf("发送上行控制消息: %v", err)
	}
	select {
	case got := <-host.inputs:
		if string(got) != string(audio) {
			t.Fatalf("被控端收到的上行消息不对: %x", got)
		}
	case err := <-host.errs:
		t.Fatalf("被控端报错: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("被控端没有收到上行控制消息")
	}

	// 控制数据报：Ping 进去，Pong 出来。
	var ping cbWriter
	ping.array(2)
	ping.uint(0)
	ping.array(1)
	ping.uint(12345678901234)
	dg := make([]byte, upHeader, upHeader+len(ping.b)+sealOverhead)
	dg[0] = frameUpDatagram
	dg[1] = kindControlDatagram
	dg = append(dg, seal(mustKey(t, keys2.DatagramSend), 0, ping.b)...)
	if err := ws2.WriteMessage(websocket.BinaryMessage, dg); err != nil {
		t.Fatalf("发送 Ping: %v", err)
	}
	select {
	case t2 := <-host.pongs:
		if t2 != 12345678901234 {
			t.Fatalf("被控端收到的 Ping 时间戳不对: %d", t2)
		}
	case err := <-host.errs:
		t.Fatalf("被控端报错: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("被控端没有收到 Ping")
	}

	frame := readDown(t, ws2, frameDownDatagram)
	if len(frame) < datagramHeader+sealOverhead {
		t.Fatalf("下行数据报太短: %x", frame)
	}
	pong, err := openStub(mustKey(t, keys2.DatagramRecv), 0, frame[datagramHeader:])
	if err != nil {
		t.Fatalf("解开 Pong: %v", err)
	}
	if string(pong) != string(ping.b) {
		t.Fatalf("Pong 与 Ping 不一致: %x / %x", pong, ping.b)
	}
}

// dialConsole 签一张票、连上控制台、发 connect、读 ready，返回连接与密钥包。
func dialConsole(t *testing.T, base string, tickets *TicketManager, hostID int64) (*websocket.Conn, keyBundle) {
	t.Helper()
	tok, err := tickets.Issue(1, hostID, 1, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	url := "ws" + strings.TrimPrefix(base, "http") + "/ws/perf?ticket=" + tok
	ws, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("连接控制台: %v", err)
	}
	if err := ws.WriteJSON(map[string]any{
		"type": "connect", "host": fmt.Sprintf("h%d", hostID),
	}); err != nil {
		t.Fatalf("发送 connect: %v", err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ready struct {
		Type      string    `json:"type"`
		SessionID uint64    `json:"session_id"`
		Safety    string    `json:"safety"`
		Keys      keyBundle `json:"keys"`
	}
	if err := ws.ReadJSON(&ready); err != nil {
		t.Fatalf("读 ready: %v", err)
	}
	if ready.Type != "ready" {
		t.Fatalf("应当先收到 ready，实际 %q", ready.Type)
	}
	if ready.Safety == "" {
		t.Fatal("ready 里没有安全码")
	}
	return ws, ready.Keys
}

// readHello 读控制通道上被控端发来的 Hello，并解开第一帧密文（计数 1）。
func readHello(t *testing.T, ws *websocket.Conn, keys keyBundle) []byte {
	t.Helper()
	frame := readDown(t, ws, frameDownStream)
	if frame[1] != laneControl {
		t.Fatalf("Hello 应当走控制通道，实际通道 %d", frame[1])
	}
	if seq := binary.LittleEndian.Uint32(frame[2:6]); seq != 0 {
		t.Fatalf("控制通道的流序号应当固定为 0，实际 %d", seq)
	}
	body := frame[downHeader:]
	if len(body) < 4 {
		t.Fatalf("Hello 帧太短: %x", frame)
	}
	n := int(binary.LittleEndian.Uint32(body[:4]))
	if len(body) < 4+n {
		t.Fatalf("Hello 的长度前缀超出帧尾: %d / %d", n, len(body)-4)
	}
	plain, err := openStub(mustKey(t, keys.ControlRecv), 1, body[4:4+n])
	if err != nil {
		t.Fatalf("解开 Hello: %v", err)
	}
	// HostMsg::Hello 是 [1, [...]]。
	if len(plain) < 2 || plain[0] != 0x82 || plain[1] != 1 {
		t.Fatalf("Hello 不是 [1, [...]]: %x", plain)
	}
	return plain
}

// readDown 读一条指定类型的下行二进制帧，跳过文本消息（ended / pong 之类）。
func readDown(t *testing.T, ws *websocket.Conn, want byte) []byte {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("读下行帧: %v", err)
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		if len(data) == 0 {
			continue
		}
		if data[0] != want {
			continue
		}
		return data
	}
}

func mustKey(t *testing.T, s string) [keyLen]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != keyLen {
		t.Fatalf("密钥包里的密钥不合法: %q", s)
	}
	var out [keyLen]byte
	copy(out[:], raw)
	return out
}
