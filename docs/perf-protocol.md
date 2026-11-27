# 性能模式协议核对（Airhand v0.4.0）

设计文档 4.9 的细节读自被控端 v0.3.1。本文件记录对着 **v0.4.0** 源码重新核对的
结果，以及接入层实现（`internal/perfgw`）依赖的常量。被控端每次升级都要重跑一遍。

源码：`github.com/sqlpxc/airhand`，标签 `v0.4.0`。

## 与 v0.3.1 的差异

协议 crate 有 20 个文件有改动，但**线上格式只多了一处**：

| 项 | 变化 | 影响 |
| --- | --- | --- |
| `ControllerIntro` | 新增 `privacy` 字段（`n(6)`，`skip_if` false） | 兼容：不写防窥模式时数组不多一项 |
| `ControllerMsg` | 新增 `Privacy { on }` | 兼容：`open_enum` 之外的新变体，不认识的整条跳过 |
| `ClientMsg::Release` | 语义从「解除绑定」改为「作废控制码」 | 只影响服务端处理，线上格式不变 |

`SIGNAL_VERSION = 10`、`SESSION_VERSION = 1`、ALPN `airhand/1`、帧前缀、通道号、
密封单元、HKDF 标签全部未变，4.9 的其余内容对 v0.4.0 仍然成立。

## 接入层用到的常量（均已核对）

| 项 | 值 | 出处 |
| --- | --- | --- |
| ALPN | `airhand/1` | `airhand-proto/src/lib.rs` |
| 信令版本 | `10`，必须精确相等 | 同上 |
| 会话版本 | `1` | 同上 |
| 信令帧 | `u32 小端长度` + 负载 | `airhand-proto/src/framing.rs` |
| 单条信令上限 | 64 KiB | `MAX_SIGNAL_MSG` |
| 首条消息 | 被控端开一条**双向流**，先写 `ClientHello`，紧跟 `Register`，不等回答 | `airhand-link/src/net.rs` |
| 角色编号 | 被控端 0，控制端 1 | `Role` |
| 消息编码 | minicbor 派生：结构体是**数组**（`skip_if` 的尾部字段不写），带字段的枚举是 `[变体号, 字段数组]` | `tests/v10.rs` |
| 注册超时 | 被控端 10 秒 | `host/mod.rs` |

黄金字节（来自 `crates/airhand-proto/tests/v10.rs`，已作为单元测试的向量）：

```
ClientHello(Host,"PC","W")      84 0a 00 62 50 43 61 57
ServerHello(version)            81 0a
ServerHello(version, 0)         82 0a 00
Register{None,keep,false}       82 01 83 f6 f5 f4
Register{Some,[123456,h'07…]}   82 01 83 82 1a 0001e240 50 07…  f4 f4
Rekey{h'07…}                    82 04 81 50 07…
Release                         81 03
Registered{123456,h'07…}        82 01 82 1a 0001e240 50 07…
```

## 关键结论

**预置配对是必需前提，不是优化项。** 被控端只认 `gate.is_known(控制端公钥)`：
`Pattern::First`（Noise XX）也要先 `is_known` 才准入，否则一律
`Refusal::PairingRequired`。所以路由器控制端的 X25519 公钥必须写进被控端
`config.toml` 的 `[[paired]]`。

桌面客户端启动时读 `[[paired]]`（`client/src-tauri/src/config.rs`，
`Paired { key: 64 位小写十六进制, name, since }`），已验证可行。

**控制码可以被服务端改写。** 被控端拿到 `Registered{code}` 后直接采纳，
`host/mod.rs` 里只有「上一个控制码不可用了」的提示。所以待批准阶段可以先给
一个临时控制码，批准之后断开连接，被控端带 `reclaim` 重连时再换成主机 id。

**TLS 只校验叶子证书指纹。** `PinnedVerifier` 忽略证书链与服务器名称，只比较
`SHA-256(叶子证书 DER)`，64 位小写十六进制，就是 `server_fp` 要填的值。

## 握手实现（Go 侧自写 Noise）

路由器只做**发起方**（控制端），所以只实现 `Noise_IK` 与 `Noise_XX` 的发起方，
被控端那一侧不写 —— 少一半代码，也少一半解析面（`internal/perfgw/noise.go`）。

踩过的坑写在这里，免得下次再踩：

- **IK 的 `<- s` 预消息**。Noise 规定初始化时先 `MixHash` 响应方的 static 公钥。
  漏掉这一步时 `ck` 的演化不受影响（`MixKey` 不碰 `h`），所以密文能对上、密钥也对，
  只有 AEAD 的关联数据错了，表现为「消息解不开」。`newNoiseIK` 里那行
  `mixHash(peer)` 就是补这个的。
- **split 的方向**：第 1 段是发起方→响应方。被控端用 `snow` 的
  `dangerously_get_raw_split`，同样是 `HKDF(ck, 空, 2)` 的两段。
- **安全码是会话级的**，不是设备固定值：`derive(h, h, "airhand safety code")` 取前 8 字节
  小端模一百万。而且被控端在收到 `Confirm` 之前不会在托盘显示这个控制端，所以设计文档
  4.10 里「管理员核对被控端托盘上的安全码」做不到 —— 预置配对已经是带外信任，
  这一句可以去掉。

### 黄金向量怎么生成

`noise.go` 的正确性只能靠字节对比：标准文档对不出 `snow` 的实现细节（比如上面那条
预消息、`split` 的切法）。生成方式：

```
# .perf/vecgen：snow 0.10 + airhand 的同一套调用，static 与 ephemeral 私钥都固定
RUSTFLAGS='--cfg getrandom_backend="custom"' cargo run --release          # 握手向量
RUSTFLAGS='--cfg getrandom_backend="custom"' cargo run --release --bin cborvec   # CBOR 字节
```

输出抄进 `internal/perfgw/vectors_test.go`。`getrandom` 的自定义后端是为了绕开本机没有
C 工具链：`snow` 的 `std` feature 会隐式启用 `ring`（`std` 里的 `ring/std` 不是弱依赖），
编不过就换纯 Rust 的 resolver，但那样 `getrandom` 在 windows-gnu 下又要 `dlltool`。

## 信令与握手消息的线上形状

手写 CBOR 编码器全靠这些实测字节，改结构前先跑一遍 `cborvec`。

```
ServerMsg::Incoming = [3, [session_id, peer, observed, init]]
Peer        = [name, ip]
IpAddr      = [0, bytes(4)] | [1, bytes(16)]        # 0 = IPv4，1 = IPv6
SocketAddr  = [0, [ip_bytes, port]] | [1, [ip_bytes, port]]
HandshakeInit   = {0: pattern, 2: noise}            # 可选字段（pake）不写键
HandshakeReply  = {0: error} | {2: noise} | {3: verdict}   # 只写存在的字段
HandshakeFinish = [noise]                            # 结构体是定长数组
ControllerIntro = [version, name, os, settings, audio, view, (privacy)]
QualitySettings = [fps, bitrate_kbps, max_short, adaptive, codec, (draw_cursor)]
StreamView      = [display, max_short]
HostVerdict     = [version] | [version, refusal]
Confirm         = a0                                 # 空映射
```

两条尾部可选字段都用 `skip_if = is_false`，为 `false` 时整个不写，数组长度随之变短
（`ControllerIntro` 是 6 或 7 项，`QualitySettings` 是 5 或 6 项）。读的时候按剩余项数判断，
不能假定固定长度。

## 会话建立顺序

对着 `host/streams.rs` 的 `HostStreams::open` 与 `secure.rs` 的 `respond` 读出来的，
`session.go` 按这个顺序写：

1. 路由器在信令流上发 `Incoming`，`init` 是 `HandshakeInit`。
2. 被控端**立刻**开本端的控制流（9 字节会话头 + 长度前缀帧），握手回答写在里面 ——
   不是路由器先开、被控端后开。
3. `Pattern::Known`（IK）：被控端只回一条 `HandshakeReply`，里面同时有 `noise`（第 2 条）
   和 `verdict`。`Pattern::First`（XX）：第一条只有 `noise`，路由器要开自己的控制流、
   写 `HandshakeFinish`（负载是 `ControllerIntro`），被控端才回第二条带 `verdict` 的。
   **XX 里流要在读决定之前开**，否则被控端在 `first_stream` 上一直等。
4. `verdict` 是 `HostVerdict` 的密封单元：控制通道「被控端→控制端」的密钥、计数 0。
5. 路由器在自己的控制流上写 `Confirm`（空映射 `a0`）：控制通道「控制端→被控端」的
   密钥、计数 0。被控端解开它才会在托盘显示这个控制端。

- 握手的这几帧是**明文** CBOR（带长度前缀），`Confirm` 才是这条流上第一帧密文。
- 之后浏览器发的控制帧从计数 1 接着往下。
- `noiseMaxMsg` = 16 KiB 是单条 Noise 消息的上限；控制通道一帧的上限是 64 KiB。

## 控制端身份密钥

- 路由器有一把长期 X25519 私钥（`perf_identity`，首次启动生成，权限 600），
  公钥（64 位小写十六进制）要写进每台被控端 `config.toml`：

  ```toml
  [[paired]]
  key = "<公钥>"
  name = "deskgw"
  since = 0
  ```

- 被控端的 `gate.is_known(控制端公钥)` 是硬门槛，`Pattern::First` 也要过这一关；
  不在 `[[paired]]` 里就回 `Refusal::PairingRequired`（1）。
- 私钥丢了或换掉，所有被控端都要重新预置 —— 它比证书更要紧，证书只影响传输层。

## 仍待实机验证

- 空闲保活：控制通道没有消息时，靠控制数据报的 `Ping` 与 QUIC keepalive 撑住长会话。
- 被控端托盘「更换控制码」后，旧的 `perf_secret` 与 `[[paired]]` 的清理流程。
- `perf.enabled` 目前只在启动时读，后台改这项要重启网关。

## 浏览器侧转发协议（已实现）

`/ws/perf?ticket=…` 是一条文本与二进制混用的 WebSocket。票据由
`POST /api/perf/ticket` 签发，30 秒有效、只能用一次、绑定登录用户与来源 IP；
`connect` 里的主机还必须与票据里的主机一致。

文本（JSON）：

| 方向 | 消息 | 说明 |
| --- | --- | --- |
| 浏览器 → 路由器 | `{"type":"connect","host":"h3"}` | 必须是第一条消息，10 秒内发出 |
| 浏览器 → 路由器 | `{"type":"disconnect"}` / `{"type":"ping"}` | 断开；心跳 |
| 路由器 → 浏览器 | `ready` | `session_id`、`host{id,name,os}`、`safety`、`keys` |
| 路由器 → 浏览器 | `error` | `kind`：`codeNotFound` / `hostBusy` / `pairingRequired` / `hostKeyChanged` / `incompatible` |
| 路由器 → 浏览器 | `ended` | 结束原因，之后是正常的关闭帧 |
| 路由器 → 浏览器 | `pong` | 心跳应答 |

`ready.keys` 全部是 64 位十六进制，计数起点按 4.9：控制通道收发各从 1 开始
（`Confirm` 与被控端的决定已经用掉 0），控制数据报与四路画面从 0 开始。
`ready` 写出去之后路由器立即清零手里的会话密钥，之后只搬密文。

二进制，首字节是类型：

```
0x01 下行流数据：类型 | 通道 u8 | 流序号 u32 小端 | 标志 u8 | 数据
0x02 下行数据报：类型 | 种类 u8 | 密封单元
0x11 上行流数据：类型 | 通道 u8 | 数据
0x12 上行数据报：类型 | 种类 u8 | 密封单元
```

- 通道号与 `airhand_proto::SessionLane::number()` 一致：

  | 通道 | 用途 | 流的形式 |
  | --- | --- | --- |
  | 0 | 控制（输入、Hello、Cursor…） | 一条常驻流挂整个会话，流序号固定 0 |
  | 1 | 大块（剪贴板、光标图像） | 一条常驻流挂整个会话，两个方向各一条，流序号从 1 起 |
  | 2–5 | 四路画面 | 一帧一条流，流序号逐个递增 |
  | 6 | 文件 | 不用（文件传输不在范围内） |

- 流序号由路由器分配：控制通道固定 0，其余从 1 开始递增。标志位 bit0 表示这条流
  结束，bit1 表示整帧被路由器丢弃（浏览器清掉组装状态）。
- 流里是「u32 长度前缀 + 密封单元」，路由器原样转发，前缀不动 —— 浏览器按
  前缀切帧。上行时路由器只补 9 字节会话头，浏览器无法指定会话号。
- 大块通道是常驻的：上行第一条消息与 9 字节会话头一次性写出（分两次小写时
  quic-go 对端只会 accept 到流、读不到数据），之后复用同一条流；会话结束时
  路由器 `CancelWrite`，浏览器看到流结束就清掉半帧状态。单条上限 2 MiB。
- 数据报只有种类 1（控制）转发，上行单条含会话头不超过 1000 字节；流上行单条
  不超过 64 KiB，并有限速（600 条/秒）。
- 写队列 32 MiB / 1024 条：视频满了丢整帧，控制通道满了直接结束会话；视频持续
  丢帧超过 10 秒也结束（浏览器根本消费不动）。

## 批准结果的持久化

批准时把重连密钥写进 `hosts.perf_secret`。网关重启后内存表是空的，被控端带着
控制码（= 主机 id）与密钥回来时，`registry.claim` 用 `OnAdopt` 查一次数据库，
对得上就直接放回「已批准」状态，管理员不必重新批准。被控端换控制码走 `Rekey`
时同步更新这份密钥。

## 与真实被控端的联调结果（Airhand 0.4.0，2026-11-26）

被控端装在本机，`config.toml` 指向 `127.0.0.1:14433`，与 `deskgw` 走真实 QUIC。

**被控端必须具备的三项配置**

```toml
server = "127.0.0.1:14433"   # UDP
server_fp = ""               # 首次连接记下服务器证书，之后变了就拒绝
[[paired]]                   # 必须是顶层数组表
key = "<后台显示的控制端公钥>"
name = "deskgw"
since = 0
```

- `[[paired]]` 写成 `[host]` 下的子表（`[[host.paired]]`）**不会被读取**：被控端日志仍是
  `paired=0`，握手会回 `PairingRequired`。顶层写法才得到 `paired=1` / `admission=Known`。
- 首次连上后被控端自己会写 `[server_trust]`（`server` + `fp`），之后换证书会拒绝连接。
- 改了 `server` / `server_fp` / `[[paired]]` 都要重启 Airhand（托盘退出再打开）。

**已验证**

| 项 | 结果 |
| --- | --- |
| `Register`（含 `reclaim`） | 真实被控端首帧被正确解析，出现在待批准列表 |
| 批准 → 断连 → 带旧码重连 | 服务端用 `alias` + `perf_secret` 认回，控制码变成 `hosts.id` |
| Noise XX（首次） | 握手成功，安全码在两端一致，公钥写入 `hosts.perf_key` |
| Noise IK（之后） | 同样成功，被控端日志仍为 `admission=Known` |
| 控制通道下行 | `HostMsg::Hello` 解出主机名、系统、`0.4.0`、显示器、H.264 编码器 |
| 控制通道上行 | `ControllerMsg::Audio{enabled:true}` 让被控端启动音频采集 |
| 数据报 | `Ping{t}` → `Pong{t}`，密钥与计数 0 起点正确 |
| 画面流 | `lane=2` 单向流到达并以结束标志收尾（未解码） |

安全码在三次会话里分别是 `497-256`、`225-902`、`305-843`，路由器 `ready` 与被控端
日志逐字相同 —— 这是握手哈希与派生一致的最直接证据。

被控端在路由器 `CancelWrite` 时会记一条 `stream failed: ... stream reset by peer` 的
WARN，属于正常收尾（我们主动取消流），不影响后续会话。

## 浏览器控制端（已实现）

代码在 `web/src/perf/`：

| 文件 | 职责 |
| --- | --- |
| `wire.ts` | 导入会话密钥、AES-GCM 密封/解封、媒体包头、SPS → `avc1.PPCCLL` |
| `cbor.ts` | 用到的 CBOR 子集（整数、字节串、文本、数组、映射、f32） |
| `messages.ts` | `HostMsg` 解析（含 `HostHello.touch`）；`RequestKeyframe`、`Ack`、`Ping`、`InputEvent::Touch` 的编码 |
| `worker.ts` | 按流序号重组、控制通道顺序解密、WebCodecs 解码、Ack/Ping/关键帧请求 |
| `client.ts` | WebSocket 与 Worker 之间的桥，密钥只在 `ready` 之后交给 Worker |

要点：

- **nonce 是 12 字节**：前 4 字节为 0，后 8 字节是小端计数，与
  `handshake.go` 的 `cipher.NewGCM` 一致。计数是 u64，JS 侧用 `BigInt` 读写，
  不能用 `>>>` 截断（会丢高位）。
- 控制通道是一条常驻流，按 u32 长度前缀切帧、串行解密；画面每帧一条流，
  按网关分配的流序号重组，密钥取 `keys.video[通道号 - 2]`。
- 每收到一帧就发 `Ack`（`seq`、到达时刻、`stream`），每秒发一次 `Ping` 并
  重发最近的 `Ack`（数据报会丢）；缺帧或解码器报错时发 `RequestKeyframe`。
- 画面在 Worker 里解成 `VideoFrame` 后转移给主线程，主线程画到 canvas 上并
  立即 `close()`；主线程不接触密钥。
- 只解 H.264（Annex-B）。codec 字符串从关键帧里第一段 SPS 的前三个字节拼出来，
  H.265/AV1 只提示不支持。
- `Cursor`（可见性，控制通道）已经处理；`CursorImage`（光标形状）与文件通道仍
  按设计丢弃。可见性在协议里是三态，不能压成布尔：
  - `shown`（1）：被控端不画光标，用本地光标；
  - `inFrame`（2）：被控端已经把光标画进画面，藏掉本地光标，**但照常发绝对坐标**
    （协议明确如此，误当成"隐藏"会让指针不动）；
  - `hidden`（0）：藏掉本地光标，改发 `MouseDelta`。
  代价是光标形状不同步：文本 I 型、调整大小、忙碌这些只从 `CursorImage` 来，
  现在网关丢弃大块通道，本地只能显示一个箭头。
- 键鼠走 `ControllerMsg::Input`（控制通道上密封）：鼠标是归一化坐标（0..1，相对
  第 0 路画面），按键与滚轮按浏览器事件翻译。一批事件攒一帧发出，`t` 与控制数据报
  的 `Ping` 用同一个时钟（被控端按到达间隔判断是否过时，两边的绝对时钟不用对齐）。
- 键盘分两条路，不重叠，由悬浮面板里的「文本 / 物理键」切换（记在 localStorage）：
  - **文本模式**（默认）：带 Ctrl/Alt/Meta 的组合、F1–F24、Escape、Tab、Enter、
    Backspace、Delete、方向键、Home/End/PageUp/PageDown、修饰键本身走
    `InputEvent::Key`；可打印字符不拦默认行为，交给一个 1×1 的隐藏 `textarea`，
    `input`（`isComposing` 为假时）与 `compositionend` 兜底把上屏的文本作为
    `InputEvent::Text` 发出去。中文、日文、emoji 都走这条，被控端按 Unicode 注入。
  - **物理键模式**：所有键（含字母数字）都按 `KeyboardEvent.code` 走
    `InputEvent::Key`，给读扫描码的程序用；中文与输入法组字一律不发送。切模式时
    先 `ReleaseAll`，并清掉输入代理里没上屏的内容。
  - 抬起时按"按下时发过没有"（`heldKeys`）决定，不看此刻的修饰键状态，否则
    Ctrl+A 的 `A` 抬起会漏发，被控端卡住这个键。
- 隐藏 `textarea` 只在文本模式、且用鼠标按下时才移到指针处并聚焦，输入法候选框
  跟着走；手指点画面不聚焦它，免得手机弹软键盘。切到物理键模式或触摸模式后，
  pointerdown 显式聚焦 canvas —— 事件被 `preventDefault` 了，焦点不会自己过去。
- **触摸**（面板里的「指针 / 触摸」切换）：`HostHello.touch`（字段 7）为真时才可选，
  否则按钮禁用并在面板里说明。按 `pointerId` 跟踪最多 10 个点，发
  `InputEvent::Touch`（变体 7，字段 `id / phase / x / y`，phase 为
  down=0 / move=1 / up=2 / cancel=3），坐标同 `MouseMove`；失焦、切模式、断开时
  给未抬起的点补 `cancel`。黄金字节 `82018205818207840201fa3f000000fa3e800000`
  由 v0.4.0 的 minicbor derive 生成。
- **触屏的「指针」模式是一块触控板**（与普通模式同款交互，只在触屏生效；鼠标仍走
  绝对坐标）：手指相对位移移动一个自绘箭头（虚拟指针初始在画面中心，位移按 1.5 倍
  屏幕像素换算），单击把虚拟指针位置同步过去再按左键，长按 520ms 出右键，双击后按住
  可拖拽（按下推迟到 560ms 的双击窗口之外，划过抖动阈值则立即按下），双指上下滑动
  按 60 CSS 像素一格折算成 `InputEvent::wheel`。被控端把光标藏起来时
  （`CursorVisibility=0`）改发 `MouseDelta`，与鼠标路径一致。切模式、失焦、断开时
  释放按住的键并清掉手势定时器。
- 顶栏已取消：主机、安全码、读数、返回与断开都收进可拖动的悬浮面板（与普通模式
  同一套交互），面板开合点按钮或面板外；按钮位置单独存 `deskgw.perfFabPos`，
  不影响 RDP 模式。
- **剪贴板走大块通道（通道 1）**：两个方向各一条常驻流，密钥 `bulk_send` /
  `bulk_recv`，计数都从 0 开始，帧还是「u32 长度前缀 + 密封单元」。
  - 下行：被控端剪贴板变了发 `HostMsg::Clipboard`（`[8, ["文本"]]`），浏览器
    直接 `navigator.clipboard.writeText`。写失败（页面没焦点、权限没给）就攒在
    `pendingRemote` 里，等下一次 `pointerdown` 这个用户手势再补一次。
  - 上行：在隐藏 `textarea` 上监听 `paste`，拿到纯文本后 `preventDefault`
    （否则会当成一次 `Text` 输入又发一遍），把原文用 `ControllerMsg::Clipboard`
    （`[7, ["文本"]]`）推过去，再补一对 `KeyV` down/up —— 被控端自己按 Ctrl+V
    粘贴，这样连不认剪贴板消息的老程序也能粘进去。
  - 只做文本：图片、文件不碰（文件剪贴板不在范围内）。单条上限 2 MiB，
    超了网关直接断开这条流。
  - 不会来回弹：下行内容只是写进本地剪贴板，不触发 `copy`；上行只在用户
    真正按 Ctrl+V 时发生一次。
- 页面失焦、标签页隐藏、主动断开时先发 `ReleaseAll`，避免被控端留下按住的键。
- 验证鼠标**不能靠画面帧差**：`shown` 时光标由控制端本地画，画面里没有指针，
  被控端也不会因为指针移动而重编码。要看效果（右键菜单、开始菜单、悬停高亮）。

实测（2026-11-27，本机，Chrome 稳定版）：

| 项 | 结果 |
| --- | --- |
| 控制通道 | Hello 解出主机名、系统、`0.4.0`、显示器、编码器 |
| 画面 | 1920×1080，30–31 fps，静态桌面 0.4–0.8 Mbps，RTT 1–12 ms |
| 连续 8 秒 | 无解码错误、无丢帧、会话不中断 |
| 安全码 | 每次会话与网关日志逐字一致 |
| 键盘输入 | `Win+R` 在被控端弹出「运行」对话框 |
| 鼠标单击 | 点任务栏开始按钮，被控端弹出开始菜单 |
| 鼠标右键 | 桌面空白处右键，菜单出现在指针所在位置（归一化坐标映射正确） |
| 光标可见性 | 被控端回 `cursor {visibility: 1}`，画面内无指针，本地光标跟随 |
| 英文文本 | 记事本里打出 `直接插入中文ABC组字上屏 xyz`（`Text` 逐段上屏，与 `Key` 混排） |
| 中文文本 | 输入法组字上屏、直接插入中文都进记事本（被控端按 Unicode 注入） |
| 剪贴板下行 | 被控端记事本里复制 `远端复制ABC-123`，浏览器 `navigator.clipboard.readText()` 读回一致 |
| 剪贴板上行 | 浏览器 `clipboard.writeText` 后按 Ctrl+V，被控端记事本粘出第二行 `浏览器推过来的xyz789`（截图确认） |
| 悬浮面板 | 桌面点击展开、拖动改位并写入 `deskgw.perfFabPos`、面板外点击收起；顶栏已移除 |
| 手机触摸 | 390×664 触摸模拟：面板在屏内可点，点画布后焦点在 canvas，不会弹软键盘 |
| 触屏指针手势 | 自绘箭头可见；单击发 `move+button0`，长按 520ms 在被控端弹出右键菜单（截图确认），双指滑动发 4 次 `wheel:50`，双击拖拽发出 `down→move→up` |
| 物理键模式 | 记事本里打出 `PHYS-ABC`（全部走 `Key`）；同模式下 `中文不应上屏` 一个字都没进 |
| 文本模式 | 切回后 `中文TEXT` 正常上屏（见截图 `keymode-text.png`） |

离线核对（`.perf/tests/perf.test.mjs`）覆盖：Go 生成的密封单元能在浏览器侧解开、
再封回去字节一致；`v10.rs` 的 CBOR 黄金字节；媒体包头与 SPS。测试入口：

```
cd .perf/tests
../deskgw/web/node_modules/.bin/esbuild perf.test.mjs --bundle --format=esm --platform=node --outfile=out.mjs
node out.mjs
```

## 已知限制

- **系统对话框不认 Unicode 注入**：「运行」（Win+R）这类用 ANSI `WM_CHAR` 的老对话框
  收不到 `Text`，中文进不去（英文正常）。记事本、浏览器、Office 这些正常的编辑框没问题。
- **文本模式下读扫描码的程序拿不到物理键**：可打印字符走 `Text`，游戏（WASD）这类程序
  需要在面板里切到「物理键」模式（已做，切换会记住）。
- **光标形状不同步**：`CursorImage` 走大块通道，网关丢弃，本地只显示箭头。
- **剪贴板只传文本**：图片、文件不传（文件剪贴板不在范围内）。下行写本地剪贴板
  需要页面有焦点，没焦点时先攒着，下一次点击补写。
- **粘贴靠被控端自己按 Ctrl+V**：浏览器把文本推过去，再补一对 `KeyV`。被控端
  当前焦点在游戏之类不认 `WM_PASTE` 的窗口里就粘不进去（键是按下去了）。
- **触摸开关受被控端限制**：Windows 被控端的 `HostHello.touch=false`，面板里的
  「触摸」禁用；手机仍能用「指针」模式，它有触控板手势（相对移动、单击、长按右键、
  双击拖拽、双指滚动），已真机验证。原生 Touch 注入效果验不了（离线有黄金字节）。
- **物理键模式下无法打字到软键盘**：手机上不自动聚焦隐藏输入框，避免误弹软键盘；
  要用软键盘打字得切回文本模式（或接蓝牙键盘后切物理键模式）。
