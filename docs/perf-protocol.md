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

- 真实被控端连上来走完 `Incoming` → XX → `Confirm`，看托盘是否出现控制端。
- 被控端用 `Pattern::Known`（Noise IK）时的字节一致性 —— 黄金向量已对上，
  还差一次真机联调。
- `ReplayWindow`（128 位窗口）与计数起点：控制通道两个方向各先用掉计数 0
  （`Confirm` 与被控端的决定），浏览器侧收发都从 1 开始。
- CBOR 用真实被控端抓包再对一遍（当前只有上游仓库的黄金字节）。

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

- 流序号由路由器分配：控制通道固定 0，其余从 1 开始递增；一帧画面一条流。
  标志位 bit0 表示这条流结束，bit1 表示整帧被路由器丢弃（浏览器清掉组装状态）。
- 流里是「u32 长度前缀 + 密封单元」，路由器原样转发，前缀不动 —— 浏览器按
  前缀切帧。上行时路由器只补 9 字节会话头，浏览器无法指定会话号。
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
