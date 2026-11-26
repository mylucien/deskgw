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

## 仍待实机验证

- 真实被控端用 `Pattern::Known`（Noise IK）连上来握手 —— 黄金向量已逐字节对上，
  还差一次真机联调。
- `ReplayWindow`（128 位窗口）与计数起点：控制通道两个方向各先用掉计数 0
  （`Confirm` 与被控端的决定），浏览器侧收发都从 1 开始。
- 流内的长度前缀在握手之后仍然逐帧存在，`Confirm` 是控制通道上的第一帧密文。
- CBOR 用真实被控端抓包再对一遍（当前只有上游仓库的黄金字节）。
