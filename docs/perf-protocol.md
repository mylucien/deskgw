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

## 仍待实机验证

- 被控端用 `Pattern::Known`（Noise IK）与 Go 侧握手的字节一致性。
- `ReplayWindow`（128 位窗口）与计数起点：控制通道两个方向各先用掉计数 0
  （`Confirm` 与被控端的决定）。
- 流内的长度前缀在握手之后仍然逐帧存在，`Confirm` 是控制通道上的第一帧密文。
- CBOR 用真实被控端抓包再对一遍（当前只有上游仓库的黄金字节）。
