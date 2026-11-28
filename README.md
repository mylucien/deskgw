# deskgw

OpenWrt Web 远程桌面网关。单一 Go 静态二进制，在路由器上提供 HTTPS 管理界面、多用户与主机授权、审计日志；远程桌面通道按里程碑逐步接入。

设计方案见 [`docs/design.md`](docs/design.md)。

## 当前实现范围

| 模块 | 状态 |
|---|---|
| HTTPS 服务、自签证书与指纹 | 已实现 |
| 登录、argon2id 密码哈希、服务端 Session、CSRF、失败锁定与自助改密 | 已实现 |
| Web 用户增删改查、角色（admin / user）、主机授权、并发配额 | 已实现 |
| 主机增删改查、私网地址校验（防 SSRF，仅性能模式的主机允许公网地址） | 已实现 |
| SQLite 持久化与 schema 迁移 | 已实现 |
| RDP 隧道（一次性票据 + 字节中转，浏览器内 TLS / NLA，含输入法与剪贴板） | 已实现 |
| 应用内多标签会话（并发上限由服务端配额决定，默认 2，可调至 32）、在线会话列表与强制断开 | 已实现 |
| 审计日志、CSV 导出（不截断）、会话记录 90 天清理、系统设置 | 已实现 |
| SMB 文件面板（浏览 / 上传分片续传 / 下载 Range / 新建 / 重命名 / 删除） | 已实现 |
| 性能模式（perfgw、浏览器端解密） | 已实现，需在设置中开启 |

RDP 连接流程：在主机列表点击「连接（RDP）」→ 输入 Windows 账号密码 → 浏览器内的 WASM 客户端与目标机直接协商，网关只做字节中转。

传输分两层：浏览器先通过 WebSocket 连到网关，网关凭一次性票据连到数据库里的私网地址，随后把两个方向的字节原样搬运。X.224 协商与 TLS 握手都发生在浏览器与目标机之间，**网关不解析 RDP、不终结 TLS、不具备解密能力**，因此 NLA 凭据既不出浏览器，也不以明文经过网关。连接票据一次性有效并绑定来源 IP；目标地址只取自数据库，浏览器无法指定。

首次连接某台主机时采用 TOFU（首次使用即信任）：把目标机证书的 SHA-256 指纹记在浏览器本地，之后指纹变化会拒绝连接，并在界面上提供「信任新证书并重连」（重装系统或换证书时用）。指纹是按主机分别保存的，清除站点数据后需要重新确认。会话工作区支持同时打开多台主机，每个标签一个独立 WASM 会话，切换标签不会重连；标签数上限取自服务端下发的用户并发配额（`users.max_sessions`，默认 2，上限 32），切到别的页面再回来会话仍在，断线后可在画布上直接重连。

键盘输入分两路：普通按键按 PS/2 扫描码发送，保留快捷键与功能键；中文、日文等输入法提交的文本走 RDP 的 Unicode 通道。浏览器只在可编辑元素上启动输入法，所以画布上叠了一个透明的输入框承接键盘，候选框跟随点击位置。剪贴板同步支持文本与 PNG 图片（RDP 模式下不做文件剪贴板），是否可用由用户的「允许剪贴板」权限决定：远端复制的内容会写入浏览器剪贴板，本地按 Ctrl+V 时先把本地内容交给远端再发送按键；读取浏览器剪贴板需要授权，被拒绝时只在会话日志里提示，不影响其余操作。图片上限 4 MiB，超过则跳过并提示；浏览器不允许脚本写图片剪贴板时（如 Firefox）退回写文本。

SMB 文件传输使用连接时输入的同一份 Windows 凭据，首次打开面板时由前端换取短期文件令牌（绑定会话与来源 IP，30 分钟有效，过期就地重取，不会把你踢回登录页）。与 RDP 不同，SMB 由网关代连，因此**网关会在内存中短暂持有明文密码**：不落盘、不写日志，用完即清零；每次文件操作新建一条连接、用完即关，全局同时最多 24 条（超出返回 503 并提示稍后重试），单次读写有 60 秒空闲上限，避免目标机卡死把名额长期占住；上传会话 5 分钟没有进展即回收。文件目标取数据库中的私网主机与 SMB 端口，路径拒绝 `..` 穿越；共享名默认 `C$`，可在面板中切换。写入是备份式替换：先写临时文件，改名覆盖前把旧文件备份，失败可回滚，不会「先删后改名」把原文件弄丢；上传会校验声明的总大小与分片偏移，覆盖已有文件需二次确认。文件操作写入审计日志。

## 快速开始

从 [Releases](../../releases) 下载对应架构的安装包：

| 文件 | 适用环境 |
|---|---|
| `deskgw_<ver>_x86_64.ipk` | OpenWrt / ImmortalWrt 24.10，x86 软路由 |
| `deskgw_<ver>_aarch64_cortex-a53.ipk` | 24.10，aarch64（an7581） |
| `deskgw-<ver>_r1_x86_64.apk` | ImmortalWrt 25.12 / snapshot |
| `deskgw-<ver>_r1_aarch64_cortex-a53.apk` | snapshot 的 airoha/an7581 |

```sh
opkg install deskgw_<ver>_<arch>.ipk        # 24.10
apk add --allow-untrusted deskgw-*.apk      # 25.12 / snapshot
```

安装完成后：

1. 服务由 procd 托管并设为开机自启，默认监听 `0.0.0.0:8443`。
2. 首次启动生成自签证书与初始管理员 `admin`，随机密码写入 `/etc/deskgw/initial-password.txt`（权限 0600），日志只提示该文件位置，不打印明文。
3. 浏览器访问 `https://<路由器地址>:8443`，登录后可用顶栏「改密码」自助修改密码，在「管理」中添加主机与用户。
4. LuCI 菜单中提供「服务 → deskgw」，用于修改监听参数、查看证书指纹与重启服务。

> 默认仅应在 LAN 内使用。管理界面是远程桌面通道的控制入口，不建议将 8443 直接映射到公网；如需外部访问，应先接入 WireGuard 等 VPN。

## UCI 配置

`/etc/config/deskgw`：

```
config deskgw 'main'
    option enabled '1'
    option listen '0.0.0.0:8443'
    option cert '/etc/deskgw/server.crt'
    option key '/etc/deskgw/server.key'
    option cert_names ''
    option data_dir '/etc/deskgw'
    option session_idle_min '30'
    option max_upload_mb '2048'
    option cookie_secure '1'
    option redirect_listen ''
    option gomemlimit ''
    option perf_enabled '0'
    option perf_listen '0.0.0.0:4433'
    option perf_cert '/etc/deskgw/perf.crt'
    option perf_key '/etc/deskgw/perf.key'
    option perf_identity '/etc/deskgw/perf_identity'
    option perf_udp_tune '1'
    option perf_udp_buf_mb '8'
```

`session_idle_min` 与 `max_upload_mb` 只在后台「设置」里还没有保存过时作为初始值写入数据库，之后以数据库为准——两处都能改会导致「改了这个那个不生效」，所以只保留一个权威来源。`perf_enabled` 只在启动时读，改完要重启服务；`perf_udp_tune` 仅在 `perf_enabled=1` 时生效，卸载包时会撤销写入的 sysctl 配置。

`data_dir` 默认是 `/etc/deskgw`（OpenWrt 上是 overlay 分区）。证书、SQLite 数据库、初始管理员密码都放这里，审计和会话会持续写入，长期运行对 eMMC/闪存不友好。要改到外部存储（例如 `/mnt/usb/deskgw`）时，注意两点：目录必须能被 root 写，且挂载要早于本服务启动（否则服务会先在 overlay 上重建一份空库，挂载完成后旧的数据库仍然被占用）。启动日志里会打印当前使用的目录。

## 目录结构

```
cmd/deskgw/               入口：TLS、证书生成、初始管理员、优雅退出
internal/
  auth/                   argon2id、Session、CSRF、登录限流
  user/ host/             用户、主机、授权
  store/                  SQLite 连接与 schema 迁移
  api/                    REST 路由与中间件
  tunnel/                 RDP 隧道：一次性票据、WS↔TCP 字节转发（不解析 RDP）
  perfgw/                 性能模式：QUIC 接入、握手、注册表、浏览器端复用
  filegw/                 SMB 文件网关：短期令牌、路径校验、go-smb2 流式读写
  httpx/ textutil/        同源校验、截断与路径等小工具
  audit/                  审计日志
  config/                 环境变量配置
web/                      Vue 3 前端与 WASM 客户端，构建产物由 Go embed 托管
wasm/                     从 IronRDP 0.17.0 官方源码裁剪的 WASM 客户端（浏览器内直连 TLS）
openwrt/                  包 Makefile、procd 脚本、UCI 默认值、LuCI 视图
scripts/                  打包、冒烟测试、SDK 下载
docs/design.md            软件设计方案
```

## 构建与验证

所有编译与测试均在 GitHub Actions 中完成：

- `lint`：gofmt 门禁 / go vet / go test / 版本号一致性 / shell / JSON / LuCI JS 静态检查
- `wasm`：用 wasm-pack 从 `wasm/` 下的官方源码构建 WASM 客户端（版本锁定 IronRDP 0.17.0）
- `ui`：Node 22 构建前端（依赖上一步产出的 WASM 包）
- `binaries`：Go 静态交叉编译 `x86_64` 与 `aarch64_cortex-a53`，校验无 `INTERP`
- `package`：打 ipk（含 `conffiles`，升级保留 UCI 配置），并准备供 SDK 使用的预编译包
- `smoke`：解包 ipk 后真实启动服务，验证证书指纹、401/200 认证、主机与用户 CRUD、审计、静态页面；RDP 隧道（无票据拒绝、双向字节原样透传、经隧道完成端到端 TLS、浏览器 destination 被忽略并改连数据库地址、票据一次性）；文件网关鉴权（无令牌/伪造令牌拒绝、无效会话拒绝）；审计 CSV 导出全量不截断；重启后遗留会话被收尾
- `sdk`：在 ImmortalWrt SDK 中编译本包，校验产物架构

`weekly` 标签跟随每次定时构建；正式版本使用 `v*` 标签。

## 项目更名

本项目由 `airhand-openwrt` 改名而来，GitHub 仓库保留原有提交历史。原先的 Airhand 中继与网页控制台打包逻辑已被本方案取代：`docs/design.md` 中性能模式不再部署 `airhand-server` / `airhand-web`，而是在网关内实现 perfgw，并把解密移到浏览器。
