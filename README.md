# deskgw

OpenWrt Web 远程桌面网关。单一 Go 静态二进制，在路由器上提供 HTTPS 管理界面、多用户与主机授权、审计日志；远程桌面通道按里程碑逐步接入。

设计方案见 [`docs/design.md`](docs/design.md)。

## 当前实现范围（M2）

| 模块 | 状态 |
|---|---|
| HTTPS 服务、自签证书与指纹 | 已实现 |
| 登录、argon2id 密码哈希、服务端 Session、CSRF、失败锁定 | 已实现 |
| Web 用户增删改查、角色（admin / user）、主机授权 | 已实现 |
| 主机增删改查、私网地址校验（防 SSRF） | 已实现 |
| SQLite 持久化与 schema 迁移 | 已实现 |
| 审计日志、系统设置、Vue 3 管理前端 | 已实现 |
| RDP 隧道（RDCleanPath 网关 + 浏览器 NLA） | 已实现 |
| 在线会话列表与强制断开 | 已实现 |
| SMB 文件面板、多标签会话 | M4 / M3 |
| 性能模式（perfgw、浏览器端解密） | M7 准入验证后实施 |

RDP 连接流程：在主机列表点击「连接（RDP）」→ 输入 Windows 账号密码 → 浏览器内 WASM 完成 NLA，网关只负责转发。Windows 凭据不保存、不经过网关；每次连接签发的票据一次性有效并绑定来源 IP；连接目标一律取数据库中的私网地址，浏览器传入的地址会被忽略。

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
2. 首次启动生成自签证书与初始管理员 `admin`，随机密码同时写入 syslog 和 `/etc/deskgw/initial-password.txt`。
3. 浏览器访问 `https://<路由器地址>:8443`，登录后可在「管理」中修改密码、添加主机与用户。
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
```

## 目录结构

```
cmd/deskgw/               入口：TLS、证书生成、初始管理员、优雅退出
internal/
  auth/                   argon2id、Session、CSRF、登录限流
  user/ host/             用户、主机、授权
  store/                  SQLite 连接与 schema 迁移
  api/                    REST 路由与中间件
  tunnel/                 RDP 隧道：一次性票据、RDCleanPath DER、WS↔TLS 转发
  audit/                  审计日志
  config/                 环境变量配置
web/                      Vue 3 前端（含 ironrdp-wasm），构建产物由 Go embed 托管
openwrt/                  包 Makefile、procd 脚本、UCI 默认值、LuCI 视图
scripts/                  打包、冒烟测试、SDK 下载
docs/design.md            软件设计方案
```

## 构建与验证

所有编译与测试均在 GitHub Actions 中完成：

- `lint`：gofmt / go vet / shell / JSON / LuCI JS 静态检查
- `ui`：Node 22 构建前端
- `binaries`：Go 静态交叉编译 `x86_64` 与 `aarch64_cortex-a53`，校验无 `INTERP`
- `package`：打 ipk，并准备供 SDK 使用的预编译包
- `smoke`：解包 ipk 后真实启动服务，验证证书指纹、401/200 认证、主机与用户 CRUD、审计、静态页面，以及 RDP 隧道（无票据拒绝、票据一次性、浏览器 destination 被忽略并改连数据库地址）
- `sdk`：在 ImmortalWrt SDK 中编译本包，校验产物架构

`weekly` 标签跟随每次定时构建；正式版本使用 `v*` 标签。

## 项目更名

本项目由 `airhand-openwrt` 改名而来，GitHub 仓库保留原有提交历史。原先的 Airhand 中继与网页控制台打包逻辑已被本方案取代：`docs/design.md` 中性能模式不再部署 `airhand-server` / `airhand-web`，而是在网关内实现 perfgw，并把解密移到浏览器。
