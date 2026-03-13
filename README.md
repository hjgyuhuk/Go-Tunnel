# GoTunnel

轻量级内网穿透工具（纯 Go，无外部服务依赖）。

## 特性

- 控制通道：`AES-256-GCM` 消息加密（带认证）
- 数据通道：`AES-128-GCM` 分块加密（带认证，防篡改）
- 多隧道映射：一条控制连接可承载多条端口映射
- 自动重连：客户端断线后自动重试
- 生产参数：日志分级、并发上限、连接空闲超时、TCP 参数优化

## 项目结构

```text
gotunnel/
├── client/main.go
├── server/main.go
└── pkg/
    ├── crypto/crypto.go
    └── proto/proto.go
```

## 构建

```bash
# 服务端
go build -o gotunnel-server ./server

# 客户端
go build -o gotunnel-client ./client
```

## 快速开始

### 1) 启动服务端（公网）

```bash
./gotunnel-server \
  -bind 0.0.0.0 \
  -port 7000 \
  -token 'your-strong-token' \
  -log-level warn \
  -max-pending 4096 \
  -max-data-conns 2048 \
  -pending-ttl 15s \
  -idle-timeout 2m
```

### 2) 启动客户端（内网）

```bash
./gotunnel-client \
  -server <public-ip>:7000 \
  -token 'your-strong-token' \
  -log-level warn \
  -max-data-conns 512 \
  -idle-timeout 2m \
  web:localhost:5173:8081
```

隧道格式：

```text
name:host:localPort:remotePort
```

示例：

- `web:localhost:5173:8081`：公网 `:8081` -> 本机 `localhost:5173`
- `ssh:127.0.0.1:22:2222`：公网 `:2222` -> 本机 `127.0.0.1:22`

## 参数说明

### 服务端参数

- `-bind`：绑定地址，默认 `0.0.0.0`
- `-port`：控制端口，默认 `7000`
- `-token`：认证 token（用于派生会话密钥与握手 HMAC）
- `-kdf-salt`：KDF 盐（hex 字符串，客户端/服务端必须一致）
- `-auth-label`：握手 HMAC label（客户端/服务端必须一致）
- `-control-label`：控制通道加密 label（客户端/服务端必须一致）
- `-data-s2c-label`：数据通道服务端->客户端 label（客户端/服务端必须一致）
- `-data-c2s-label`：数据通道客户端->服务端 label（客户端/服务端必须一致）
- `-log-level`：日志级别，`debug|info|warn|error`，默认 `info`
- `-max-pending`：待配对外部连接上限，默认 `4096`
- `-max-data-conns`：活跃数据连接上限，默认 `2048`
- `-pending-ttl`：待配对连接超时，默认 `15s`
- `-idle-timeout`：数据连接空闲读写超时，默认 `2m`

### 客户端参数

- `-server`：服务端地址 `host:port`，默认 `127.0.0.1:7000`
- `-token`：认证 token（需与服务端一致，用于握手 HMAC）
- `-kdf-salt`：KDF 盐（hex 字符串，客户端/服务端必须一致）
- `-auth-label`：握手 HMAC label（客户端/服务端必须一致）
- `-control-label`：控制通道加密 label（客户端/服务端必须一致）
- `-data-s2c-label`：数据通道服务端->客户端 label（客户端/服务端必须一致）
- `-data-c2s-label`：数据通道客户端->服务端 label（客户端/服务端必须一致）
- `-log-level`：日志级别，`debug|info|warn|error`，默认 `info`
- `-max-data-conns`：客户端活跃数据连接上限，默认 `512`
- `-idle-timeout`：数据连接空闲读写超时，默认 `2m`

## 生产建议

- 生产环境优先使用 `-log-level warn` 或 `error`
- 必须使用高强度随机 token，避免弱口令
- 控制端口只对客户端可达（安全组/IP 白名单）
- 仅开放必要公网映射端口
- 对外暴露端口前，确认目标本地服务本身有鉴权与访问控制

## 常见问题

### `connect: connection refused`（本地服务连接失败）

通常是本地服务监听地址不匹配。例如前端开发服务可能只监听 `::1`，但你映射的是 `127.0.0.1`。

可选处理：

- 把隧道写成 `web:localhost:5173:8081`
- 或让本地服务显式监听 IPv4，例如 `--host 127.0.0.1`

## 协议概览

1. 客户端连接服务端控制端口
2. 服务端发送 `Challenge(nonce)`
3. 客户端发送 `Hello(nonce,tunnels,auth)`（控制通道加密，auth 为 HMAC）
4. 服务端回 `HelloAck(ok)`
5. 外部用户访问映射端口时，服务端发送 `NewConn(connID)`
6. 客户端建立数据连接，先读 `Challenge(nonce)`，再发送 `ConnReady(connID,nonce,auth)`
7. 双端进入 `AES-128-GCM` 分块双向转发
