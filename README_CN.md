# mpc_server_demo

[English](README.md) | **中文**

[ceres_mpc](https://github.com/SauceWu/ceres-mpc) Flutter SDK 的 Demo MPC 服务端（Party1）。

基于 [sl-dkls23](https://github.com/silence-laboratories/dkls23) 实现两方 DKLs23 ECDSA 协议的服务端，使用 Axum 作为 Web 框架。

## 功能

- **JSON-RPC 2.0** -- 单一 `/rpc` 端点，处理 `keygen`、`sign`、`recovery`、`export_key`
- **WebSocket** -- `/ws` 端点，使用相同的 JSON-RPC 协议，支持持久连接
- **4 轮协议** -- DKG（密钥生成）、DSG（签名）、key refresh（恢复），均为 4 轮 DKLs23
- **批量消息优化** -- 每轮通过 `Notify` 信号收集所有协议消息，以批量 `WireEnvelope`（`payloads` 数组）返回，最小化 HTTP 往返
- **会话管理** -- 内存临时会话，带 TTL 超时驱逐
- **密钥导出** -- 返回服务端 keyshare，用于完整私钥重建

## 架构

```
POST /rpc  或  WS /ws
       │
       ▼
  dispatch_rpc()
       │
       ├── keygen  → keygen_start / keygen_continue
       ├── sign    → sign_start   / sign_continue
       ├── recovery→ recovery_start / recovery_continue
       └── export_key
                │
                ▼
         ChannelRelayConn（带 Notify）
                │
                ▼
         sl-dkls23 协议 task（async）
```

**核心模块：**

| 文件 | 用途 |
|------|------|
| `main.rs` | 入口，启动 Axum 服务器 |
| `lib.rs` | JSON-RPC 路由、协议 handler、批量收集/注入辅助函数 |
| `relay.rs` | `ChannelRelayConn` -- 将 sl-dkls23 Relay trait 桥接到 mpsc channel，带 `Notify` 轮次完成信号 |
| `types.rs` | `WireEnvelope`（含 `payloads` 批量字段）、协议参数/响应类型 |
| `state.rs` | `AppState`、会话结构体（`KeygenSession`、`SignSession`、`RecoverySession`）、`KeyRecord` 存储 |
| `rpc.rs` | JSON-RPC 请求/响应类型 |
| `address.rs` | EIP-55 EVM 地址派生 |

## 快速开始

### 环境要求

- Rust 工具链（stable）
- 无外部依赖（内存存储，无需数据库）

### 运行

```bash
cargo run
```

服务器启动在 `http://0.0.0.0:3000`：
- `POST /rpc` -- HTTP JSON-RPC 端点
- `GET /ws` -- WebSocket 升级端点

### 测试

```bash
cargo test
```

### 配置

环境变量：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `RUST_LOG` | `info` | 日志级别（使用 `tracing-subscriber` + `env-filter`） |

## 协议流程

每个操作（keygen/sign/recovery）遵循 4 轮模式：

1. **第 1 轮（start）：** 客户端发送空参数（或 `mpcKeyId`）。服务端启动协议 task，通过 `Notify` 信号收集首批消息，返回 `sessionId` + 批量 `WireEnvelope`。
2. **第 2-3 轮（continue）：** 客户端发送 `clientPayload`（批量 `WireEnvelope`）。服务端解码批量消息，逐条注入，收集下一批，返回批量响应。
3. **第 4 轮（final）：** 协议完成。服务端提取结果（Keyshare / 签名），返回完成响应。

### 批量 WireEnvelope 格式

```json
{
  "session_id": "hex-session-id",
  "protocol": "dkg",
  "round": 1,
  "from_id": 1,
  "to_id": 0,
  "payload_encoding": "cbor_base64",
  "payload": "",
  "payloads": ["<base64 msg1>", "<base64 msg2>", "..."]
}
```

`payloads` 存在时，该轮所有消息均在数组中，`payload` 字段为空。向后兼容：`payloads` 缺失时回退到读取单条 `payload` 字段。

## JSON-RPC 方法

| 方法 | 说明 | 第 1 轮参数 |
|------|------|-------------|
| `keygen` | 两方 DKG，产出 Keyshare + EVM 地址 | `{}` |
| `sign` | 两方 DSG，产出 (r, s, recid) | `{ mpcKeyId, messageHash }` |
| `recovery` | Key refresh，产出新 Keyshare（地址不变） | `{ mpcKeyId }` |
| `export_key` | 返回服务端 keyshare 字节 | `{ mpcKeyId }` |

完整请求/响应格式参见 [服务端集成指南](https://github.com/SauceWu/ceres-mpc/blob/main/doc/SERVER_INTEGRATION_CN.md)。

## 依赖

| Crate | 用途 |
|-------|------|
| [axum](https://crates.io/crates/axum) 0.7 | HTTP/WebSocket 框架 |
| [sl-dkls23](https://crates.io/crates/sl-dkls23) 1.0.0-beta | DKLs23 协议（keygen、sign、key refresh） |
| [sl-mpc-mate](https://crates.io/crates/sl-mpc-mate) 1.0.0-beta | MPC 协调（Relay trait） |
| [tokio](https://crates.io/crates/tokio) 1 | 异步运行时 |
| [k256](https://crates.io/crates/k256) 0.13 | secp256k1 椭圆曲线 |
| [dashmap](https://crates.io/crates/dashmap) 5 | 并发 key 存储 |

## 安全说明

这是一个用于开发和测试的 **demo 服务端**。生产环境使用请：

- 添加身份验证（API key、JWT、mTLS）
- 添加速率限制
- 使用持久化加密存储保存 keyshare（而非内存 `DashMap`）
- 启用 TLS（HTTPS）
- 添加所有密钥操作的审计日志
- `export_key` 强制 MFA
- 完整安全要求参见 [服务端集成指南](https://github.com/SauceWu/ceres-mpc/blob/main/doc/SERVER_INTEGRATION_CN.md)

## 许可证

MIT
