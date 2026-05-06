# mpc_server_demo

[English](README.md) | **中文**

[ceres_mpc](https://github.com/SauceWu/ceres-mpc) Flutter SDK 的 Demo MPC 服务端（Party1）。

基于 Axum 实现两方 MPC 协议服务端：

- **EVM（secp256k1）** — 基于 [sl-dkls23](https://github.com/silence-laboratories/dkls23) 的 DKLs23 ECDSA
- **Solana（Ed25519）** — 基于 [frost-ed25519](https://crates.io/crates/frost-ed25519) 的 FROST Schnorr

## 功能

- **JSON-RPC 2.0** — 单一 `/rpc` 端点，处理 `keygen`、`sign`、`recovery`、`export_key`
- **WebSocket** — `/ws` 端点，使用相同的 JSON-RPC 协议，支持持久连接
- **双曲线支持** — 传入 `curve: "ed25519"` 走 FROST/Solana 路径，不传走 DKLs23/EVM 路径
- **DKLs23（secp256k1）** — 4 轮 DKG、DSG、key refresh；批量 `WireEnvelope`（`payloads` 数组）
- **FROST-Ed25519（Ed25519）** — 3 轮 DKG、2 轮签名协调、3 轮 key refresh；服务端为 `Identifier(2)`
- **会话管理** — 内存临时会话，带 TTL 超时驱逐
- **密钥导出** — 返回服务端签名份额；已导出的密钥将拒绝后续签名请求

## 架构

```
POST /rpc  或  WS /ws
       │
       ▼
  dispatch_rpc()
       │
       ├── keygen   ──► curve="ed25519"? ──► frost_keygen_round1/2/3
       │            └──► （默认）         ──► keygen_start / keygen_continue (DKLs23)
       │
       ├── sign     ──► curve="ed25519"? ──► frost_sign_round1/2
       │            └──► （默认）         ──► sign_start / sign_continue (DKLs23)
       │
       ├── recovery ──► curve="ed25519"? ──► frost_recovery_round1/2/3
       │            └──► （默认）         ──► recovery_start / recovery_continue (DKLs23)
       │
       └── export_key ► frost_keystore?  ──► frost_export
                     └──► （默认）        ──► DKLs23 keyshare 导出
```

**核心模块：**

| 文件 | 用途 |
|------|------|
| `main.rs` | 入口，启动 Axum 服务器 |
| `lib.rs` | JSON-RPC 路由、协议 handler、曲线分发 |
| `frost.rs` | FROST-Ed25519 会话编排 — 所有密码学委托给 `ceres_wallet_frost_mpc` |
| `relay.rs` | `ChannelRelayConn` — 将 sl-dkls23 Relay trait 桥接到 mpsc channel，带 `Notify` 轮次完成信号 |
| `types.rs` | `WireEnvelope`（含 `curve`、`payloads` 批量字段）、协议参数/响应类型 |
| `state.rs` | `AppState`、DKLs23 会话结构体、FROST 会话结构体、密钥记录存储 |
| `rpc.rs` | JSON-RPC 请求/响应类型 |
| `address.rs` | EIP-55 EVM 地址派生 |

## 快速开始

### 环境要求

- Rust 工具链（stable）
- 无外部依赖（内存存储，无需数据库）

### 运行

```bash
# 开发模式
cargo run

# 生产 / 性能优先（推荐 — 密码学运算快 20-50x）
cargo run --release
```

服务器启动在 `http://0.0.0.0:3000`：
- `POST /rpc` — HTTP JSON-RPC 端点
- `GET /ws` — WebSocket 升级端点

### 测试

```bash
cargo test
```

### 配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `RUST_LOG` | `info` | 日志级别（使用 `tracing-subscriber` + `env-filter`） |

## 协议流程

### DKLs23 / EVM（secp256k1）

每个操作遵循 **4 轮**模式。不传 `curve` 或传 `curve: "secp256k1"`。

1. **第 1 轮（start）：** 客户端发送参数。服务端启动协议 task，通过 `Notify` 信号收集首批消息，返回 `sessionId` + 批量 `WireEnvelope`。
2. **第 2–3 轮（continue）：** 客户端发送批量 `clientPayload`。服务端解码并逐条注入，收集下一批，返回响应。
3. **第 4 轮（final）：** 协议完成，服务端返回 Keyshare / 签名完成响应。

### FROST / Solana（Ed25519）

传入 `curve: "ed25519"`。服务端为 `Identifier(2)`，客户端为 `Identifier(1)`。

**Keygen（3 轮）：**
1. 客户端发送 `round1::Package` → 服务端返回 `round1::Package`
2. 客户端发送 `round2::Package`（寻址至服务端）→ 服务端返回 `round2::Package`（寻址至客户端）
3. 客户端发送 finalize 信号 → 服务端调用 `dkg::part3`，存储 `KeyPackage`，返回 `{ mpcKeyId, address（SOL base58）, curve: "ed25519" }`

**Sign（2 轮）：**
1. 客户端发送 `SigningCommitments` → 服务端返回 `SigningCommitments`
2. 客户端发送完整 `SigningPackage`（消息 + 所有承诺）→ 服务端返回 `SignatureShare`；客户端聚合为 64 字节 Schnorr 签名

**Recovery（3 轮）：** 结构同 keygen，使用 `keys::refresh` API。finalize 时原子替换服务端 `KeyPackage`，`rotation_version` 自增。

**Export（单次调用）：** 返回 `ShareEnvelope v2` — `base64(json({ v:2, curve:"ed25519", share: base64(json({kp, pkp})) }))`。标记密钥为已导出，后续签名请求将被拒绝。

### WireEnvelope 格式

```json
{
  "session_id": "hex-session-id",
  "protocol": "dkg",
  "round": 1,
  "from_id": 1,
  "to_id": 0,
  "payload_encoding": "cbor_base64",
  "payload": "<base64>",
  "curve": "ed25519"
}
```

DKLs23 响应使用 `payloads` 数组（批量）。FROST 响应使用单条 `payload`。DKLs23 不携带 `curve` 字段（向后兼容）。

## JSON-RPC 方法

| 方法 | 曲线 | 第 1 轮参数 | 返回 |
|------|------|------------|------|
| `keygen` | — (EVM) | `{ round: 1 }` | `sessionId` + `WireEnvelope` |
| `keygen` | `ed25519` | `{ round: 1, curve: "ed25519", clientPayload: "<base64>" }` | `sessionId` + `WireEnvelope` |
| `keygen` | `ed25519` | `{ round: 3, sessionId }` | `{ mpcKeyId, address, curve }` |
| `sign` | — (EVM) | `{ round: 1, mpcKeyId, messageHash }` | `sessionId` + `WireEnvelope` |
| `sign` | `ed25519` | `{ round: 1, curve: "ed25519", mpcKeyId, messageHash, clientPayload }` | `sessionId` + `WireEnvelope` |
| `recovery` | — (EVM) | `{ round: 1, mpcKeyId }` | `sessionId` + `WireEnvelope` |
| `recovery` | `ed25519` | `{ round: 1, curve: "ed25519", mpcKeyId, clientPayload }` | `sessionId` + `WireEnvelope` |
| `export_key` | — / `ed25519` | `{ mpcKeyId }` | `{ serverSharePrivate }` |

完整请求/响应格式参见 [服务端集成指南](https://github.com/SauceWu/ceres-mpc/blob/main/doc/SERVER_INTEGRATION_CN.md)。

## 依赖

| Crate | 用途 |
|-------|------|
| [axum](https://crates.io/crates/axum) 0.7 | HTTP/WebSocket 框架 |
| [sl-dkls23](https://crates.io/crates/sl-dkls23) 1.0.0-beta | DKLs23 协议（keygen、sign、key refresh） |
| [sl-mpc-mate](https://crates.io/crates/sl-mpc-mate) 1.0.0-beta | MPC 协调（Relay trait） |
| [frost-ed25519](https://crates.io/crates/frost-ed25519) 3 | FROST Schnorr（keygen、sign、key refresh） |
| [ceres_wallet_frost_mpc](https://github.com/SauceWu/ceres_wallet_frost_mpc) | FROST-Ed25519 2-of-2 密码学库 — keygen/sign/recovery/export/backup |
| [tokio](https://crates.io/crates/tokio) 1 | 异步运行时 |
| [k256](https://crates.io/crates/k256) 0.13 | secp256k1 椭圆曲线 |
| [dashmap](https://crates.io/crates/dashmap) 5 | 并发会话/密钥存储 |
| [bs58](https://crates.io/crates/bs58) 0.5 | Base58 编码（Solana 地址派生） |

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
