# mpc_server_demo

**English** | [中文](README_CN.md)

Demo MPC server (Party1) for the [ceres_mpc](https://github.com/SauceWu/ceres-mpc) Flutter SDK.

Implements the server side of the two-party DKLs23 ECDSA protocol using [sl-dkls23](https://github.com/silence-laboratories/dkls23), with Axum as the web framework.

## Features

- **JSON-RPC 2.0** -- Single `/rpc` endpoint handling `keygen`, `sign`, `recovery`, `export_key`
- **WebSocket** -- `/ws` endpoint with the same JSON-RPC protocol for persistent connections
- **4-Round Protocol** -- DKG (keygen), DSG (sign), key refresh (recovery), all 4-round DKLs23
- **Batch Message Optimization** -- Each round collects all protocol messages via `Notify` signal and returns them as a batch `WireEnvelope` (`payloads` array), minimizing HTTP round-trips
- **Session Management** -- Ephemeral in-memory sessions with TTL-based expiration
- **Key Export** -- Returns server keyshare for full private key reconstruction

## Architecture

```
POST /rpc  or  WS /ws
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
         ChannelRelayConn (with Notify)
                │
                ▼
         sl-dkls23 protocol task (async)
```

**Key components:**

| File | Purpose |
|------|---------|
| `main.rs` | Entry point, starts Axum server |
| `lib.rs` | JSON-RPC dispatch, protocol handlers, batch collect/inject helpers |
| `relay.rs` | `ChannelRelayConn` -- bridges sl-dkls23 Relay trait to mpsc channels with `Notify` round-complete signal |
| `types.rs` | `WireEnvelope` (with `payloads` batch field), protocol params/responses |
| `state.rs` | `AppState`, session structs (`KeygenSession`, `SignSession`, `RecoverySession`), `KeyRecord` storage |
| `rpc.rs` | JSON-RPC request/response types |
| `address.rs` | EIP-55 EVM address derivation |

## Getting Started

### Prerequisites

- Rust toolchain (stable)
- No external dependencies (in-memory storage, no database)

### Run

```bash
cargo run
```

Server starts on `http://0.0.0.0:3000` with:
- `POST /rpc` -- HTTP JSON-RPC endpoint
- `GET /ws` -- WebSocket upgrade endpoint

### Test

```bash
cargo test
```

### Configure

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level (uses `tracing-subscriber` with `env-filter`) |

## Protocol Flow

Each operation (keygen/sign/recovery) follows a 4-round pattern:

1. **Round 1 (start):** Client sends empty params (or `mpcKeyId`). Server spawns protocol task, collects first batch of messages via `Notify` signal, returns `sessionId` + batch `WireEnvelope`.
2. **Rounds 2-3 (continue):** Client sends `clientPayload` (batch `WireEnvelope`). Server decodes batch, injects all messages, collects next batch, returns batch response.
3. **Round 4 (final):** Protocol completes. Server extracts result (Keyshare / Signature), returns completion response.

### Batch WireEnvelope Format

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

When `payloads` is present, all messages for the round are in the array. The `payload` field is empty. For backward compatibility, `decode_all_payloads()` falls back to the single `payload` field when `payloads` is absent.

## JSON-RPC Methods

| Method | Description | Round 1 Params |
|--------|-------------|----------------|
| `keygen` | Two-party DKG, produces Keyshare + EVM address | `{}` |
| `sign` | Two-party DSG, produces (r, s, recid) | `{ mpcKeyId, messageHash }` |
| `recovery` | Key refresh, produces new Keyshare (same address) | `{ mpcKeyId }` |
| `export_key` | Returns server keyshare bytes | `{ mpcKeyId }` |

See the [ceres_mpc Server Integration Guide](https://github.com/SauceWu/ceres-mpc/blob/main/doc/SERVER_INTEGRATION.md) for complete request/response schemas.

## Dependencies

| Crate | Purpose |
|-------|---------|
| [axum](https://crates.io/crates/axum) 0.7 | HTTP/WebSocket framework |
| [sl-dkls23](https://crates.io/crates/sl-dkls23) 1.0.0-beta | DKLs23 protocol (keygen, sign, key refresh) |
| [sl-mpc-mate](https://crates.io/crates/sl-mpc-mate) 1.0.0-beta | MPC coordination (Relay trait) |
| [tokio](https://crates.io/crates/tokio) 1 | Async runtime |
| [k256](https://crates.io/crates/k256) 0.13 | secp256k1 elliptic curve |
| [dashmap](https://crates.io/crates/dashmap) 5 | Concurrent key storage |

## Security Notes

This is a **demo server** for development and testing. For production use:

- Add authentication (API keys, JWT, mTLS)
- Add rate limiting
- Use persistent encrypted storage for keyshares (not in-memory `DashMap`)
- Enable TLS (HTTPS)
- Add audit logging for all key operations
- Enforce MFA for `export_key`
- See the [ceres_mpc Server Integration Guide](https://github.com/SauceWu/ceres-mpc/blob/main/doc/SERVER_INTEGRATION.md) for full security requirements

## License

MIT
