# mpc_server_demo

**English** | [中文](README_CN.md)

Demo MPC server (Party1) for the [ceres_mpc](https://github.com/SauceWu/ceres-mpc) Flutter SDK.

Implements the server side of two-party MPC protocols using Axum as the web framework:

- **EVM (secp256k1)** — DKLs23 ECDSA via [sl-dkls23](https://github.com/silence-laboratories/dkls23)
- **Solana (Ed25519)** — FROST Schnorr via [frost-ed25519](https://crates.io/crates/frost-ed25519)

## Features

- **JSON-RPC 2.0** — Single `/rpc` endpoint handling `keygen`, `sign`, `recovery`, `export_key`
- **WebSocket** — `/ws` endpoint with the same JSON-RPC protocol for persistent connections
- **Dual-curve support** — Pass `curve: "ed25519"` for FROST/Solana, omit for DKLs23/EVM
- **DKLs23 (secp256k1)** — 4-round DKG, DSG, key refresh; batch `WireEnvelope` with `payloads` array
- **FROST-Ed25519 (Ed25519)** — 3-round DKG, 2-round sign coordinator, 3-round key refresh; server as `Identifier(2)`
- **Session Management** — Ephemeral in-memory sessions with TTL-based expiration
- **Key Export** — Returns server signing share; exported keys are blocked from further signing

## Architecture

```
POST /rpc  or  WS /ws
       │
       ▼
  dispatch_rpc()
       │
       ├── keygen   ──► curve="ed25519"? ──► frost_keygen_round1/2/3
       │            └──► (default)       ──► keygen_start / keygen_continue (DKLs23)
       │
       ├── sign     ──► curve="ed25519"? ──► frost_sign_round1/2
       │            └──► (default)       ──► sign_start / sign_continue (DKLs23)
       │
       ├── recovery ──► curve="ed25519"? ──► frost_recovery_round1/2/3
       │            └──► (default)       ──► recovery_start / recovery_continue (DKLs23)
       │
       └── export_key ► frost_keystore?  ──► frost_export
                     └──► (default)      ──► DKLs23 keyshare export
```

**Key components:**

| File | Purpose |
|------|---------|
| `main.rs` | Entry point, starts Axum server |
| `lib.rs` | JSON-RPC dispatch, protocol handlers, curve routing |
| `frost.rs` | FROST-Ed25519 protocol functions (keygen/sign/recovery/export) + ShareEnvelope v2 codec |
| `relay.rs` | `ChannelRelayConn` — bridges sl-dkls23 Relay trait to mpsc channels with `Notify` round-complete signal |
| `types.rs` | `WireEnvelope` (with `curve`, `payloads` batch field), protocol params/responses |
| `state.rs` | `AppState`, DKLs23 session structs, FROST session structs, key record storage |
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
- `POST /rpc` — HTTP JSON-RPC endpoint
- `GET /ws` — WebSocket upgrade endpoint

### Test

```bash
cargo test
```

### Configure

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level (`tracing-subscriber` with `env-filter`) |

## Protocol Flow

### DKLs23 / EVM (secp256k1)

Each operation follows a **4-round** pattern. Omit `curve` or set `curve: "secp256k1"`.

1. **Round 1 (start):** Client sends params. Server spawns protocol task, collects first batch via `Notify`, returns `sessionId` + batch `WireEnvelope`.
2. **Rounds 2–3 (continue):** Client sends batch `clientPayload`. Server injects all messages, collects next batch, returns response.
3. **Round 4 (final):** Protocol completes. Server returns Keyshare / Signature completion response.

### FROST / Solana (Ed25519)

Pass `curve: "ed25519"`. Server acts as `Identifier(2)`, client as `Identifier(1)`.

**Keygen (3 rounds):**
1. Client sends `round1::Package` → server returns `round1::Package`
2. Client sends `round2::Package` (addressed to server) → server returns `round2::Package` (addressed to client)
3. Client signals finalize → server calls `dkg::part3`, stores `KeyPackage`, returns `{ mpcKeyId, address (SOL base58), curve: "ed25519" }`

**Sign (2 rounds):**
1. Client sends `SigningCommitments` → server returns `SigningCommitments`
2. Client sends full `SigningPackage` (message + all commitments) → server returns `SignatureShare`; client aggregates to 64-byte Schnorr signature

**Recovery (3 rounds):** Same structure as keygen using `keys::refresh` API. Atomically replaces server `KeyPackage` on finalize. `rotation_version` increments.

**Export (1 call):** Returns `signing_share().serialize()` as hex. Marks key as exported; subsequent sign calls are rejected.

### WireEnvelope Format

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

DKLs23 responses use `payloads` array (batch). FROST responses use single `payload`. The `curve` field is omitted for DKLs23 (backward compatible).

## JSON-RPC Methods

| Method | Curve | Round 1 Params | Result |
|--------|-------|----------------|--------|
| `keygen` | — (EVM) | `{ round: 1 }` | `sessionId` + `WireEnvelope` |
| `keygen` | `ed25519` | `{ round: 1, curve: "ed25519", clientPayload: "<base64>" }` | `sessionId` + `WireEnvelope` |
| `keygen` | `ed25519` | `{ round: 3, sessionId }` | `{ mpcKeyId, address, curve }` |
| `sign` | — (EVM) | `{ round: 1, mpcKeyId, messageHash }` | `sessionId` + `WireEnvelope` |
| `sign` | `ed25519` | `{ round: 1, curve: "ed25519", mpcKeyId, messageHash, clientPayload }` | `sessionId` + `WireEnvelope` |
| `recovery` | — (EVM) | `{ round: 1, mpcKeyId }` | `sessionId` + `WireEnvelope` |
| `recovery` | `ed25519` | `{ round: 1, curve: "ed25519", mpcKeyId, clientPayload }` | `sessionId` + `WireEnvelope` |
| `export_key` | — / `ed25519` | `{ mpcKeyId }` | `{ serverSharePrivate }` |

See the [ceres_mpc Server Integration Guide](https://github.com/SauceWu/ceres-mpc/blob/main/doc/SERVER_INTEGRATION.md) for complete request/response schemas.

## Dependencies

| Crate | Purpose |
|-------|---------|
| [axum](https://crates.io/crates/axum) 0.7 | HTTP/WebSocket framework |
| [sl-dkls23](https://crates.io/crates/sl-dkls23) 1.0.0-beta | DKLs23 protocol (keygen, sign, key refresh) |
| [sl-mpc-mate](https://crates.io/crates/sl-mpc-mate) 1.0.0-beta | MPC coordination (Relay trait) |
| [frost-ed25519](https://crates.io/crates/frost-ed25519) 3 | FROST Schnorr (keygen, sign, key refresh) |
| [tokio](https://crates.io/crates/tokio) 1 | Async runtime |
| [k256](https://crates.io/crates/k256) 0.13 | secp256k1 elliptic curve |
| [dashmap](https://crates.io/crates/dashmap) 5 | Concurrent session/key storage |
| [bs58](https://crates.io/crates/bs58) 0.5 | Base58 encoding for Solana addresses |

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
