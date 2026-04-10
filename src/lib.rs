pub mod address;
pub mod relay;
pub mod rpc;
pub mod state;
pub mod types;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex, Notify};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use sl_dkls23::keygen::key_refresh::{self, KeyshareForRefresh};
use sl_dkls23::keygen::Keyshare;
use sl_dkls23::setup::keygen::SetupMessage as KeygenSetup;
use sl_dkls23::setup::sign::SetupMessage as SignSetup;
use sl_dkls23::setup::{NoSigningKey, NoVerifyingKey};
use sl_mpc_mate::message::InstanceId;

use crate::relay::ChannelRelayConn;
use crate::rpc::{JsonRpcRequest, JsonRpcResponse, RpcProblem};
use crate::state::{AppState, KeyRecord, KeygenSession, RecoverySession, SignSession, SESSION_TTL};
use crate::types::{
    ExportKeyParams, ExportKeyResponse, KeygenCompletedResponse, KeygenParams, ProtocolType,
    RecoveryCompletedResponse, RecoveryParams, SignCompletedResponse, SignParams, StartResponse,
    WireEnvelope,
};

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/rpc", post(rpc_handler))
        .route("/ws", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── JSON-RPC dispatch (shared by HTTP and WS) ───────────────────

async fn dispatch_rpc(state: &AppState, request: JsonRpcRequest) -> JsonRpcResponse {
    if request.jsonrpc != "2.0" {
        return JsonRpcResponse::failure(
            request.id,
            RpcProblem::new(-32600, "Invalid request: jsonrpc must be 2.0"),
        );
    }

    let method = request.method.clone();
    let id = request.id.clone();

    let outcome = match request.method.as_str() {
        "keygen" => handle_keygen(state.clone(), request.params).await,
        "sign" => handle_sign(state.clone(), request.params).await,
        "recovery" => handle_recovery(state.clone(), request.params).await,
        "export_key" => export_key(state.clone(), request.params).await,
        _ => Err(RpcProblem::new(
            -32601,
            format!("Method not found: {}", method),
        )),
    };

    match outcome {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(problem) => {
            warn!(method, code = problem.code, message = %problem.message, "rpc failed");
            JsonRpcResponse::failure(id, problem)
        }
    }
}

// ── HTTP handler ─────────────────────────────────────────────────

async fn rpc_handler(
    State(state): State<AppState>,
    Json(request): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    Json(dispatch_rpc(&state, request).await)
}

// ── WebSocket handler ────────────────────────────────────────────

async fn ws_handler(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_connection(state, socket))
}

async fn ws_connection(state: AppState, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    info!("WebSocket client connected");

    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => break,
            Ok(_) => continue, // ignore binary/ping/pong
            Err(e) => {
                warn!("WebSocket receive error: {e}");
                break;
            }
        };

        let request: JsonRpcRequest = match serde_json::from_str(&msg) {
            Ok(req) => req,
            Err(e) => {
                let error_resp = JsonRpcResponse::failure(
                    Value::Null,
                    RpcProblem::new(-32700, format!("Parse error: {e}")),
                );
                let _ = sender
                    .send(Message::Text(serde_json::to_string(&error_resp).unwrap()))
                    .await;
                continue;
            }
        };

        let response = dispatch_rpc(&state, request).await;
        let response_text = serde_json::to_string(&response).unwrap();

        if sender.send(Message::Text(response_text)).await.is_err() {
            break;
        }
    }

    info!("WebSocket client disconnected");
}

// ── Unified method handlers ──────────────────────────────────────

async fn handle_keygen(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    let params: KeygenParams = parse_params(params)?;

    if params.round == 1 {
        keygen_start(state).await
    } else {
        let session_id = params
            .session_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing sessionId for round > 1"))?;
        let client_payload = params
            .client_payload
            .ok_or_else(|| RpcProblem::new(-32600, "Missing clientPayload for round > 1"))?;
        keygen_continue(
            state,
            json!({"sessionId": session_id, "round": params.round, "clientPayload": client_payload}),
        )
        .await
    }
}

async fn handle_sign(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    let params: SignParams = parse_params(params)?;

    if params.round == 1 {
        let mpc_key_id = params
            .mpc_key_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing mpcKeyId for sign round 1"))?;
        let message_hash = params
            .message_hash
            .ok_or_else(|| RpcProblem::new(-32600, "Missing messageHash for sign round 1"))?;
        sign_start(state, json!({"mpcKeyId": mpc_key_id, "messageHash": message_hash})).await
    } else {
        let session_id = params
            .session_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing sessionId for round > 1"))?;
        let client_payload = params
            .client_payload
            .ok_or_else(|| RpcProblem::new(-32600, "Missing clientPayload for round > 1"))?;
        sign_continue(
            state,
            json!({"sessionId": session_id, "round": params.round, "clientPayload": client_payload}),
        )
        .await
    }
}

async fn handle_recovery(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    let params: RecoveryParams = parse_params(params)?;

    if params.round == 1 {
        let mpc_key_id = params
            .mpc_key_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing mpcKeyId for recovery round 1"))?;
        recovery_start(state, json!({"mpcKeyId": mpc_key_id})).await
    } else {
        let session_id = params
            .session_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing sessionId for round > 1"))?;
        let client_payload = params
            .client_payload
            .ok_or_else(|| RpcProblem::new(-32600, "Missing clientPayload for round > 1"))?;
        recovery_continue(
            state,
            json!({"sessionId": session_id, "round": params.round, "clientPayload": client_payload}),
        )
        .await
    }
}

// ── Shared helpers ───────────────────────────────────────────────

fn parse_params<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, RpcProblem> {
    serde_json::from_value(params)
        .map_err(|e| RpcProblem::new(-32600, format!("Invalid params: {e}")))
}

fn new_session_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn instance_id_from_session(session_id: &str) -> Result<InstanceId, RpcProblem> {
    let bytes = hex::decode(session_id)
        .map_err(|e| RpcProblem::new(-32600, format!("sessionId hex decode failed: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        RpcProblem::new(-32600, "sessionId must be exactly 32 bytes (64 hex chars)")
    })?;
    Ok(InstanceId::from(arr))
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

fn decode_client_envelope(
    payload_json: &str,
    expected_session: &str,
    expected_protocol: ProtocolType,
) -> Result<Vec<u8>, RpcProblem> {
    let env: WireEnvelope = serde_json::from_str(payload_json)
        .map_err(|e| RpcProblem::new(-32600, format!("invalid clientPayload JSON: {e}")))?;

    if env.session_id != expected_session {
        return Err(RpcProblem::new(
            -32600,
            "clientPayload.session_id does not match sessionId",
        ));
    }
    if env.protocol != expected_protocol {
        return Err(RpcProblem::new(
            -32600,
            "clientPayload.protocol does not match method",
        ));
    }
    if env.from_id != 0 {
        return Err(RpcProblem::new(
            -32600,
            format!("expected from_id=0, got {}", env.from_id),
        ));
    }
    // round in WireEnvelope is informational — not validated against RPC round param
    // (envelope round = message origin round, RPC round = call sequence number)

    BASE64_STANDARD
        .decode(&env.payload)
        .map_err(|e| RpcProblem::new(-32600, format!("base64 decode client payload failed: {e}")))
}

fn encode_server_envelope(
    session_id: String,
    protocol: ProtocolType,
    round: u8,
    payload: Vec<u8>,
) -> WireEnvelope {
    WireEnvelope::new(
        session_id,
        protocol,
        round,
        1,
        Some(0),
        BASE64_STANDARD.encode(payload),
    )
}

/// 异步批量收集：先 subscribe notified，再 recv 第一条，再 await notified，最后 drain。
/// 服务端运行在 tokio async 上下文中，直接 await 而非 block_on。
///
/// 关键时序安全（与客户端 16-01 collect_batch 对称）：
/// 先创建 notified() future（subscribe），再 recv() 第一条消息，
/// 再 await notified。保证 notify_one 不会在 subscribe 之前发生。
/// 批量收集协议消息。返回 (messages, protocol_done)：
/// - messages: 本轮收集到的所有消息
/// - protocol_done: true = 协议 task 已完成（channel 关闭），false = 协议在等输入
/// 返回 None 仅当协议完成且无消息产出。
async fn collect_batch_async(
    rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    round_complete: &Arc<Notify>,
) -> Option<(Vec<Vec<u8>>, bool)> {
    // Step 1: 注册 Notify 订阅
    let notified = round_complete.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();

    // Step 2: 等第一条消息
    let first = rx.recv().await?;
    let mut messages = vec![first];
    let mut protocol_done = false;

    // Step 3: 等协议 task 进入等待输入状态 OR 协议完成
    loop {
        tokio::select! {
            biased;
            _ = &mut notified => {
                break;
            }
            msg = rx.recv() => {
                match msg {
                    Some(m) => messages.push(m),
                    None => { protocol_done = true; break; }
                }
            }
        }
    }

    // Step 4: drain 剩余
    while let Ok(msg) = rx.try_recv() {
        messages.push(msg);
    }

    tracing::debug!("collect_batch_async: collected {} messages, protocol_done={}", messages.len(), protocol_done);
    Some((messages, protocol_done))
}

async fn inject_all_async(
    tx: &mpsc::Sender<Vec<u8>>,
    messages: Vec<Vec<u8>>,
) -> Result<(), RpcProblem> {
    for msg in messages {
        tx.send(msg).await
            .map_err(|e| RpcProblem::new(-32603, format!("failed to inject message: {e}")))?;
    }
    Ok(())
}

fn decode_client_envelope_batch(
    payload_json: &str,
    expected_session: &str,
    expected_protocol: ProtocolType,
) -> Result<Vec<Vec<u8>>, RpcProblem> {
    let env: WireEnvelope = serde_json::from_str(payload_json)
        .map_err(|e| RpcProblem::new(-32600, format!("invalid clientPayload JSON: {e}")))?;
    if env.session_id != expected_session {
        return Err(RpcProblem::new(-32600, "clientPayload.session_id does not match sessionId"));
    }
    if env.protocol != expected_protocol {
        return Err(RpcProblem::new(-32600, "clientPayload.protocol does not match method"));
    }
    if env.from_id != 0 {
        return Err(RpcProblem::new(-32600, format!("expected from_id=0, got {}", env.from_id)));
    }
    env.decode_all_payloads()
        .map_err(|e| RpcProblem::new(-32600, e))
}

fn encode_server_envelope_batch(
    session_id: String,
    protocol: ProtocolType,
    round: u8,
    messages: Vec<Vec<u8>>,
) -> WireEnvelope {
    let payloads: Vec<String> = messages.iter()
        .map(|m| BASE64_STANDARD.encode(m))
        .collect();
    WireEnvelope::new_batch(session_id, protocol, round, 1, Some(0), payloads)
}

fn keyshare_record(
    key_id: String,
    keyshare_bytes: Vec<u8>,
    rotation_version: i32,
) -> Result<KeyRecord, RpcProblem> {
    let keyshare = Keyshare::from_bytes(&keyshare_bytes)
        .ok_or_else(|| RpcProblem::new(-32603, "invalid keyshare bytes from protocol"))?;
    let public_key = keyshare.public_key().to_affine().to_encoded_point(false);
    let public_key_hex = hex::encode(public_key.as_bytes());
    let address = address::derive_evm_address(public_key.as_bytes())
        .map_err(|e| RpcProblem::new(-32603, e))?;

    Ok(KeyRecord {
        mpc_key_id: key_id,
        keyshare_bytes,
        address,
        public_key: public_key_hex,
        rotation_version,
        exported: false,
    })
}

// ── Legacy protocol handlers (also used by unified handlers) ─────

async fn keygen_start(state: AppState) -> Result<Value, RpcProblem> {
    let session_id = new_session_id();
    let instance = instance_id_from_session(&session_id)?;
    let verifying_keys = vec![NoVerifyingKey::new(0), NoVerifyingKey::new(1)];
    let setup = KeygenSetup::new(instance, NoSigningKey, 1, verifying_keys, &[0u8, 0u8], 2);

    let (tx_in, rx_in) = mpsc::channel::<Vec<u8>>(16);
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let (relay, round_complete) = ChannelRelayConn::new(rx_in, tx_out);
    let seed = random_seed();

    let task_handle = tokio::spawn(async move {
        sl_dkls23::keygen::dkg::run(setup, seed, relay)
            .await
            .map(|ks| ks.as_slice().to_vec())
            .map_err(|e| e.to_string())
    });

    let (batch, _done) = collect_batch_async(&mut rx_out, &round_complete)
        .await
        .ok_or_else(|| RpcProblem::new(-32603, "protocol task closed before producing round 1"))?;

    state.keygen_sessions.insert(
        session_id.clone(),
        Arc::new(KeygenSession {
            tx_in,
            rx_out: Mutex::new(rx_out),
            task_handle: Mutex::new(Some(task_handle)),
            created_at: Instant::now(),
            round_complete,
        }),
    );

    info!(
        method = "keygen",
        session_id,
        protocol = "dkg",
        "created session"
    );

    Ok(json!(StartResponse {
        session_id: session_id.clone(),
        server_payload: encode_server_envelope_batch(session_id, ProtocolType::Dkg, 1, batch),
    }))
}

async fn keygen_continue(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct P {
        session_id: String,
        round: u8,
        client_payload: String,
    }
    let params: P = parse_params(params)?;
    let session = state
        .keygen_sessions
        .get(&params.session_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| {
            RpcProblem::new(
                -32001,
                format!("Session not found or expired: {}", params.session_id),
            )
        })?;

    if session.created_at.elapsed() > SESSION_TTL {
        state.keygen_sessions.remove(&params.session_id);
        return Err(RpcProblem::new(
            -32001,
            format!("Session not found or expired: {}", params.session_id),
        ));
    }

    let client_bytes_vec = decode_client_envelope_batch(
        &params.client_payload,
        &params.session_id,
        ProtocolType::Dkg,
    )?;

    info!(method = "keygen", session_id = %params.session_id, round = params.round, client_msgs = client_bytes_vec.len(), "injecting client batch");
    inject_all_async(&session.tx_in, client_bytes_vec).await?;

    let next_batch = {
        let mut rx = session.rx_out.lock().await;
        collect_batch_async(&mut *rx, &session.round_complete).await
    };

    if let Some((server_msgs, protocol_done)) = next_batch {
        info!(method = "keygen", session_id = %params.session_id, round = params.round, server_msgs = server_msgs.len(), protocol_done, "collected server batch");

        if protocol_done {
            // 协议已完成 — 立即 join task + persist keyshare
            // 客户端可能处理完这批消息后直接 completed，不会再调服务端
            info!(method = "keygen", session_id = %params.session_id, "protocol_done=true, pre-persisting keyshare");
            if let Some(handle) = session.task_handle.lock().await.take() {
                match handle.await {
                    Ok(Ok(ks_bytes)) => {
                        match keyshare_record(params.session_id.clone(), ks_bytes, 1) {
                            Ok(record) => {
                                info!(method = "keygen", session_id = %params.session_id, address = %record.address, "keyshare persisted");
                                state.keystore.insert(record.mpc_key_id.clone(), record);
                            }
                            Err(e) => warn!(method = "keygen", session_id = %params.session_id, error = %e.message, "failed to create key record"),
                        }
                    }
                    Ok(Err(e)) => warn!(method = "keygen", session_id = %params.session_id, error = %e, "protocol error on join"),
                    Err(e) => warn!(method = "keygen", session_id = %params.session_id, error = %e, "task join error"),
                }
            }
            state.keygen_sessions.remove(&params.session_id);
        }

        // 有消息就发送 — 客户端需要这些消息来完成自己的协议
        let next_round = params.round.saturating_add(1);
        return Ok(json!(StartResponse {
            session_id: params.session_id.clone(),
            server_payload: encode_server_envelope_batch(
                params.session_id,
                ProtocolType::Dkg,
                next_round,
                server_msgs,
            ),
        }));
    }

    // 协议完成 — join task 获取 Keyshare
    info!(method = "keygen", session_id = %params.session_id, round = params.round, "protocol task completed, joining");
    let handle = session
        .task_handle
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "keygen task handle missing"))?;
    state.keygen_sessions.remove(&params.session_id);

    let keyshare_bytes = handle
        .await
        .map_err(|e| RpcProblem::new(-32603, format!("keygen task join error: {e}")))?
        .map_err(|e| RpcProblem::new(-32603, format!("keygen protocol error: {e}")))?;

    let record = keyshare_record(params.session_id.clone(), keyshare_bytes, 1)?;
    let response = KeygenCompletedResponse {
        status: "completed",
        mpc_key_id: record.mpc_key_id.clone(),
        address: record.address.clone(),
        public_key: record.public_key.clone(),
        curve: "secp256k1",
        threshold: 2,
        key_ref: record.mpc_key_id.clone(),
        backup_state: "none",
        rotation_version: record.rotation_version,
        local_encrypted_share: String::new(),
    };
    state.keystore.insert(record.mpc_key_id.clone(), record);

    Ok(json!(response))
}

async fn sign_start(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct P {
        mpc_key_id: String,
        message_hash: String,
    }
    let params: P = parse_params(params)?;

    if params.message_hash.len() != 64 {
        return Err(RpcProblem::new(
            -32600,
            "messageHash must be 64 hex chars (32 bytes)",
        ));
    }
    let digest_vec = hex::decode(&params.message_hash)
        .map_err(|e| RpcProblem::new(-32600, format!("messageHash hex decode failed: {e}")))?;
    let digest: [u8; 32] = digest_vec
        .try_into()
        .map_err(|_| RpcProblem::new(-32600, "messageHash must be exactly 32 bytes"))?;

    let key_record = state
        .keystore
        .get(&params.mpc_key_id)
        .ok_or_else(|| RpcProblem::new(-32003, format!("Key not found: {}", params.mpc_key_id)))?;
    if key_record.exported {
        return Err(RpcProblem::new(
            -32004,
            format!("Key already exported: {}", params.mpc_key_id),
        ));
    }
    let keyshare = Keyshare::from_bytes(&key_record.keyshare_bytes)
        .ok_or_else(|| RpcProblem::new(-32603, "stored keyshare is invalid"))?;
    drop(key_record);

    let session_id = new_session_id();
    let instance = instance_id_from_session(&session_id)?;
    let verifying_keys = vec![NoVerifyingKey::new(0), NoVerifyingKey::new(1)];
    let chain_path = derivation_path::DerivationPath::from_str("m")
        .map_err(|e| RpcProblem::new(-32603, format!("invalid derivation path: {e}")))?;
    let setup = SignSetup::new(
        instance,
        NoSigningKey,
        1,
        verifying_keys,
        Arc::new(keyshare),
    )
    .with_hash(digest)
    .with_chain_path(chain_path);

    let (tx_in, rx_in) = mpsc::channel::<Vec<u8>>(16);
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let (relay, round_complete) = ChannelRelayConn::new(rx_in, tx_out);
    let seed = random_seed();

    let task_handle = tokio::spawn(async move {
        sl_dkls23::sign::run(setup, seed, relay)
            .await
            .map(|(sig, recid)| {
                let (r, s) = sig.split_bytes();
                let mut bytes = r.to_vec();
                bytes.extend_from_slice(&s);
                (bytes, recid.to_byte())
            })
            .map_err(|e| e.to_string())
    });

    let (batch, _done) = collect_batch_async(&mut rx_out, &round_complete)
        .await
        .ok_or_else(|| RpcProblem::new(-32603, "sign task closed before producing round 1"))?;

    state.sign_sessions.insert(
        session_id.clone(),
        Arc::new(SignSession {
            tx_in,
            rx_out: Mutex::new(rx_out),
            task_handle: Mutex::new(Some(task_handle)),
            created_at: Instant::now(),
            round_complete,
        }),
    );

    Ok(json!(StartResponse {
        session_id: session_id.clone(),
        server_payload: encode_server_envelope_batch(session_id, ProtocolType::Dsg, 1, batch),
    }))
}

async fn sign_continue(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct P {
        session_id: String,
        round: u8,
        client_payload: String,
    }
    let params: P = parse_params(params)?;
    let session = state
        .sign_sessions
        .get(&params.session_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| {
            RpcProblem::new(
                -32001,
                format!("Session not found or expired: {}", params.session_id),
            )
        })?;

    if session.created_at.elapsed() > SESSION_TTL {
        state.sign_sessions.remove(&params.session_id);
        return Err(RpcProblem::new(
            -32001,
            format!("Session not found or expired: {}", params.session_id),
        ));
    }

    let client_bytes_vec = decode_client_envelope_batch(
        &params.client_payload,
        &params.session_id,
        ProtocolType::Dsg,
    )?;

    info!(method = "sign", session_id = %params.session_id, round = params.round, client_msgs = client_bytes_vec.len(), "injecting client batch");
    inject_all_async(&session.tx_in, client_bytes_vec).await?;

    let next_batch = {
        let mut rx = session.rx_out.lock().await;
        collect_batch_async(&mut *rx, &session.round_complete).await
    };

    if let Some((server_msgs, protocol_done)) = next_batch {
        info!(method = "sign", session_id = %params.session_id, round = params.round, server_msgs = server_msgs.len(), protocol_done, "collected server batch");

        if protocol_done {
            // sign 不需要 persist keyshare，但需要清理 session
            // 签名结果在 task join 时获取，但客户端可能不会再调一轮
            // 所以这里 join task 拿结果，但不返回 completed（消息还要发给客户端）
            info!(method = "sign", session_id = %params.session_id, "protocol_done=true, pre-joining sign task");
            // sign 的结果（r,s,recid）不需要服务端持久化，清理 session 即可
            state.sign_sessions.remove(&params.session_id);
        }

        let next_round = params.round.saturating_add(1);
        return Ok(json!(StartResponse {
            session_id: params.session_id.clone(),
            server_payload: encode_server_envelope_batch(
                params.session_id,
                ProtocolType::Dsg,
                next_round,
                server_msgs,
            ),
        }));
    }
    info!(method = "sign", session_id = %params.session_id, round = params.round, "protocol task completed, joining");

    let handle = session
        .task_handle
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "sign task handle missing"))?;
    state.sign_sessions.remove(&params.session_id);

    let (sig_bytes, recid) = handle
        .await
        .map_err(|e| RpcProblem::new(-32603, format!("sign task join error: {e}")))?
        .map_err(|e| RpcProblem::new(-32603, format!("sign protocol error: {e}")))?;

    if sig_bytes.len() != 64 {
        return Err(RpcProblem::new(
            -32603,
            format!("unexpected signature length: {}", sig_bytes.len()),
        ));
    }

    Ok(json!(SignCompletedResponse {
        status: "completed",
        r: hex::encode(&sig_bytes[..32]),
        s: hex::encode(&sig_bytes[32..]),
        recid,
    }))
}

async fn recovery_start(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct P {
        mpc_key_id: String,
    }
    let params: P = parse_params(params)?;
    let key_record = state
        .keystore
        .get(&params.mpc_key_id)
        .ok_or_else(|| RpcProblem::new(-32003, format!("Key not found: {}", params.mpc_key_id)))?;

    let keyshare = Keyshare::from_bytes(&key_record.keyshare_bytes)
        .ok_or_else(|| RpcProblem::new(-32603, "stored keyshare is invalid"))?;
    let rotation_version = key_record.rotation_version;
    drop(key_record);

    let share_for_refresh = KeyshareForRefresh::from_keyshare(&keyshare, None);

    let session_id = new_session_id();
    let instance = instance_id_from_session(&session_id)?;
    let verifying_keys = vec![NoVerifyingKey::new(0), NoVerifyingKey::new(1)];
    let setup = KeygenSetup::new(instance, NoSigningKey, 1, verifying_keys, &[0u8, 0u8], 2);

    let (tx_in, rx_in) = mpsc::channel::<Vec<u8>>(16);
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let (relay, round_complete) = ChannelRelayConn::new(rx_in, tx_out);
    let seed = random_seed();

    let task_handle = tokio::spawn(async move {
        key_refresh::run(setup, seed, relay, share_for_refresh)
            .await
            .map(|ks| ks.as_slice().to_vec())
            .map_err(|e| e.to_string())
    });

    let (batch, _done) = collect_batch_async(&mut rx_out, &round_complete)
        .await
        .ok_or_else(|| RpcProblem::new(-32603, "recovery task closed before producing round 1"))?;

    state.recovery_sessions.insert(
        session_id.clone(),
        Arc::new(RecoverySession {
            tx_in,
            rx_out: Mutex::new(rx_out),
            task_handle: Mutex::new(Some(task_handle)),
            created_at: Instant::now(),
            mpc_key_id: params.mpc_key_id,
            round_complete,
        }),
    );

    info!(
        protocol = "rotation",
        rotation_version, "started recovery session"
    );

    Ok(json!(StartResponse {
        session_id: session_id.clone(),
        server_payload: encode_server_envelope_batch(
            session_id,
            ProtocolType::Rotation,
            1,
            batch,
        ),
    }))
}

async fn recovery_continue(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct P {
        session_id: String,
        round: u8,
        client_payload: String,
    }
    let params: P = parse_params(params)?;
    let session = state
        .recovery_sessions
        .get(&params.session_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| {
            RpcProblem::new(
                -32001,
                format!("Session not found or expired: {}", params.session_id),
            )
        })?;

    if session.created_at.elapsed() > SESSION_TTL {
        state.recovery_sessions.remove(&params.session_id);
        return Err(RpcProblem::new(
            -32001,
            format!("Session not found or expired: {}", params.session_id),
        ));
    }

    let client_bytes_vec = decode_client_envelope_batch(
        &params.client_payload,
        &params.session_id,
        ProtocolType::Rotation,
    )?;

    info!(method = "recovery", session_id = %params.session_id, round = params.round, client_msgs = client_bytes_vec.len(), "injecting client batch");
    inject_all_async(&session.tx_in, client_bytes_vec).await?;

    let next_batch = {
        let mut rx = session.rx_out.lock().await;
        collect_batch_async(&mut *rx, &session.round_complete).await
    };

    if let Some((server_msgs, protocol_done)) = next_batch {
        info!(method = "recovery", session_id = %params.session_id, round = params.round, server_msgs = server_msgs.len(), protocol_done, "collected server batch");

        if protocol_done {
            // 协议已完成 — 立即 join task + persist 新 keyshare
            info!(method = "recovery", session_id = %params.session_id, "protocol_done=true, pre-persisting keyshare");
            if let Some(handle) = session.task_handle.lock().await.take() {
                match handle.await {
                    Ok(Ok(ks_bytes)) => {
                        let old_rotation = state
                            .keystore
                            .get(&session.mpc_key_id)
                            .map(|record| record.rotation_version)
                            .unwrap_or(0);
                        match keyshare_record(session.mpc_key_id.clone(), ks_bytes, old_rotation + 1) {
                            Ok(record) => {
                                info!(method = "recovery", session_id = %params.session_id, address = %record.address, rv = record.rotation_version, "keyshare persisted");
                                state.keystore.insert(record.mpc_key_id.clone(), record);
                            }
                            Err(e) => warn!(method = "recovery", session_id = %params.session_id, error = %e.message, "failed to create key record"),
                        }
                    }
                    Ok(Err(e)) => warn!(method = "recovery", session_id = %params.session_id, error = %e, "protocol error on join"),
                    Err(e) => warn!(method = "recovery", session_id = %params.session_id, error = %e, "task join error"),
                }
            }
            state.recovery_sessions.remove(&params.session_id);
        }

        let next_round = params.round.saturating_add(1);
        return Ok(json!(StartResponse {
            session_id: params.session_id.clone(),
            server_payload: encode_server_envelope_batch(
                params.session_id,
                ProtocolType::Rotation,
                next_round,
                server_msgs,
            ),
        }));
    }

    // collect_batch 返回 None — 协议完成且无消息
    info!(method = "recovery", session_id = %params.session_id, round = params.round, "protocol task completed (no final msgs), joining");
    let handle = session
        .task_handle
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "recovery task handle missing"))?;
    state.recovery_sessions.remove(&params.session_id);

    let keyshare_bytes = handle
        .await
        .map_err(|e| RpcProblem::new(-32603, format!("recovery task join error: {e}")))?
        .map_err(|e| RpcProblem::new(-32603, format!("recovery protocol error: {e}")))?;

    let old_rotation = state
        .keystore
        .get(&session.mpc_key_id)
        .map(|record| record.rotation_version)
        .ok_or_else(|| RpcProblem::new(-32003, format!("Key not found: {}", session.mpc_key_id)))?;
    let record = keyshare_record(session.mpc_key_id.clone(), keyshare_bytes, old_rotation + 1)?;

    let response = RecoveryCompletedResponse {
        status: "completed",
        mpc_key_id: record.mpc_key_id.clone(),
        address: record.address.clone(),
        public_key: record.public_key.clone(),
        rotation_version: record.rotation_version,
        local_encrypted_share: String::new(),
    };
    state.keystore.insert(record.mpc_key_id.clone(), record);

    Ok(json!(response))
}

async fn export_key(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    let params: ExportKeyParams = parse_params(params)?;
    let mut key_record = state
        .keystore
        .get_mut(&params.mpc_key_id)
        .ok_or_else(|| RpcProblem::new(-32003, format!("Key not found: {}", params.mpc_key_id)))?;

    let response = ExportKeyResponse {
        server_share_private: BASE64_STANDARD.encode(&key_record.keyshare_bytes),
    };
    key_record.exported = true;

    Ok(json!(response))
}

pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,mpc_server_demo=debug".into()),
        )
        .init();

    let state = AppState::new();
    state.spawn_cleanup_task();
    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("MPC server listening on http://0.0.0.0:3000");
    info!("  HTTP JSON-RPC: POST /rpc");
    info!("  WebSocket:     GET  /ws");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn rpc_unknown_method_returns_jsonrpc_error() {
        let state = AppState::new();
        let app = build_app(state);

        let request = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "jsonrpc": "2.0",
                    "method": "unknown",
                    "params": {},
                    "id": 1
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn wire_envelope_serializes_expected_fields() {
        let env = encode_server_envelope("abcd".to_string(), ProtocolType::Dkg, 1, vec![1, 2, 3]);
        let value = serde_json::to_value(env).unwrap();
        assert_eq!(value["payload_encoding"], "cbor_base64");
        assert_eq!(value["from_id"], 1);
        assert_eq!(value["to_id"], 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unified_keygen_round1_creates_session() {
        let state = AppState::new();
        let app = build_app(state);

        let request = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "jsonrpc": "2.0",
                    "method": "keygen",
                    "params": {"round": 1},
                    "id": 1
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        // Should have result with sessionId and serverPayload
        assert!(json["result"]["sessionId"].is_string());
        assert!(json["result"]["serverPayload"]["payload"].is_string());
    }

    #[tokio::test]
    async fn ws_route_exists() {
        let state = AppState::new();
        let app = build_app(state);

        // GET /ws without upgrade header returns 400-level (upgrade required)
        let request = Request::builder()
            .method("GET")
            .uri("/ws")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Without WebSocket upgrade headers, axum returns an error status
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }
}
