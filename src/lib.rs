pub mod address;
pub mod frost;
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
        "keygen"     => handle_keygen(state.clone(), request.params).await,
        "sign"       => handle_sign(state.clone(), request.params).await,
        "recovery"   => handle_recovery(state.clone(), request.params).await,
        "export_key" => export_key(state.clone(), request.params).await,
        _            => Err(RpcProblem::new(-32601, format!("Method not found: {method}"))),
    };
    match outcome {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(problem) => {
            warn!(method, code = problem.code, message = %problem.message, "rpc failed");
            JsonRpcResponse::failure(id, problem)
        }
    }
}

async fn rpc_handler(
    State(state): State<AppState>,
    Json(request): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    Json(dispatch_rpc(&state, request).await)
}

async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_connection(state, socket))
}

async fn ws_connection(state: AppState, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    info!("WebSocket client connected");
    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(e) => { warn!("WebSocket receive error: {e}"); break; }
        };
        let request: JsonRpcRequest = match serde_json::from_str(&msg) {
            Ok(req) => req,
            Err(e) => {
                let err = JsonRpcResponse::failure(
                    Value::Null,
                    RpcProblem::new(-32700, format!("Parse error: {e}")),
                );
                let _ = sender.send(Message::Text(serde_json::to_string(&err).unwrap())).await;
                continue;
            }
        };
        let response = serde_json::to_string(&dispatch_rpc(&state, request).await).unwrap();
        if sender.send(Message::Text(response)).await.is_err() {
            break;
        }
    }
    info!("WebSocket client disconnected");
}

async fn handle_keygen(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    let params: KeygenParams = parse_params(params)?;

    let is_frost = params.curve.as_deref() == Some("ed25519")
        || params.session_id.as_ref()
            .map_or(false, |sid| state.frost_keygen_sessions.contains_key(sid.as_str()));

    if is_frost {
        let session_id = params.session_id.unwrap_or_default();
        let client_payload = params.client_payload.unwrap_or_default();
        return match params.round {
            1 => {
                let (session_id, envelope) = frost::frost_keygen_round1(&state).await?;
                Ok(json!(StartResponse { session_id, server_payload: envelope }))
            }
            2 => {
                let envelope =
                    frost::frost_keygen_round2(&session_id, &client_payload, &state).await?;
                Ok(json!(StartResponse { session_id, server_payload: envelope }))
            }
            3 => {
                let (mpc_key_id, address, public_key) =
                    frost::frost_keygen_round3(&session_id, &client_payload, &state).await?;
                Ok(json!(KeygenCompletedResponse {
                    status: "completed",
                    mpc_key_id: mpc_key_id.clone(),
                    address,
                    public_key,
                    curve: "ed25519",
                    threshold: 2,
                    key_ref: mpc_key_id,
                    backup_state: "none",
                    rotation_version: 1,
                    local_encrypted_share: String::new(),
                }))
            }
            r => Err(RpcProblem::new(-32600, format!("Unsupported FROST keygen round: {r}"))),
        };
    }

    if params.round == 1 {
        keygen_start(state).await
    } else {
        let session_id = params.session_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing sessionId"))?;
        let client_payload = params.client_payload
            .ok_or_else(|| RpcProblem::new(-32600, "Missing clientPayload"))?;
        keygen_continue(state, session_id, params.round, client_payload).await
    }
}

async fn handle_sign(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    let params: SignParams = parse_params(params)?;

    let is_frost_r1 = params.round == 1
        && params.mpc_key_id.as_ref()
            .map_or(false, |id| state.frost_keystore.contains_key(id.as_str()));
    let is_frost_r2 = params.round > 1
        && params.session_id.as_ref()
            .map_or(false, |sid| state.frost_sign_sessions.contains_key(sid.as_str()));

    if is_frost_r1 {
        let mpc_key_id = params.mpc_key_id.unwrap();
        let message_hash = params.message_hash
            .ok_or_else(|| RpcProblem::new(-32600, "Missing messageHash"))?;
        let (session_id, envelope) =
            frost::frost_sign_round1(&mpc_key_id, &message_hash, &state).await?;
        return Ok(json!(StartResponse { session_id, server_payload: envelope }));
    }
    if is_frost_r2 {
        let session_id = params.session_id.as_ref().unwrap();
        let client_payload = params.client_payload
            .ok_or_else(|| RpcProblem::new(-32600, "Missing clientPayload"))?;
        let envelope = frost::frost_sign_round2(session_id, &client_payload, &state).await?;
        return Ok(json!(StartResponse { session_id: session_id.clone(), server_payload: envelope }));
    }

    if params.round == 1 {
        let mpc_key_id = params.mpc_key_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing mpcKeyId"))?;
        let message_hash = params.message_hash
            .ok_or_else(|| RpcProblem::new(-32600, "Missing messageHash"))?;
        sign_start(state, mpc_key_id, message_hash).await
    } else {
        let session_id = params.session_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing sessionId"))?;
        let client_payload = params.client_payload
            .ok_or_else(|| RpcProblem::new(-32600, "Missing clientPayload"))?;
        sign_continue(state, session_id, params.round, client_payload).await
    }
}

async fn handle_recovery(state: AppState, params: Value) -> Result<Value, RpcProblem> {
    let params: RecoveryParams = parse_params(params)?;

    let is_frost_r1 = params.round == 1
        && params.mpc_key_id.as_ref()
            .map_or(false, |id| state.frost_keystore.contains_key(id.as_str()));
    let is_frost_rn = params.round > 1
        && params.session_id.as_ref()
            .map_or(false, |sid| state.frost_recovery_sessions.contains_key(sid.as_str()));

    if is_frost_r1 {
        let mpc_key_id = params.mpc_key_id.unwrap();
        let client_ver = params.current_rotation_version
            .ok_or_else(|| RpcProblem::new(-32600, "Missing currentRotationVersion"))?;
        let server_ver = state.frost_keystore.get(&mpc_key_id)
            .map(|r| r.rotation_version)
            .unwrap_or(0);
        if client_ver != server_ver {
            return Err(RpcProblem::new(
                -32600,
                format!("rotation_version mismatch: expected {server_ver}, got {client_ver}"),
            ));
        }
        let (session_id, envelope) = frost::frost_recovery_round1(&mpc_key_id, &state).await?;
        return Ok(json!(StartResponse { session_id, server_payload: envelope }));
    }
    if is_frost_rn {
        let session_id = params.session_id.as_ref().unwrap().clone();
        let client_payload = params.client_payload
            .ok_or_else(|| RpcProblem::new(-32600, "Missing clientPayload"))?;
        return match params.round {
            2 => {
                let envelope =
                    frost::frost_recovery_round2(&session_id, &client_payload, &state).await?;
                Ok(json!(StartResponse { session_id, server_payload: envelope }))
            }
            3 => {
                let (mpc_key_id, address, rotation_version) =
                    frost::frost_recovery_round3(&session_id, &client_payload, &state).await?;
                let public_key = state.frost_keystore.get(&mpc_key_id)
                    .and_then(|r| r.public_key_package.verifying_key().serialize()
                        .map(|b| hex::encode(b.as_ref() as &[u8])).ok())
                    .unwrap_or_default();
                Ok(json!(RecoveryCompletedResponse {
                    status: "completed",
                    mpc_key_id,
                    address,
                    public_key,
                    rotation_version,
                    local_encrypted_share: String::new(),
                }))
            }
            r => Err(RpcProblem::new(-32600, format!("Unsupported FROST recovery round: {r}"))),
        };
    }

    if params.round == 1 {
        let mpc_key_id = params.mpc_key_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing mpcKeyId"))?;
        recovery_start(state, mpc_key_id).await
    } else {
        let session_id = params.session_id
            .ok_or_else(|| RpcProblem::new(-32600, "Missing sessionId"))?;
        let client_payload = params.client_payload
            .ok_or_else(|| RpcProblem::new(-32600, "Missing clientPayload"))?;
        recovery_continue(state, session_id, params.round, client_payload).await
    }
}

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
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RpcProblem::new(-32600, "sessionId must be exactly 32 bytes (64 hex chars)"))?;
    Ok(InstanceId::from(arr))
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

#[cfg(test)]
fn encode_server_envelope(
    session_id: String,
    protocol: ProtocolType,
    round: u8,
    payload: Vec<u8>,
) -> WireEnvelope {
    WireEnvelope::new(session_id, protocol, round, 1, Some(0), BASE64_STANDARD.encode(payload))
}

// subscribe before first recv so a notify fired between spawn and collect is not missed
async fn collect_batch_async(
    rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    round_complete: &Arc<Notify>,
) -> Option<(Vec<Vec<u8>>, bool)> {
    let notified = round_complete.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();

    let first = rx.recv().await?;
    let mut messages = vec![first];
    let mut protocol_done = false;

    loop {
        tokio::select! {
            biased;
            _ = &mut notified => break,
            msg = rx.recv() => match msg {
                Some(m) => messages.push(m),
                None => { protocol_done = true; break; }
            }
        }
    }
    while let Ok(msg) = rx.try_recv() {
        messages.push(msg);
    }
    Some((messages, protocol_done))
}

async fn inject_all_async(tx: &mpsc::Sender<Vec<u8>>, messages: Vec<Vec<u8>>) -> Result<(), RpcProblem> {
    for msg in messages {
        tx.send(msg).await
            .map_err(|e| RpcProblem::new(-32603, format!("inject message: {e}")))?;
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
    env.decode_all_payloads().map_err(|e| RpcProblem::new(-32600, e))
}

fn encode_server_envelope_batch(
    session_id: String,
    protocol: ProtocolType,
    round: u8,
    messages: Vec<Vec<u8>>,
) -> WireEnvelope {
    let payloads = messages.iter().map(|m| BASE64_STANDARD.encode(m)).collect();
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
    let address = address::derive_evm_address(public_key.as_bytes())
        .map_err(|e| RpcProblem::new(-32603, e))?;
    Ok(KeyRecord {
        mpc_key_id: key_id,
        keyshare_bytes,
        address,
        public_key: hex::encode(public_key.as_bytes()),
        rotation_version,
        exported: false,
    })
}

async fn keygen_start(state: AppState) -> Result<Value, RpcProblem> {
    let session_id = new_session_id();
    let instance = instance_id_from_session(&session_id)?;
    let setup = KeygenSetup::new(
        instance, NoSigningKey, 1,
        vec![NoVerifyingKey::new(0), NoVerifyingKey::new(1)],
        &[0u8, 0u8], 2,
    );
    let (tx_in, rx_in) = mpsc::channel::<Vec<u8>>(16);
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let (relay, round_complete) = ChannelRelayConn::new(rx_in, tx_out);

    let task_handle = tokio::spawn(async move {
        sl_dkls23::keygen::dkg::run(setup, random_seed(), relay)
            .await
            .map(|ks| ks.as_slice().to_vec())
            .map_err(|e| e.to_string())
    });

    let (batch, _) = collect_batch_async(&mut rx_out, &round_complete)
        .await
        .ok_or_else(|| RpcProblem::new(-32603, "keygen task closed before round 1"))?;

    info!(session_id, "keygen session created");
    state.keygen_sessions.insert(session_id.clone(), Arc::new(KeygenSession {
        tx_in,
        rx_out: Mutex::new(rx_out),
        task_handle: Mutex::new(Some(task_handle)),
        created_at: Instant::now(),
        round_complete,
    }));
    Ok(json!(StartResponse {
        session_id: session_id.clone(),
        server_payload: encode_server_envelope_batch(session_id, ProtocolType::Dkg, 1, batch),
    }))
}

async fn keygen_continue(
    state: AppState,
    session_id: String,
    round: u8,
    client_payload: String,
) -> Result<Value, RpcProblem> {
    let session = state.keygen_sessions.get(&session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| RpcProblem::new(-32001, format!("session not found: {session_id}")))?;
    if session.created_at.elapsed() > SESSION_TTL {
        state.keygen_sessions.remove(&session_id);
        return Err(RpcProblem::new(-32001, format!("session expired: {session_id}")));
    }

    let client_msgs = decode_client_envelope_batch(&client_payload, &session_id, ProtocolType::Dkg)?;
    inject_all_async(&session.tx_in, client_msgs).await?;

    let next_batch = {
        let mut rx = session.rx_out.lock().await;
        collect_batch_async(&mut *rx, &session.round_complete).await
    };

    if let Some((server_msgs, done)) = next_batch {
        if done {
            if let Some(handle) = session.task_handle.lock().await.take() {
                match handle.await {
                    Ok(Ok(ks_bytes)) => match keyshare_record(session_id.clone(), ks_bytes, 1) {
                        Ok(record) => {
                            info!(session_id, address = %record.address, "keyshare persisted");
                            state.keystore.insert(record.mpc_key_id.clone(), record);
                        }
                        Err(e) => warn!(session_id, error = %e.message, "keyshare record failed"),
                    },
                    Ok(Err(e)) => warn!(session_id, error = %e, "protocol error"),
                    Err(e)     => warn!(session_id, error = %e, "task join error"),
                }
            }
            state.keygen_sessions.remove(&session_id);
        }
        return Ok(json!(StartResponse {
            session_id: session_id.clone(),
            server_payload: encode_server_envelope_batch(
                session_id, ProtocolType::Dkg, round.saturating_add(1), server_msgs,
            ),
        }));
    }

    let handle = session.task_handle.lock().await.take()
        .ok_or_else(|| RpcProblem::new(-32603, "keygen task handle missing"))?;
    state.keygen_sessions.remove(&session_id);

    let ks_bytes = handle.await
        .map_err(|e| RpcProblem::new(-32603, format!("task join: {e}")))?
        .map_err(|e| RpcProblem::new(-32603, format!("protocol: {e}")))?;
    let record = keyshare_record(session_id.clone(), ks_bytes, 1)?;
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

async fn sign_start(state: AppState, mpc_key_id: String, message_hash: String) -> Result<Value, RpcProblem> {
    if message_hash.len() != 64 {
        return Err(RpcProblem::new(-32600, "messageHash must be 64 hex chars (32 bytes)"));
    }
    let digest: [u8; 32] = hex::decode(&message_hash)
        .map_err(|e| RpcProblem::new(-32600, format!("messageHash hex decode: {e}")))?
        .try_into()
        .map_err(|_| RpcProblem::new(-32600, "messageHash must be exactly 32 bytes"))?;

    let key_record = state.keystore.get(&mpc_key_id)
        .ok_or_else(|| RpcProblem::new(-32003, format!("Key not found: {mpc_key_id}")))?;
    if key_record.exported {
        return Err(RpcProblem::new(-32004, format!("Key already exported: {mpc_key_id}")));
    }
    let keyshare = Keyshare::from_bytes(&key_record.keyshare_bytes)
        .ok_or_else(|| RpcProblem::new(-32603, "stored keyshare is invalid"))?;
    drop(key_record);

    let session_id = new_session_id();
    let instance = instance_id_from_session(&session_id)?;
    let chain_path = derivation_path::DerivationPath::from_str("m")
        .map_err(|e| RpcProblem::new(-32603, format!("derivation path: {e}")))?;
    let setup = SignSetup::new(
        instance, NoSigningKey, 1,
        vec![NoVerifyingKey::new(0), NoVerifyingKey::new(1)],
        Arc::new(keyshare),
    )
    .with_hash(digest)
    .with_chain_path(chain_path);

    let (tx_in, rx_in) = mpsc::channel::<Vec<u8>>(16);
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let (relay, round_complete) = ChannelRelayConn::new(rx_in, tx_out);

    let task_handle = tokio::spawn(async move {
        sl_dkls23::sign::run(setup, random_seed(), relay)
            .await
            .map(|(sig, recid)| {
                let (r, s) = sig.split_bytes();
                let mut bytes = r.to_vec();
                bytes.extend_from_slice(&s);
                (bytes, recid.to_byte())
            })
            .map_err(|e| e.to_string())
    });

    let (batch, _) = collect_batch_async(&mut rx_out, &round_complete)
        .await
        .ok_or_else(|| RpcProblem::new(-32603, "sign task closed before round 1"))?;

    state.sign_sessions.insert(session_id.clone(), Arc::new(SignSession {
        tx_in,
        rx_out: Mutex::new(rx_out),
        task_handle: Mutex::new(Some(task_handle)),
        created_at: Instant::now(),
        round_complete,
    }));
    Ok(json!(StartResponse {
        session_id: session_id.clone(),
        server_payload: encode_server_envelope_batch(session_id, ProtocolType::Dsg, 1, batch),
    }))
}

async fn sign_continue(
    state: AppState,
    session_id: String,
    round: u8,
    client_payload: String,
) -> Result<Value, RpcProblem> {
    let session = state.sign_sessions.get(&session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| RpcProblem::new(-32001, format!("session not found: {session_id}")))?;
    if session.created_at.elapsed() > SESSION_TTL {
        state.sign_sessions.remove(&session_id);
        return Err(RpcProblem::new(-32001, format!("session expired: {session_id}")));
    }

    let client_msgs = decode_client_envelope_batch(&client_payload, &session_id, ProtocolType::Dsg)?;
    inject_all_async(&session.tx_in, client_msgs).await?;

    let next_batch = {
        let mut rx = session.rx_out.lock().await;
        collect_batch_async(&mut *rx, &session.round_complete).await
    };

    if let Some((server_msgs, done)) = next_batch {
        if done {
            state.sign_sessions.remove(&session_id);
        }
        return Ok(json!(StartResponse {
            session_id: session_id.clone(),
            server_payload: encode_server_envelope_batch(
                session_id, ProtocolType::Dsg, round.saturating_add(1), server_msgs,
            ),
        }));
    }

    let handle = session.task_handle.lock().await.take()
        .ok_or_else(|| RpcProblem::new(-32603, "sign task handle missing"))?;
    state.sign_sessions.remove(&session_id);

    let (sig_bytes, recid) = handle.await
        .map_err(|e| RpcProblem::new(-32603, format!("task join: {e}")))?
        .map_err(|e| RpcProblem::new(-32603, format!("protocol: {e}")))?;

    if sig_bytes.len() != 64 {
        return Err(RpcProblem::new(-32603, format!("unexpected signature length: {}", sig_bytes.len())));
    }
    Ok(json!(SignCompletedResponse {
        status: "completed",
        r: hex::encode(&sig_bytes[..32]),
        s: hex::encode(&sig_bytes[32..]),
        recid,
    }))
}

async fn recovery_start(state: AppState, mpc_key_id: String) -> Result<Value, RpcProblem> {
    let key_record = state.keystore.get(&mpc_key_id)
        .ok_or_else(|| RpcProblem::new(-32003, format!("Key not found: {mpc_key_id}")))?;
    let keyshare = Keyshare::from_bytes(&key_record.keyshare_bytes)
        .ok_or_else(|| RpcProblem::new(-32603, "stored keyshare is invalid"))?;
    let rotation_version = key_record.rotation_version;
    drop(key_record);

    let share_for_refresh = KeyshareForRefresh::from_keyshare(&keyshare, None);
    let session_id = new_session_id();
    let instance = instance_id_from_session(&session_id)?;
    let setup = KeygenSetup::new(
        instance, NoSigningKey, 1,
        vec![NoVerifyingKey::new(0), NoVerifyingKey::new(1)],
        &[0u8, 0u8], 2,
    );
    let (tx_in, rx_in) = mpsc::channel::<Vec<u8>>(16);
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let (relay, round_complete) = ChannelRelayConn::new(rx_in, tx_out);

    let task_handle = tokio::spawn(async move {
        key_refresh::run(setup, random_seed(), relay, share_for_refresh)
            .await
            .map(|ks| ks.as_slice().to_vec())
            .map_err(|e| e.to_string())
    });

    let (batch, _) = collect_batch_async(&mut rx_out, &round_complete)
        .await
        .ok_or_else(|| RpcProblem::new(-32603, "recovery task closed before round 1"))?;

    info!(session_id, rotation_version, "recovery session created");
    state.recovery_sessions.insert(session_id.clone(), Arc::new(RecoverySession {
        tx_in,
        rx_out: Mutex::new(rx_out),
        task_handle: Mutex::new(Some(task_handle)),
        created_at: Instant::now(),
        mpc_key_id,
        round_complete,
    }));
    Ok(json!(StartResponse {
        session_id: session_id.clone(),
        server_payload: encode_server_envelope_batch(session_id, ProtocolType::Rotation, 1, batch),
    }))
}

async fn recovery_continue(
    state: AppState,
    session_id: String,
    round: u8,
    client_payload: String,
) -> Result<Value, RpcProblem> {
    let session = state.recovery_sessions.get(&session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| RpcProblem::new(-32001, format!("session not found: {session_id}")))?;
    if session.created_at.elapsed() > SESSION_TTL {
        state.recovery_sessions.remove(&session_id);
        return Err(RpcProblem::new(-32001, format!("session expired: {session_id}")));
    }

    let client_msgs = decode_client_envelope_batch(&client_payload, &session_id, ProtocolType::Rotation)?;
    inject_all_async(&session.tx_in, client_msgs).await?;

    let next_batch = {
        let mut rx = session.rx_out.lock().await;
        collect_batch_async(&mut *rx, &session.round_complete).await
    };

    if let Some((server_msgs, done)) = next_batch {
        if done {
            if let Some(handle) = session.task_handle.lock().await.take() {
                let old_rotation = state.keystore.get(&session.mpc_key_id)
                    .map(|r| r.rotation_version).unwrap_or(0);
                match handle.await {
                    Ok(Ok(ks_bytes)) => match keyshare_record(session.mpc_key_id.clone(), ks_bytes, old_rotation + 1) {
                        Ok(record) => {
                            info!(session_id, address = %record.address, rv = record.rotation_version, "keyshare persisted");
                            state.keystore.insert(record.mpc_key_id.clone(), record);
                        }
                        Err(e) => warn!(session_id, error = %e.message, "keyshare record failed"),
                    },
                    Ok(Err(e)) => warn!(session_id, error = %e, "protocol error"),
                    Err(e)     => warn!(session_id, error = %e, "task join error"),
                }
            }
            state.recovery_sessions.remove(&session_id);
        }
        return Ok(json!(StartResponse {
            session_id: session_id.clone(),
            server_payload: encode_server_envelope_batch(
                session_id, ProtocolType::Rotation, round.saturating_add(1), server_msgs,
            ),
        }));
    }

    let handle = session.task_handle.lock().await.take()
        .ok_or_else(|| RpcProblem::new(-32603, "recovery task handle missing"))?;
    state.recovery_sessions.remove(&session_id);

    let ks_bytes = handle.await
        .map_err(|e| RpcProblem::new(-32603, format!("task join: {e}")))?
        .map_err(|e| RpcProblem::new(-32603, format!("protocol: {e}")))?;
    let old_rotation = state.keystore.get(&session.mpc_key_id)
        .map(|r| r.rotation_version)
        .ok_or_else(|| RpcProblem::new(-32003, format!("Key not found: {}", session.mpc_key_id)))?;
    let record = keyshare_record(session.mpc_key_id.clone(), ks_bytes, old_rotation + 1)?;
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
    if state.frost_keystore.contains_key(&params.mpc_key_id) {
        let share = frost::frost_export(&params.mpc_key_id, &state)?;
        return Ok(json!(ExportKeyResponse { server_share_private: share }));
    }
    let mut key_record = state.keystore.get_mut(&params.mpc_key_id)
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
                json!({"jsonrpc": "2.0", "method": "unknown", "params": {}, "id": 1}).to_string(),
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
                json!({"jsonrpc": "2.0", "method": "keygen", "params": {"round": 1}, "id": 1})
                    .to_string(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json["result"]["sessionId"].is_string());
        assert!(json["result"]["serverPayload"]["payload"].is_string());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn frost_keygen_round1_creates_frost_session() {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;
        use frost_ed25519::keys::dkg;
        use frost_ed25519::Identifier;

        let state = AppState::new();
        let app = build_app(state);
        let mut rng = rand::thread_rng();
        let client_id = Identifier::try_from(1u16).unwrap();
        let (_, client_r1_pkg) = dkg::part1(client_id, 2, 2, &mut rng).unwrap();
        let client_r1_b64 =
            BASE64_STANDARD.encode(serde_json::to_string(&client_r1_pkg).unwrap().as_bytes());

        let request = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "jsonrpc": "2.0",
                    "method": "keygen",
                    "params": {"round": 1, "curve": "ed25519", "clientPayload": client_r1_b64},
                    "id": 1
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json["result"]["sessionId"].is_string(), "expected sessionId");
        assert_eq!(json["result"]["serverPayload"]["curve"], "ed25519");
        assert_eq!(json["result"]["serverPayload"]["round"], 1);
    }

    #[tokio::test]
    async fn ws_route_exists() {
        let state = AppState::new();
        let app = build_app(state);
        let request = Request::builder()
            .method("GET")
            .uri("/ws")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }
}
