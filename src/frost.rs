//! FROST-Ed25519 工具函数和协议处理
//!
//! - encode_frost_key / decode_frost_key: ShareEnvelope v2 JSON 编解码
//! - derive_solana_address: 32 字节 verifying_key → base58 Solana 地址
//! - frost_keygen_round1/2/3: FROST DKG 3-round keygen（server = Identifier(2)）
//! - frost_sign_round1/2: FROST sign 2-round coordinator

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use frost_ed25519::keys::dkg;
use frost_ed25519::keys::dkg::{round1 as dkg_r1, round2 as dkg_r2};
use frost_ed25519::{round1 as sign_r1, round2 as sign_r2};
use frost_ed25519::Identifier;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::rpc::RpcProblem;
use crate::state::{AppState, FrostKeygenSession, FrostKeyRecord, FrostSignSession, SESSION_TTL};
use crate::types::{ProtocolType, WireEnvelope};

/// 将 FROST KeyPackage 序列化为 ShareEnvelope v2 JSON 字符串。
///
/// 输出格式：`{"v":2,"curve":"ed25519","share":"<base64>"}`
/// 其中 share = BASE64(serde_json(key_pkg))
pub fn encode_frost_key(key_pkg: &frost_ed25519::keys::KeyPackage) -> Result<String, String> {
    let pkg_json = serde_json::to_string(key_pkg)
        .map_err(|e| format!("KeyPackage serialize failed: {e}"))?;
    let share_b64 = BASE64_STANDARD.encode(pkg_json.as_bytes());
    Ok(json!({"v": 2, "curve": "ed25519", "share": share_b64}).to_string())
}

/// 将 ShareEnvelope v2 JSON 字符串反序列化为 FROST KeyPackage。
pub fn decode_frost_key(s: &str) -> Result<frost_ed25519::keys::KeyPackage, String> {
    let v: Value = serde_json::from_str(s)
        .map_err(|e| format!("ShareEnvelope parse failed: {e}"))?;
    let share_b64 = v["share"]
        .as_str()
        .ok_or_else(|| "missing 'share' field in ShareEnvelope".to_string())?;
    let pkg_bytes = BASE64_STANDARD
        .decode(share_b64)
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    serde_json::from_slice(&pkg_bytes)
        .map_err(|e| format!("KeyPackage deserialize failed: {e}"))
}

/// 从 32 字节 Ed25519 verifying key 派生 Solana base58 地址。
pub fn derive_solana_address(verifying_key_bytes: &[u8]) -> String {
    bs58::encode(verifying_key_bytes).into_string()
}

// ── FROST keygen 3-round DKG ─────────────────────────────────────

/// Keygen round 1: 接收 client r1 package（base64 JSON），生成 server r1 package，
/// 创建 FrostKeygenSession，返回 (session_id, WireEnvelope)。
pub async fn frost_keygen_round1(
    client_r1_pkg_b64: &str,
    state: &AppState,
) -> Result<(String, WireEnvelope), RpcProblem> {
    let client_r1_json = BASE64_STANDARD
        .decode(client_r1_pkg_b64)
        .map_err(|e| RpcProblem::new(-32600, format!("base64 decode client r1 pkg: {e}")))?;
    let client_r1_pkg: dkg_r1::Package = serde_json::from_slice(&client_r1_json)
        .map_err(|e| RpcProblem::new(-32600, format!("deserialize client r1 pkg: {e}")))?;

    let mut rng = rand::thread_rng();
    let server_id = Identifier::try_from(2u16)
        .map_err(|e| RpcProblem::new(-32603, format!("Identifier(2) failed: {e}")))?;
    let (r1_secret, r1_pkg) = dkg::part1(server_id, 2, 2, &mut rng)
        .map_err(|e| RpcProblem::new(-32603, format!("DKG part1 failed: {e}")))?;

    let mut session_bytes = [0u8; 32];
    rng.fill_bytes(&mut session_bytes);
    let session_id = hex::encode(session_bytes);

    let session = FrostKeygenSession {
        round1_secret: Mutex::new(Some(r1_secret)),
        round2_secret: Mutex::new(None),
        client_r1_package: Mutex::new(Some(client_r1_pkg)),
        server_r1_package: Mutex::new(Some(r1_pkg.clone())),
        client_r2_package: Mutex::new(None),
        created_at: Instant::now(),
    };
    state
        .frost_keygen_sessions
        .insert(session_id.clone(), Arc::new(session));

    let r1_json = serde_json::to_string(&r1_pkg)
        .map_err(|e| RpcProblem::new(-32603, format!("serialize server r1 pkg: {e}")))?;
    let r1_b64 = BASE64_STANDARD.encode(r1_json.as_bytes());

    let mut env = WireEnvelope::new(session_id.clone(), ProtocolType::Dkg, 1, 1, Some(0), r1_b64);
    env.curve = Some("ed25519".to_string());

    Ok((session_id, env))
}

/// Keygen round 2: 接收 client r2 package，推进 DKG part2，返回 server r2 package。
pub async fn frost_keygen_round2(
    session_id: &str,
    client_r2_pkg_b64: &str,
    state: &AppState,
) -> Result<WireEnvelope, RpcProblem> {
    let session = state
        .frost_keygen_sessions
        .get(session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| {
            RpcProblem::new(-32001, format!("FROST keygen session not found: {session_id}"))
        })?;

    if session.created_at.elapsed() > SESSION_TTL {
        state.frost_keygen_sessions.remove(session_id);
        return Err(RpcProblem::new(
            -32001,
            format!("FROST keygen session expired: {session_id}"),
        ));
    }

    let client_r2_json = BASE64_STANDARD
        .decode(client_r2_pkg_b64)
        .map_err(|e| RpcProblem::new(-32600, format!("base64 decode client r2 pkg: {e}")))?;
    let client_r2_pkg: dkg_r2::Package = serde_json::from_slice(&client_r2_json)
        .map_err(|e| RpcProblem::new(-32600, format!("deserialize client r2 pkg: {e}")))?;

    // Take r1_secret (consumes it; can't be used again)
    let r1_secret = session
        .round1_secret
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "round1_secret missing; round2 already called?"))?;

    // Clone client_r1_package — keep it in session for round3
    let client_r1_pkg = session
        .client_r1_package
        .lock()
        .await
        .clone()
        .ok_or_else(|| RpcProblem::new(-32603, "client_r1_package missing"))?;

    let client_id = Identifier::try_from(1u16)
        .map_err(|e| RpcProblem::new(-32603, format!("Identifier(1) failed: {e}")))?;

    // part2 receives only OTHER participants' r1 packages (not server's own)
    let mut round1_packages = BTreeMap::new();
    round1_packages.insert(client_id, client_r1_pkg);

    let (r2_secret, r2_pkgs_map) = dkg::part2(r1_secret, &round1_packages)
        .map_err(|e| RpcProblem::new(-32603, format!("DKG part2 failed: {e}")))?;

    let r2_pkg_for_client = r2_pkgs_map
        .get(&client_id)
        .ok_or_else(|| RpcProblem::new(-32603, "no r2 package for client in part2 output"))?
        .clone();

    // Store r2_secret and client_r2_pkg for round3
    *session.round2_secret.lock().await = Some(r2_secret);
    *session.client_r2_package.lock().await = Some(client_r2_pkg);

    let r2_json = serde_json::to_string(&r2_pkg_for_client)
        .map_err(|e| RpcProblem::new(-32603, format!("serialize server r2 pkg: {e}")))?;
    let r2_b64 = BASE64_STANDARD.encode(r2_json.as_bytes());

    let mut env = WireEnvelope::new(
        session_id.to_string(),
        ProtocolType::Dkg,
        2,
        1,
        Some(0),
        r2_b64,
    );
    env.curve = Some("ed25519".to_string());

    Ok(env)
}

/// Keygen round 3 (finalize): 调用 DKG part3，将 FrostKeyRecord 存入 frost_keystore，
/// 返回 (mpc_key_id, sol_address, public_key_hex)。
pub async fn frost_keygen_round3(
    session_id: &str,
    state: &AppState,
) -> Result<(String, String, String), RpcProblem> {
    let session = state
        .frost_keygen_sessions
        .get(session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| {
            RpcProblem::new(-32001, format!("FROST keygen session not found: {session_id}"))
        })?;

    let r2_secret = session
        .round2_secret
        .lock()
        .await
        .take()
        .ok_or_else(|| {
            RpcProblem::new(-32603, "round2_secret missing; round3 called before round2?")
        })?;

    let client_r1_pkg = session
        .client_r1_package
        .lock()
        .await
        .clone()
        .ok_or_else(|| RpcProblem::new(-32603, "client_r1_package missing for finalize"))?;

    let client_r2_pkg = session
        .client_r2_package
        .lock()
        .await
        .clone()
        .ok_or_else(|| RpcProblem::new(-32603, "client_r2_package missing for finalize"))?;

    let client_id = Identifier::try_from(1u16)
        .map_err(|e| RpcProblem::new(-32603, format!("Identifier(1) failed: {e}")))?;

    let mut round1_packages = BTreeMap::new();
    round1_packages.insert(client_id, client_r1_pkg);

    let mut round2_packages = BTreeMap::new();
    round2_packages.insert(client_id, client_r2_pkg);

    let (key_pkg, pub_key_pkg) = dkg::part3(&r2_secret, &round1_packages, &round2_packages)
        .map_err(|e| RpcProblem::new(-32603, format!("DKG part3 failed: {e}")))?;

    let vk_ser = pub_key_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| RpcProblem::new(-32603, format!("vk serialize failed: {e}")))?;
    let vk_bytes: &[u8] = vk_ser.as_ref();

    let address = derive_solana_address(vk_bytes);
    let public_key = hex::encode(vk_bytes);
    let mpc_key_id = session_id.to_string();

    let record = FrostKeyRecord {
        mpc_key_id: mpc_key_id.clone(),
        key_package: key_pkg,
        public_key_package: pub_key_pkg,
        address: address.clone(),
        rotation_version: 1,
        exported: false,
    };
    state.frost_keystore.insert(mpc_key_id.clone(), record);
    state.frost_keygen_sessions.remove(session_id);

    Ok((mpc_key_id, address, public_key))
}

// ── FROST sign 2-round coordinator ──────────────────────────────

/// Sign round 1 (commit): 接收 client SigningCommitments，生成 server nonces + commitments，
/// 创建 FrostSignSession，返回 (session_id, WireEnvelope)。
pub async fn frost_sign_round1(
    mpc_key_id: &str,
    client_commitments_b64: &str,
    message_hash_hex: &str,
    state: &AppState,
) -> Result<(String, WireEnvelope), RpcProblem> {
    // Validate key exists and is not exported
    {
        let key_record = state
            .frost_keystore
            .get(mpc_key_id)
            .ok_or_else(|| RpcProblem::new(-32003, format!("FROST key not found: {mpc_key_id}")))?;
        if key_record.exported {
            return Err(RpcProblem::new(
                -32004,
                format!("signing rejected: keyshare has been exported ({mpc_key_id})"),
            ));
        }
    }

    let client_commitments_json = BASE64_STANDARD
        .decode(client_commitments_b64)
        .map_err(|e| RpcProblem::new(-32600, format!("base64 decode client commitments: {e}")))?;
    let client_commitments: frost_ed25519::round1::SigningCommitments =
        serde_json::from_slice(&client_commitments_json)
            .map_err(|e| RpcProblem::new(-32600, format!("deserialize client commitments: {e}")))?;

    let hash_bytes = hex::decode(message_hash_hex)
        .map_err(|e| RpcProblem::new(-32600, format!("hex decode message hash: {e}")))?;
    let message_hash: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| RpcProblem::new(-32600, "messageHash must be exactly 32 bytes"))?;

    let mut rng = rand::thread_rng();

    // commit() is sync; hold DashMap ref only for this block (no await)
    let (nonces, server_commitments) = {
        let key_record = state
            .frost_keystore
            .get(mpc_key_id)
            .ok_or_else(|| RpcProblem::new(-32003, format!("FROST key not found: {mpc_key_id}")))?;
        sign_r1::commit(key_record.key_package.signing_share(), &mut rng)
    };

    let mut session_bytes = [0u8; 32];
    rng.fill_bytes(&mut session_bytes);
    let session_id = hex::encode(session_bytes);

    let session = FrostSignSession {
        nonces: Mutex::new(Some(nonces)),
        client_commitments: Mutex::new(Some(client_commitments)),
        message_hash,
        mpc_key_id: mpc_key_id.to_string(),
        created_at: Instant::now(),
    };
    state
        .frost_sign_sessions
        .insert(session_id.clone(), Arc::new(session));

    let commitments_json = serde_json::to_string(&server_commitments)
        .map_err(|e| RpcProblem::new(-32603, format!("serialize server commitments: {e}")))?;
    let commitments_b64 = BASE64_STANDARD.encode(commitments_json.as_bytes());

    let mut env = WireEnvelope::new(
        session_id.clone(),
        ProtocolType::Dsg,
        1,
        1,
        Some(0),
        commitments_b64,
    );
    env.curve = Some("ed25519".to_string());

    Ok((session_id, env))
}

/// Sign round 2 (sign): 接收 client SigningPackage，调用 round2::sign，
/// 返回 WireEnvelope(round=2, payload=base64(SignatureShare JSON))。
pub async fn frost_sign_round2(
    session_id: &str,
    signing_package_b64: &str,
    state: &AppState,
) -> Result<WireEnvelope, RpcProblem> {
    let session = state
        .frost_sign_sessions
        .get(session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| {
            RpcProblem::new(-32001, format!("FROST sign session not found: {session_id}"))
        })?;

    if session.created_at.elapsed() > SESSION_TTL {
        state.frost_sign_sessions.remove(session_id);
        return Err(RpcProblem::new(
            -32001,
            format!("FROST sign session expired: {session_id}"),
        ));
    }

    let signing_pkg_json = BASE64_STANDARD
        .decode(signing_package_b64)
        .map_err(|e| RpcProblem::new(-32600, format!("base64 decode signing package: {e}")))?;
    let signing_package: frost_ed25519::SigningPackage = serde_json::from_slice(&signing_pkg_json)
        .map_err(|e| RpcProblem::new(-32600, format!("deserialize signing package: {e}")))?;

    let nonces = session
        .nonces
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "sign nonces missing"))?;

    let signature_share = {
        let key_record = state
            .frost_keystore
            .get(&session.mpc_key_id)
            .ok_or_else(|| {
                RpcProblem::new(-32003, format!("FROST key not found: {}", session.mpc_key_id))
            })?;
        sign_r2::sign(&signing_package, &nonces, &key_record.key_package)
            .map_err(|e| RpcProblem::new(-32603, format!("FROST sign failed: {e}")))?
    };

    state.frost_sign_sessions.remove(session_id);

    let sig_json = serde_json::to_string(&signature_share)
        .map_err(|e| RpcProblem::new(-32603, format!("serialize signature share: {e}")))?;
    let sig_b64 = BASE64_STANDARD.encode(sig_json.as_bytes());

    let mut env = WireEnvelope::new(
        session_id.to_string(),
        ProtocolType::Dsg,
        2,
        1,
        Some(0),
        sig_b64,
    );
    env.curve = Some("ed25519".to_string());

    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use frost_ed25519::keys::dkg;
    use frost_ed25519::{round1 as sign_r1, Identifier, SigningPackage};

    #[test]
    fn derive_solana_address_32_zero_bytes() {
        let addr = derive_solana_address(&[0u8; 32]);
        assert!(!addr.is_empty(), "address must not be empty");
        assert!(!addr.contains('0'));
    }

    #[test]
    fn share_envelope_v2_json_shape() {
        let fake_b64 = BASE64_STANDARD.encode(b"fake_pkg_json");
        let envelope = json!({"v": 2, "curve": "ed25519", "share": fake_b64}).to_string();
        let parsed: Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(parsed["v"], 2);
        assert_eq!(parsed["curve"], "ed25519");
        assert!(parsed["share"].is_string());
    }

    #[tokio::test]
    async fn test_frost_keygen_full_roundtrip() {
        let state = AppState::new();
        let mut rng = rand::thread_rng();

        let client_id = Identifier::try_from(1u16).unwrap();
        let server_id = Identifier::try_from(2u16).unwrap();

        // Client: DKG round 1
        let (client_r1_secret, client_r1_pkg) =
            dkg::part1(client_id, 2, 2, &mut rng).unwrap();
        let client_r1_b64 =
            BASE64_STANDARD.encode(serde_json::to_string(&client_r1_pkg).unwrap().as_bytes());

        // Server: round 1
        let (session_id, server_env_r1) =
            frost_keygen_round1(&client_r1_b64, &state).await.unwrap();
        assert_eq!(server_env_r1.round, 1);
        assert_eq!(server_env_r1.curve, Some("ed25519".to_string()));

        // Client: decode server r1, run DKG round 2
        let server_r1_json = BASE64_STANDARD.decode(&server_env_r1.payload).unwrap();
        let server_r1_pkg: dkg::round1::Package =
            serde_json::from_slice(&server_r1_json).unwrap();

        let mut client_r1_pkgs = BTreeMap::new();
        client_r1_pkgs.insert(server_id, server_r1_pkg);
        let (client_r2_secret, client_r2_pkgs) =
            dkg::part2(client_r1_secret, &client_r1_pkgs).unwrap();

        // Client sends its r2 package (addressed to server = Identifier(2))
        let r2_for_server = client_r2_pkgs.get(&server_id).unwrap();
        let r2_b64 = BASE64_STANDARD
            .encode(serde_json::to_string(r2_for_server).unwrap().as_bytes());

        // Server: round 2
        let server_env_r2 = frost_keygen_round2(&session_id, &r2_b64, &state)
            .await
            .unwrap();
        assert_eq!(server_env_r2.round, 2);
        assert_eq!(server_env_r2.curve, Some("ed25519".to_string()));

        // Client: decode server r2, run DKG part3
        let server_r2_json = BASE64_STANDARD.decode(&server_env_r2.payload).unwrap();
        let server_r2_pkg: dkg::round2::Package =
            serde_json::from_slice(&server_r2_json).unwrap();

        let mut client_r2_pkgs_for_part3 = BTreeMap::new();
        client_r2_pkgs_for_part3.insert(server_id, server_r2_pkg);
        let (_client_key_pkg, _client_pub_key_pkg) =
            dkg::part3(&client_r2_secret, &client_r1_pkgs, &client_r2_pkgs_for_part3).unwrap();

        // Server: round 3 finalize
        let (mpc_key_id, address, public_key) =
            frost_keygen_round3(&session_id, &state).await.unwrap();

        assert!(!mpc_key_id.is_empty());
        assert!(!address.is_empty());
        assert_eq!(public_key.len(), 64, "public_key must be 32 bytes = 64 hex chars");
        assert!(state.frost_keystore.contains_key(&mpc_key_id));
        // Session should be removed after finalize
        assert!(!state.frost_keygen_sessions.contains_key(&session_id));
    }

    #[tokio::test]
    async fn test_frost_sign_full_roundtrip() {
        let state = AppState::new();
        let mut rng = rand::thread_rng();

        let client_id = Identifier::try_from(1u16).unwrap();
        let server_id = Identifier::try_from(2u16).unwrap();

        // --- Run full keygen first ---
        let (client_r1_secret, client_r1_pkg) =
            dkg::part1(client_id, 2, 2, &mut rng).unwrap();
        let client_r1_b64 =
            BASE64_STANDARD.encode(serde_json::to_string(&client_r1_pkg).unwrap().as_bytes());

        let (session_id, server_env_r1) =
            frost_keygen_round1(&client_r1_b64, &state).await.unwrap();

        let server_r1_json = BASE64_STANDARD.decode(&server_env_r1.payload).unwrap();
        let server_r1_pkg: dkg::round1::Package =
            serde_json::from_slice(&server_r1_json).unwrap();

        let mut client_r1_pkgs = BTreeMap::new();
        client_r1_pkgs.insert(server_id, server_r1_pkg);
        let (client_r2_secret, client_r2_pkgs) =
            dkg::part2(client_r1_secret, &client_r1_pkgs).unwrap();

        let r2_for_server = client_r2_pkgs.get(&server_id).unwrap();
        let r2_b64 = BASE64_STANDARD
            .encode(serde_json::to_string(r2_for_server).unwrap().as_bytes());

        let server_env_r2 = frost_keygen_round2(&session_id, &r2_b64, &state)
            .await
            .unwrap();

        let server_r2_json = BASE64_STANDARD.decode(&server_env_r2.payload).unwrap();
        let server_r2_pkg: dkg::round2::Package =
            serde_json::from_slice(&server_r2_json).unwrap();

        let mut client_r2_pkgs_for_part3 = BTreeMap::new();
        client_r2_pkgs_for_part3.insert(server_id, server_r2_pkg);
        let (client_key_pkg, _) =
            dkg::part3(&client_r2_secret, &client_r1_pkgs, &client_r2_pkgs_for_part3).unwrap();

        let (mpc_key_id, _, _) = frost_keygen_round3(&session_id, &state).await.unwrap();

        // --- Sign: round 1 ---
        let message = b"FROST test message";

        let (client_nonces, client_commitments) =
            sign_r1::commit(client_key_pkg.signing_share(), &mut rng);
        let client_commitments_b64 = BASE64_STANDARD.encode(
            serde_json::to_string(&client_commitments).unwrap().as_bytes(),
        );

        // message_hash_hex: 32-byte placeholder (server stores but doesn't validate vs message)
        let mut fake_hash = [0u8; 32];
        rng.fill_bytes(&mut fake_hash);
        let message_hash_hex = hex::encode(fake_hash);

        let (sign_session_id, server_env_sign_r1) = frost_sign_round1(
            &mpc_key_id,
            &client_commitments_b64,
            &message_hash_hex,
            &state,
        )
        .await
        .unwrap();
        assert_eq!(server_env_sign_r1.round, 1);
        assert_eq!(server_env_sign_r1.curve, Some("ed25519".to_string()));

        // Client: decode server commitments, build SigningPackage
        let server_commitments_json =
            BASE64_STANDARD.decode(&server_env_sign_r1.payload).unwrap();
        let server_commitments: frost_ed25519::round1::SigningCommitments =
            serde_json::from_slice(&server_commitments_json).unwrap();

        let mut all_commitments = BTreeMap::new();
        all_commitments.insert(client_id, client_commitments);
        all_commitments.insert(server_id, server_commitments);
        let signing_package = SigningPackage::new(all_commitments, message);

        let signing_pkg_b64 = BASE64_STANDARD.encode(
            serde_json::to_string(&signing_package).unwrap().as_bytes(),
        );

        // Server: sign round 2
        let server_env_sign_r2 =
            frost_sign_round2(&sign_session_id, &signing_pkg_b64, &state)
                .await
                .unwrap();
        assert_eq!(server_env_sign_r2.round, 2);
        assert_eq!(server_env_sign_r2.curve, Some("ed25519".to_string()));

        // Verify signature share can be deserialized
        let sig_json = BASE64_STANDARD.decode(&server_env_sign_r2.payload).unwrap();
        let _server_sig_share: frost_ed25519::round2::SignatureShare =
            serde_json::from_slice(&sig_json).unwrap();

        // Sign session should be removed
        assert!(!state.frost_sign_sessions.contains_key(&sign_session_id));

        // Client can aggregate: (omit full aggregate in unit test, structure is verified)
        let _ = client_nonces; // was consumed by commit(); nonces are in server session
    }
}
