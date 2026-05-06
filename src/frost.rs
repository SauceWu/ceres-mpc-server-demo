//! FROST-Ed25519 protocol handlers — session management + WireEnvelope packaging.
//! All protocol cryptography is delegated to `ceres_wallet_frost_mpc`.

use std::sync::Arc;
use std::time::Instant;

use rand::RngCore;
use tokio::sync::Mutex;

use crate::rpc::RpcProblem;
use crate::state::{
    AppState, FrostKeygenSession, FrostKeyRecord, FrostRecoverySession, FrostSignSession,
    SESSION_TTL,
};
use crate::types::{ProtocolType, WireEnvelope};
use ceres_wallet_frost_mpc as fmpc;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Validate client WireEnvelope and return its inner encoded payload.
/// The payload string is passed directly to library functions which decode it internally.
fn extract_inner_payload(
    client_payload: &str,
    expected_session: &str,
    expected_protocol: ProtocolType,
) -> Result<String, RpcProblem> {
    let env: WireEnvelope = serde_json::from_str(client_payload)
        .map_err(|e| RpcProblem::new(-32600, format!("invalid clientPayload JSON: {e}")))?;
    if env.session_id != expected_session {
        return Err(RpcProblem::new(-32600, "clientPayload.session_id mismatch"));
    }
    if env.protocol != expected_protocol {
        return Err(RpcProblem::new(-32600, "clientPayload.protocol mismatch"));
    }
    Ok(env.payload)
}

/// Build a server WireEnvelope with a pre-encoded payload string.
fn build_raw_envelope(
    session_id: String,
    protocol: ProtocolType,
    round: u8,
    payload: String,
) -> WireEnvelope {
    let mut env = WireEnvelope::new(session_id, protocol, round, 1, Some(0), payload);
    env.curve = Some("ed25519".to_string());
    env
}

fn mpc_err(e: fmpc::FrostMpcError) -> RpcProblem {
    RpcProblem::new(-32603, e.to_string())
}

fn derive_solana_address(verifying_key_bytes: &[u8]) -> String {
    bs58::encode(verifying_key_bytes).into_string()
}

fn new_session_id(rng: &mut impl RngCore) -> String {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ── FROST keygen 3-round DKG ──────────────────────────────────────────────────

pub async fn frost_keygen_round1(state: &AppState) -> Result<(String, WireEnvelope), RpcProblem> {
    let mut rng = rand::thread_rng();
    let (keygen_state, server_payload) = fmpc::keygen_part1(2, &mut rng).map_err(mpc_err)?;
    let session_id = new_session_id(&mut rng);
    state.frost_keygen_sessions.insert(
        session_id.clone(),
        Arc::new(FrostKeygenSession {
            state: Mutex::new(Some(keygen_state)),
            created_at: Instant::now(),
        }),
    );
    Ok((
        session_id.clone(),
        build_raw_envelope(session_id, ProtocolType::Dkg, 1, server_payload),
    ))
}

pub async fn frost_keygen_round2(
    session_id: &str,
    client_payload: &str,
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

    let client_inner = extract_inner_payload(client_payload, session_id, ProtocolType::Dkg)?;
    let keygen_state = session
        .state
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "keygen state already consumed"))?;
    let (new_state, server_payload) =
        fmpc::keygen_part2(keygen_state, &client_inner).map_err(mpc_err)?;
    *session.state.lock().await = Some(new_state);
    Ok(build_raw_envelope(
        session_id.to_string(),
        ProtocolType::Dkg,
        2,
        server_payload,
    ))
}

pub async fn frost_keygen_round3(
    session_id: &str,
    client_payload: &str,
    state: &AppState,
) -> Result<(String, String, String), RpcProblem> {
    let session = state
        .frost_keygen_sessions
        .get(session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| {
            RpcProblem::new(-32001, format!("FROST keygen session not found: {session_id}"))
        })?;

    let client_inner = extract_inner_payload(client_payload, session_id, ProtocolType::Dkg)?;
    let keygen_state = session
        .state
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "keygen state missing"))?;
    let (key_pkg, pub_key_pkg) =
        fmpc::keygen_part3(keygen_state, &client_inner).map_err(mpc_err)?;

    let vk_ser = pub_key_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| RpcProblem::new(-32603, format!("vk serialize: {e}")))?;
    let vk_bytes: &[u8] = vk_ser.as_ref();
    let address = derive_solana_address(vk_bytes);
    let public_key = hex::encode(vk_bytes);
    let mpc_key_id = session_id.to_string();

    state.frost_keystore.insert(
        mpc_key_id.clone(),
        FrostKeyRecord {
            mpc_key_id: mpc_key_id.clone(),
            key_package: key_pkg,
            public_key_package: pub_key_pkg,
            address: address.clone(),
            rotation_version: 1,
            exported: false,
        },
    );
    state.frost_keygen_sessions.remove(session_id);
    Ok((mpc_key_id, address, public_key))
}

// ── FROST sign 2-round ────────────────────────────────────────────────────────

pub async fn frost_sign_round1(
    mpc_key_id: &str,
    message_hash_hex: &str,
    state: &AppState,
) -> Result<(String, WireEnvelope), RpcProblem> {
    let (key_package, exported) = {
        let r = state
            .frost_keystore
            .get(mpc_key_id)
            .ok_or_else(|| RpcProblem::new(-32003, format!("FROST key not found: {mpc_key_id}")))?;
        (r.key_package.clone(), r.exported)
    };
    if exported {
        return Err(RpcProblem::new(
            -32004,
            format!("signing rejected: keyshare exported ({mpc_key_id})"),
        ));
    }

    let hash_bytes = hex::decode(message_hash_hex)
        .map_err(|e| RpcProblem::new(-32600, format!("hex decode messageHash: {e}")))?;
    let message_hash: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| RpcProblem::new(-32600, "messageHash must be exactly 32 bytes"))?;

    let mut rng = rand::thread_rng();
    let (sign_state, server_payload) =
        fmpc::sign_part1(&key_package, message_hash, &mut rng).map_err(mpc_err)?;
    let session_id = new_session_id(&mut rng);
    state.frost_sign_sessions.insert(
        session_id.clone(),
        Arc::new(FrostSignSession {
            state: Mutex::new(Some(sign_state)),
            mpc_key_id: mpc_key_id.to_string(),
            created_at: Instant::now(),
        }),
    );
    Ok((
        session_id.clone(),
        build_raw_envelope(session_id, ProtocolType::Dsg, 1, server_payload),
    ))
}

pub async fn frost_sign_round2(
    session_id: &str,
    client_payload: &str,
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

    let client_inner = extract_inner_payload(client_payload, session_id, ProtocolType::Dsg)?;
    let sign_state = session
        .state
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "sign state missing"))?;
    let key_package = state
        .frost_keystore
        .get(&session.mpc_key_id)
        .ok_or_else(|| {
            RpcProblem::new(
                -32003,
                format!("FROST key not found: {}", session.mpc_key_id),
            )
        })?
        .key_package
        .clone();

    let server_payload =
        fmpc::sign_part2(sign_state, &client_inner, &key_package).map_err(mpc_err)?;
    state.frost_sign_sessions.remove(session_id);
    Ok(build_raw_envelope(
        session_id.to_string(),
        ProtocolType::Dsg,
        2,
        server_payload,
    ))
}

// ── FROST recovery 3-round key refresh ───────────────────────────────────────

pub async fn frost_recovery_round1(
    mpc_key_id: &str,
    state: &AppState,
) -> Result<(String, WireEnvelope), RpcProblem> {
    let (old_key_pkg, old_pub_key_pkg) = {
        let r = state
            .frost_keystore
            .get(mpc_key_id)
            .ok_or_else(|| RpcProblem::new(-32003, format!("FROST key not found: {mpc_key_id}")))?;
        (r.key_package.clone(), r.public_key_package.clone())
    };

    let mut rng = rand::thread_rng();
    let (recovery_state, server_payload) =
        fmpc::recovery_part1(old_key_pkg, old_pub_key_pkg, &mut rng).map_err(mpc_err)?;
    let session_id = new_session_id(&mut rng);
    state.frost_recovery_sessions.insert(
        session_id.clone(),
        Arc::new(FrostRecoverySession {
            state: Mutex::new(Some(recovery_state)),
            mpc_key_id: mpc_key_id.to_string(),
            created_at: Instant::now(),
        }),
    );
    Ok((
        session_id.clone(),
        build_raw_envelope(session_id, ProtocolType::Rotation, 1, server_payload),
    ))
}

pub async fn frost_recovery_round2(
    session_id: &str,
    client_payload: &str,
    state: &AppState,
) -> Result<WireEnvelope, RpcProblem> {
    let session = state
        .frost_recovery_sessions
        .get(session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| {
            RpcProblem::new(
                -32001,
                format!("FROST recovery session not found: {session_id}"),
            )
        })?;

    if session.created_at.elapsed() > SESSION_TTL {
        state.frost_recovery_sessions.remove(session_id);
        return Err(RpcProblem::new(
            -32001,
            format!("FROST recovery session expired: {session_id}"),
        ));
    }

    let client_inner =
        extract_inner_payload(client_payload, session_id, ProtocolType::Rotation)?;
    let recovery_state = session
        .state
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "recovery state missing"))?;
    let (new_state, server_payload) =
        fmpc::recovery_part2(recovery_state, &client_inner).map_err(mpc_err)?;
    *session.state.lock().await = Some(new_state);
    Ok(build_raw_envelope(
        session_id.to_string(),
        ProtocolType::Rotation,
        2,
        server_payload,
    ))
}

pub async fn frost_recovery_round3(
    session_id: &str,
    client_payload: &str,
    state: &AppState,
) -> Result<(String, String, i32), RpcProblem> {
    let session = state
        .frost_recovery_sessions
        .get(session_id)
        .map(|e| Arc::clone(e.value()))
        .ok_or_else(|| {
            RpcProblem::new(
                -32001,
                format!("FROST recovery session not found: {session_id}"),
            )
        })?;

    let client_inner =
        extract_inner_payload(client_payload, session_id, ProtocolType::Rotation)?;
    let recovery_state = session
        .state
        .lock()
        .await
        .take()
        .ok_or_else(|| RpcProblem::new(-32603, "recovery state missing"))?;
    let (new_key_pkg, new_pub_key_pkg) =
        fmpc::recovery_part3(recovery_state, &client_inner).map_err(mpc_err)?;

    let vk_ser = new_pub_key_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| RpcProblem::new(-32603, format!("vk serialize: {e}")))?;
    let address = derive_solana_address(vk_ser.as_ref());
    let old_rotation = state
        .frost_keystore
        .get(&session.mpc_key_id)
        .map(|r| r.rotation_version)
        .unwrap_or(1);
    let new_rotation = old_rotation + 1;

    state.frost_keystore.insert(
        session.mpc_key_id.clone(),
        FrostKeyRecord {
            mpc_key_id: session.mpc_key_id.clone(),
            key_package: new_key_pkg,
            public_key_package: new_pub_key_pkg,
            address: address.clone(),
            rotation_version: new_rotation,
            exported: false,
        },
    );
    state.frost_recovery_sessions.remove(session_id);
    Ok((session.mpc_key_id.clone(), address, new_rotation))
}

// ── Export ────────────────────────────────────────────────────────────────────

pub fn frost_export(mpc_key_id: &str, state: &AppState) -> Result<String, RpcProblem> {
    let mut record = state
        .frost_keystore
        .get_mut(mpc_key_id)
        .ok_or_else(|| RpcProblem::new(-32003, format!("FROST key not found: {mpc_key_id}")))?;
    if record.exported {
        return Err(RpcProblem::new(
            -32004,
            format!("key already exported: {mpc_key_id}"),
        ));
    }
    let envelope =
        fmpc::build_share_envelope(&record.key_package, &record.public_key_package)
            .map_err(mpc_err)?;
    record.exported = true;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use ceres_wallet_frost_mpc::wire::{
        DkgR1Payload, DkgR2Payload, RefreshR1Payload, RefreshR2Payload, SignR1Payload,
    };
    use frost_ed25519::keys::dkg;
    use frost_ed25519::keys::dkg::{round1 as dkg_r1, round2 as dkg_r2};
    use frost_ed25519::{round1 as sign_r1, Identifier};
    use rand::RngCore;
    use std::collections::BTreeMap;

    fn make_client_env(
        session_id: &str,
        protocol: ProtocolType,
        round: u8,
        inner_payload: &impl serde::Serialize,
    ) -> String {
        let inner_json = serde_json::to_vec(inner_payload).unwrap();
        let mut env = WireEnvelope::new(
            session_id.to_string(),
            protocol,
            round,
            0,
            Some(1),
            BASE64_STANDARD.encode(&inner_json),
        );
        env.curve = Some("ed25519".to_string());
        serde_json::to_string(&env).unwrap()
    }

    #[tokio::test]
    async fn test_frost_keygen_full_roundtrip() {
        let state = AppState::new();
        let mut rng = rand::thread_rng();
        let client_id = Identifier::try_from(1u16).unwrap();
        let server_id = Identifier::try_from(2u16).unwrap();

        let (session_id, server_env_r1) = frost_keygen_round1(&state).await.unwrap();
        assert_eq!(server_env_r1.round, 1);
        assert_eq!(server_env_r1.curve, Some("ed25519".to_string()));

        let r1_inner: DkgR1Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&server_env_r1.payload).unwrap())
                .unwrap();
        let server_r1_pkg = dkg_r1::Package::deserialize(
            &hex::decode(&r1_inner.round1_pkg).unwrap(),
        )
        .unwrap();

        let (client_r1_secret, client_r1_pkg) =
            dkg::part1(client_id, 2, 2, &mut rng).unwrap();
        let client_r1_str = make_client_env(
            &session_id,
            ProtocolType::Dkg,
            1,
            &DkgR1Payload { round1_pkg: hex::encode(client_r1_pkg.serialize().unwrap()) },
        );

        let server_env_r2 = frost_keygen_round2(&session_id, &client_r1_str, &state)
            .await
            .unwrap();
        assert_eq!(server_env_r2.round, 2);

        let r2_inner: DkgR2Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&server_env_r2.payload).unwrap())
                .unwrap();
        let server_r2_pkg = dkg_r2::Package::deserialize(
            &hex::decode(&r2_inner.round2_pkg).unwrap(),
        )
        .unwrap();

        let mut client_r1_pkgs = BTreeMap::new();
        client_r1_pkgs.insert(server_id, server_r1_pkg);
        let (client_r2_secret, client_r2_pkgs) =
            dkg::part2(client_r1_secret, &client_r1_pkgs).unwrap();
        let client_r2_str = make_client_env(
            &session_id,
            ProtocolType::Dkg,
            2,
            &DkgR2Payload {
                round2_pkg: hex::encode(
                    client_r2_pkgs.get(&server_id).unwrap().serialize().unwrap(),
                ),
            },
        );

        let (mpc_key_id, address, public_key) =
            frost_keygen_round3(&session_id, &client_r2_str, &state)
                .await
                .unwrap();

        let mut r2_for_part3 = BTreeMap::new();
        r2_for_part3.insert(server_id, server_r2_pkg);
        dkg::part3(&client_r2_secret, &client_r1_pkgs, &r2_for_part3).unwrap();

        assert!(!mpc_key_id.is_empty());
        assert!(!address.is_empty());
        assert_eq!(public_key.len(), 64);
        assert!(state.frost_keystore.contains_key(&mpc_key_id));
        assert!(!state.frost_keygen_sessions.contains_key(&session_id));
    }

    async fn run_keygen() -> (
        AppState,
        String,
        frost_ed25519::keys::KeyPackage,
        frost_ed25519::keys::PublicKeyPackage,
    ) {
        let state = AppState::new();
        let mut rng = rand::thread_rng();
        let client_id = Identifier::try_from(1u16).unwrap();
        let server_id = Identifier::try_from(2u16).unwrap();

        let (session_id, server_env_r1) = frost_keygen_round1(&state).await.unwrap();
        let r1_inner: DkgR1Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&server_env_r1.payload).unwrap())
                .unwrap();
        let server_r1_pkg = dkg_r1::Package::deserialize(
            &hex::decode(&r1_inner.round1_pkg).unwrap(),
        )
        .unwrap();
        let (client_r1_secret, client_r1_pkg) = dkg::part1(client_id, 2, 2, &mut rng).unwrap();
        let client_r1_str = make_client_env(
            &session_id,
            ProtocolType::Dkg,
            1,
            &DkgR1Payload { round1_pkg: hex::encode(client_r1_pkg.serialize().unwrap()) },
        );

        let server_env_r2 = frost_keygen_round2(&session_id, &client_r1_str, &state)
            .await
            .unwrap();
        let r2_inner: DkgR2Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&server_env_r2.payload).unwrap())
                .unwrap();
        let server_r2_pkg = dkg_r2::Package::deserialize(
            &hex::decode(&r2_inner.round2_pkg).unwrap(),
        )
        .unwrap();
        let mut client_r1_pkgs = BTreeMap::new();
        client_r1_pkgs.insert(server_id, server_r1_pkg);
        let (client_r2_secret, client_r2_pkgs) =
            dkg::part2(client_r1_secret, &client_r1_pkgs).unwrap();
        let client_r2_str = make_client_env(
            &session_id,
            ProtocolType::Dkg,
            2,
            &DkgR2Payload {
                round2_pkg: hex::encode(
                    client_r2_pkgs.get(&server_id).unwrap().serialize().unwrap(),
                ),
            },
        );
        let (mpc_key_id, _, _) =
            frost_keygen_round3(&session_id, &client_r2_str, &state).await.unwrap();

        let mut r2_for_part3 = BTreeMap::new();
        r2_for_part3.insert(server_id, server_r2_pkg);
        let (client_key_pkg, client_pub_key_pkg) =
            dkg::part3(&client_r2_secret, &client_r1_pkgs, &r2_for_part3).unwrap();

        (state, mpc_key_id, client_key_pkg, client_pub_key_pkg)
    }

    #[tokio::test]
    async fn test_frost_sign_full_roundtrip() {
        let (state, mpc_key_id, client_key_pkg, _) = run_keygen().await;
        let mut rng = rand::thread_rng();
        let client_id = Identifier::try_from(1u16).unwrap();
        let server_id = Identifier::try_from(2u16).unwrap();

        let mut fake_hash = [0u8; 32];
        rng.fill_bytes(&mut fake_hash);
        let message_hash_hex = hex::encode(fake_hash);

        let (sign_session_id, server_env_r1) =
            frost_sign_round1(&mpc_key_id, &message_hash_hex, &state)
                .await
                .unwrap();
        assert_eq!(server_env_r1.round, 1);

        let r1_inner: SignR1Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&server_env_r1.payload).unwrap())
                .unwrap();
        let _server_commitments =
            frost_ed25519::round1::SigningCommitments::deserialize(
                &hex::decode(&r1_inner.commitments).unwrap(),
            )
            .unwrap();

        let (client_nonces, client_commitments) =
            sign_r1::commit(client_key_pkg.signing_share(), &mut rng);
        let client_r1_str = make_client_env(
            &sign_session_id,
            ProtocolType::Dsg,
            1,
            &SignR1Payload {
                commitments: hex::encode(client_commitments.serialize().unwrap()),
            },
        );

        let server_env_r2 =
            frost_sign_round2(&sign_session_id, &client_r1_str, &state)
                .await
                .unwrap();
        assert_eq!(server_env_r2.round, 2);

        let r2_inner: ceres_wallet_frost_mpc::wire::SignR2Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&server_env_r2.payload).unwrap())
                .unwrap();
        let signing_pkg = frost_ed25519::SigningPackage::deserialize(
            &hex::decode(&r2_inner.signing_pkg).unwrap(),
        )
        .unwrap();
        let server_sig_share = frost_ed25519::round2::SignatureShare::deserialize(
            &hex::decode(&r2_inner.sig_share).unwrap(),
        )
        .unwrap();
        let client_sig_share =
            frost_ed25519::round2::sign(&signing_pkg, &client_nonces, &client_key_pkg).unwrap();

        let mut shares = BTreeMap::new();
        shares.insert(client_id, client_sig_share);
        shares.insert(server_id, server_sig_share);
        assert!(!state.frost_sign_sessions.contains_key(&sign_session_id));
        let _ = (shares, signing_pkg);
    }

    #[tokio::test]
    async fn test_frost_recovery_full_roundtrip() {
        use frost_ed25519::keys::refresh;

        let (state, mpc_key_id, client_key_pkg, client_pub_key_pkg) = run_keygen().await;
        let mut rng = rand::thread_rng();
        let client_id = Identifier::try_from(1u16).unwrap();
        let server_id = Identifier::try_from(2u16).unwrap();

        let (recovery_session_id, server_env_r1) =
            frost_recovery_round1(&mpc_key_id, &state).await.unwrap();
        assert_eq!(server_env_r1.round, 1);

        let r1_inner: RefreshR1Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&server_env_r1.payload).unwrap())
                .unwrap();
        let server_r1_pkg = dkg_r1::Package::deserialize(
            &hex::decode(&r1_inner.refresh_round1_pkg).unwrap(),
        )
        .unwrap();
        let (client_r1_secret, client_r1_pkg) =
            refresh::refresh_dkg_part1(client_id, 2, 2, &mut rng).unwrap();
        let client_r1_str = make_client_env(
            &recovery_session_id,
            ProtocolType::Rotation,
            1,
            &RefreshR1Payload {
                refresh_round1_pkg: hex::encode(client_r1_pkg.serialize().unwrap()),
            },
        );

        let server_env_r2 =
            frost_recovery_round2(&recovery_session_id, &client_r1_str, &state)
                .await
                .unwrap();
        assert_eq!(server_env_r2.round, 2);

        let r2_inner: RefreshR2Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&server_env_r2.payload).unwrap())
                .unwrap();
        let server_r2_pkg = dkg_r2::Package::deserialize(
            &hex::decode(&r2_inner.refresh_round2_pkg).unwrap(),
        )
        .unwrap();
        let mut client_r1_pkgs = BTreeMap::new();
        client_r1_pkgs.insert(server_id, server_r1_pkg);
        let (client_r2_secret, client_r2_pkgs) =
            refresh::refresh_dkg_part2(client_r1_secret, &client_r1_pkgs).unwrap();
        let client_r2_str = make_client_env(
            &recovery_session_id,
            ProtocolType::Rotation,
            2,
            &RefreshR2Payload {
                refresh_round2_pkg: hex::encode(
                    client_r2_pkgs.get(&server_id).unwrap().serialize().unwrap(),
                ),
            },
        );

        let (returned_mpc_key_id, address, rotation_version) =
            frost_recovery_round3(&recovery_session_id, &client_r2_str, &state)
                .await
                .unwrap();

        let mut r2_for_finalize = BTreeMap::new();
        r2_for_finalize.insert(server_id, server_r2_pkg);
        refresh::refresh_dkg_shares(
            &client_r2_secret,
            &client_r1_pkgs,
            &r2_for_finalize,
            client_pub_key_pkg,
            client_key_pkg,
        )
        .unwrap();

        assert_eq!(returned_mpc_key_id, mpc_key_id);
        assert!(!address.is_empty());
        assert_eq!(rotation_version, 2);
        assert!(!state.frost_recovery_sessions.contains_key(&recovery_session_id));
    }

    async fn run_one_recovery(
        state: &AppState,
        mpc_key_id: &str,
        client_key_pkg: frost_ed25519::keys::KeyPackage,
        client_pub_key_pkg: frost_ed25519::keys::PublicKeyPackage,
    ) -> (
        frost_ed25519::keys::KeyPackage,
        frost_ed25519::keys::PublicKeyPackage,
        i32,
    ) {
        use frost_ed25519::keys::refresh;

        let mut rng = rand::thread_rng();
        let client_id = Identifier::try_from(1u16).unwrap();
        let server_id = Identifier::try_from(2u16).unwrap();

        let (sid, srv_r1) = frost_recovery_round1(mpc_key_id, state).await.unwrap();
        let r1_inner: RefreshR1Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&srv_r1.payload).unwrap()).unwrap();
        let srv_r1_pkg = dkg_r1::Package::deserialize(
            &hex::decode(&r1_inner.refresh_round1_pkg).unwrap(),
        )
        .unwrap();
        let (cli_r1_secret, cli_r1_pkg) =
            refresh::refresh_dkg_part1(client_id, 2, 2, &mut rng).unwrap();
        let cli_r1_str = make_client_env(
            &sid,
            ProtocolType::Rotation,
            1,
            &RefreshR1Payload {
                refresh_round1_pkg: hex::encode(cli_r1_pkg.serialize().unwrap()),
            },
        );

        let srv_r2 = frost_recovery_round2(&sid, &cli_r1_str, state).await.unwrap();
        let r2_inner: RefreshR2Payload =
            serde_json::from_slice(&BASE64_STANDARD.decode(&srv_r2.payload).unwrap()).unwrap();
        let srv_r2_pkg = dkg_r2::Package::deserialize(
            &hex::decode(&r2_inner.refresh_round2_pkg).unwrap(),
        )
        .unwrap();
        let mut r1_pkgs = BTreeMap::new();
        r1_pkgs.insert(server_id, srv_r1_pkg);
        let (cli_r2_secret, cli_r2_pkgs) =
            refresh::refresh_dkg_part2(cli_r1_secret, &r1_pkgs).unwrap();
        let cli_r2_str = make_client_env(
            &sid,
            ProtocolType::Rotation,
            2,
            &RefreshR2Payload {
                refresh_round2_pkg: hex::encode(
                    cli_r2_pkgs.get(&server_id).unwrap().serialize().unwrap(),
                ),
            },
        );

        let (_, _, rotation_version) =
            frost_recovery_round3(&sid, &cli_r2_str, state).await.unwrap();
        let mut r2_fin = BTreeMap::new();
        r2_fin.insert(server_id, srv_r2_pkg);
        let (new_cli_kp, new_cli_pkp) = refresh::refresh_dkg_shares(
            &cli_r2_secret,
            &r1_pkgs,
            &r2_fin,
            client_pub_key_pkg,
            client_key_pkg,
        )
        .unwrap();

        (new_cli_kp, new_cli_pkp, rotation_version)
    }

    #[tokio::test]
    async fn test_frost_recovery_rotation_version_increments() {
        let (state, mpc_key_id, mut kp, mut pkp) = run_keygen().await;
        assert_eq!(
            state.frost_keystore.get(&mpc_key_id).unwrap().rotation_version,
            1
        );
        for expected in 2..=4 {
            let (new_kp, new_pkp, rv) =
                run_one_recovery(&state, &mpc_key_id, kp, pkp).await;
            assert_eq!(rv, expected);
            kp = new_kp;
            pkp = new_pkp;
        }
    }

    #[tokio::test]
    async fn test_frost_export_and_sign_guard() {
        let (state, mpc_key_id, _client_key_pkg, _) = run_keygen().await;
        let mut rng = rand::thread_rng();

        let share_envelope = frost_export(&mpc_key_id, &state).unwrap();
        assert!(!share_envelope.is_empty());
        let raw = BASE64_STANDARD.decode(&share_envelope).unwrap();
        let env: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(env["v"], 2);
        assert_eq!(env["curve"], "ed25519");
        let share_inner_raw =
            BASE64_STANDARD.decode(env["share"].as_str().unwrap()).unwrap();
        let mat: serde_json::Value = serde_json::from_slice(&share_inner_raw).unwrap();
        assert!(!mat["kp"].as_str().unwrap().is_empty());
        assert!(!mat["pkp"].as_str().unwrap().is_empty());
        assert!(state.frost_keystore.get(&mpc_key_id).unwrap().exported);
        assert!(frost_export(&mpc_key_id, &state).is_err());

        let mut fake_hash = [0u8; 32];
        rng.fill_bytes(&mut fake_hash);
        let result = frost_sign_round1(&mpc_key_id, &hex::encode(fake_hash), &state).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("exported"));
    }
}
