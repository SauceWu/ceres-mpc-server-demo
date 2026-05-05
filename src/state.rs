use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;

use dashmap::DashMap;

pub const SESSION_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Keygen,
    Sign,
    Recovery,
}

impl ProtocolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keygen => "dkg",
            Self::Sign => "dsg",
            Self::Recovery => "rotation",
        }
    }
}

pub type KeygenTaskResult = Result<Vec<u8>, String>;
pub type RecoveryTaskResult = Result<Vec<u8>, String>;
pub type SignTaskResult = Result<(Vec<u8>, u8), String>;

pub struct KeygenSession {
    pub tx_in: mpsc::Sender<Vec<u8>>,
    pub rx_out: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    pub task_handle: Mutex<Option<JoinHandle<KeygenTaskResult>>>,
    pub created_at: Instant,
    pub round_complete: Arc<Notify>,
}

pub struct RecoverySession {
    pub tx_in: mpsc::Sender<Vec<u8>>,
    pub rx_out: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    pub task_handle: Mutex<Option<JoinHandle<RecoveryTaskResult>>>,
    pub created_at: Instant,
    pub mpc_key_id: String,
    pub round_complete: Arc<Notify>,
}

pub struct SignSession {
    pub tx_in: mpsc::Sender<Vec<u8>>,
    pub rx_out: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    pub task_handle: Mutex<Option<JoinHandle<SignTaskResult>>>,
    pub created_at: Instant,
    pub round_complete: Arc<Notify>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRecordSummary {
    pub mpc_key_id: String,
    pub address: String,
    pub public_key: String,
    pub rotation_version: i32,
}

pub struct KeyRecord {
    pub mpc_key_id: String,
    pub keyshare_bytes: Vec<u8>,
    pub address: String,
    pub public_key: String,
    pub rotation_version: i32,
    pub exported: bool,
}

impl KeyRecord {
    pub fn summary(&self) -> KeyRecordSummary {
        KeyRecordSummary {
            mpc_key_id: self.mpc_key_id.clone(),
            address: self.address.clone(),
            public_key: self.public_key.clone(),
            rotation_version: self.rotation_version,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub keygen_sessions: Arc<DashMap<String, Arc<KeygenSession>>>,
    pub sign_sessions: Arc<DashMap<String, Arc<SignSession>>>,
    pub recovery_sessions: Arc<DashMap<String, Arc<RecoverySession>>>,
    pub keystore: Arc<DashMap<String, KeyRecord>>,
    pub frost_keygen_sessions: Arc<DashMap<String, Arc<FrostKeygenSession>>>,
    pub frost_sign_sessions: Arc<DashMap<String, Arc<FrostSignSession>>>,
    pub frost_recovery_sessions: Arc<DashMap<String, Arc<FrostRecoverySession>>>,
    pub frost_keystore: Arc<DashMap<String, FrostKeyRecord>>,
}

// ── FROST-Ed25519 session types ──────────────────────────────────

use frost_ed25519::keys::dkg::{round1 as frost_r1, round2 as frost_r2};

pub struct FrostKeygenSession {
    pub round1_secret: tokio::sync::Mutex<Option<frost_r1::SecretPackage>>,
    pub round2_secret: tokio::sync::Mutex<Option<frost_r2::SecretPackage>>,
    pub created_at: Instant,
}

pub struct FrostSignSession {
    pub nonces: tokio::sync::Mutex<Option<frost_ed25519::round1::SigningNonces>>,
    pub message_hash: [u8; 32],
    pub mpc_key_id: String,
    pub created_at: Instant,
}

pub struct FrostRecoverySession {
    pub round1_secret: tokio::sync::Mutex<Option<frost_r1::SecretPackage>>,
    pub round2_secret: tokio::sync::Mutex<Option<frost_r2::SecretPackage>>,
    pub mpc_key_id: String,
    pub created_at: Instant,
}

pub struct FrostKeyRecord {
    pub mpc_key_id: String,
    pub key_package: frost_ed25519::keys::KeyPackage,
    pub public_key_package: frost_ed25519::keys::PublicKeyPackage,
    pub address: String,
    pub rotation_version: i32,
    pub exported: bool,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            keygen_sessions: Arc::new(DashMap::new()),
            sign_sessions: Arc::new(DashMap::new()),
            recovery_sessions: Arc::new(DashMap::new()),
            keystore: Arc::new(DashMap::new()),
            frost_keygen_sessions: Arc::new(DashMap::new()),
            frost_sign_sessions: Arc::new(DashMap::new()),
            frost_recovery_sessions: Arc::new(DashMap::new()),
            frost_keystore: Arc::new(DashMap::new()),
        }
    }

    pub fn spawn_cleanup_task(&self) {
        let keygen_sessions = Arc::clone(&self.keygen_sessions);
        let sign_sessions = Arc::clone(&self.sign_sessions);
        let recovery_sessions = Arc::clone(&self.recovery_sessions);
        let frost_keygen_sessions = Arc::clone(&self.frost_keygen_sessions);
        let frost_sign_sessions = Arc::clone(&self.frost_sign_sessions);
        let frost_recovery_sessions = Arc::clone(&self.frost_recovery_sessions);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = Instant::now();
                keygen_sessions
                    .retain(|_, session| now.duration_since(session.created_at) <= SESSION_TTL);
                sign_sessions
                    .retain(|_, session| now.duration_since(session.created_at) <= SESSION_TTL);
                recovery_sessions
                    .retain(|_, session| now.duration_since(session.created_at) <= SESSION_TTL);
                frost_keygen_sessions
                    .retain(|_, session| now.duration_since(session.created_at) <= SESSION_TTL);
                frost_sign_sessions
                    .retain(|_, session| now.duration_since(session.created_at) <= SESSION_TTL);
                frost_recovery_sessions
                    .retain(|_, session| now.duration_since(session.created_at) <= SESSION_TTL);
            }
        });
    }
}
