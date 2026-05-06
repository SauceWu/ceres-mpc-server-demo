use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolType {
    Dkg,
    Dsg,
    Rotation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    pub session_id: String,
    pub protocol: ProtocolType,
    pub round: u8,
    pub from_id: u8,
    pub to_id: Option<u8>,
    pub payload_encoding: String,
    pub payload: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payloads: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
}

impl WireEnvelope {
    pub fn new(
        session_id: String,
        protocol: ProtocolType,
        round: u8,
        from_id: u8,
        to_id: Option<u8>,
        payload: String,
    ) -> Self {
        Self {
            session_id,
            protocol,
            round,
            from_id,
            to_id,
            payload_encoding: "cbor_base64".to_string(),
            payload,
            step: None,
            payloads: None,
            curve: None,
        }
    }

    pub fn new_batch(
        session_id: String,
        protocol: ProtocolType,
        round: u8,
        from_id: u8,
        to_id: Option<u8>,
        payloads: Vec<String>,
    ) -> Self {
        Self {
            session_id,
            protocol,
            round,
            from_id,
            to_id,
            payload_encoding: "cbor_base64".to_string(),
            payload: String::new(),
            step: None,
            payloads: Some(payloads),
            curve: None,
        }
    }

    pub fn decode_all_payloads(&self) -> Result<Vec<Vec<u8>>, String> {
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::Engine as _;
        if let Some(payloads) = &self.payloads {
            payloads.iter()
                .map(|p| BASE64_STANDARD.decode(p).map_err(|e| format!("base64 decode failed: {e}")))
                .collect()
        } else {
            let bytes = BASE64_STANDARD.decode(&self.payload)
                .map_err(|e| format!("base64 decode failed: {e}"))?;
            Ok(vec![bytes])
        }
    }
}

/// Unified keygen params: round=1 → start, round>1 → continue
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeygenParams {
    pub round: u8,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub client_payload: Option<String>,
    #[serde(default)]
    pub curve: Option<String>,
}

/// Unified sign params
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignParams {
    pub round: u8,
    #[serde(default)]
    pub mpc_key_id: Option<String>,
    #[serde(default)]
    pub message_hash: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub client_payload: Option<String>,
    #[serde(default)]
    pub curve: Option<String>,
}

/// Unified recovery params
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryParams {
    pub round: u8,
    #[serde(default)]
    pub mpc_key_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub client_payload: Option<String>,
    #[serde(default)]
    pub curve: Option<String>,
    #[serde(default)]
    pub current_rotation_version: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportKeyParams {
    pub mpc_key_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartResponse {
    pub session_id: String,
    pub server_payload: WireEnvelope,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeygenCompletedResponse {
    pub status: &'static str,
    pub mpc_key_id: String,
    pub address: String,
    pub public_key: String,
    pub curve: &'static str,
    pub threshold: i32,
    pub key_ref: String,
    pub backup_state: &'static str,
    pub rotation_version: i32,
    pub local_encrypted_share: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCompletedResponse {
    pub status: &'static str,
    pub mpc_key_id: String,
    pub address: String,
    pub public_key: String,
    pub rotation_version: i32,
    pub local_encrypted_share: String,
}

#[derive(Debug, Serialize)]
pub struct SignCompletedResponse {
    pub status: &'static str,
    pub r: String,
    pub s: String,
    pub recid: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportKeyResponse {
    pub server_share_private: String,
}
