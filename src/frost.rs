//! FROST-Ed25519 工具函数
//!
//! - encode_frost_key / decode_frost_key: ShareEnvelope v2 JSON 编解码
//! - derive_solana_address: 32 字节 verifying_key → base58 Solana 地址
//!
//! 与 ceres_mpc 客户端 ShareEnvelope::encode() / ::decode() 格式完全一致：
//! JSON { "v": 2, "curve": "ed25519", "share": "<base64 of serde_json(KeyPackage)>" }

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

/// 将 FROST KeyPackage 序列化为 ShareEnvelope v2 JSON 字符串。
///
/// 输出格式：`{"v":2,"curve":"ed25519","share":"<base64>"}`
/// 其中 share = BASE64(serde_json(key_pkg))
pub fn encode_frost_key(
    key_pkg: &frost_ed25519::keys::KeyPackage,
) -> Result<String, String> {
    let pkg_json = serde_json::to_string(key_pkg)
        .map_err(|e| format!("KeyPackage serialize failed: {e}"))?;
    let share_b64 = BASE64_STANDARD.encode(pkg_json.as_bytes());
    Ok(json!({"v": 2, "curve": "ed25519", "share": share_b64}).to_string())
}

/// 将 ShareEnvelope v2 JSON 字符串反序列化为 FROST KeyPackage。
///
/// 接受格式：`{"v":2,"curve":"ed25519","share":"<base64>"}`
/// （v 和 curve 字段目前仅解析 share，后续可加版本校验）
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
///
/// 与 ceres_mpc 客户端 derive_solana_address() 实现一致：
/// address = bs58::encode(verifying_key_bytes)
pub fn derive_solana_address(verifying_key_bytes: &[u8]) -> String {
    bs58::encode(verifying_key_bytes).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_solana_address_32_zero_bytes() {
        // 32 字节全零 → bs58 结果固定（验证函数可调用，非协议正确性测试）
        let addr = derive_solana_address(&[0u8; 32]);
        assert!(!addr.is_empty(), "address must not be empty");
        // base58 字母表不含 0/O/I/l
        assert!(!addr.contains('0'));
    }

    #[test]
    fn share_envelope_v2_json_shape() {
        // 构造一个假的 base64 share，验证 JSON 结构（不需要真实 KeyPackage）
        let fake_b64 = BASE64_STANDARD.encode(b"fake_pkg_json");
        let envelope = json!({"v": 2, "curve": "ed25519", "share": fake_b64}).to_string();
        let parsed: Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(parsed["v"], 2);
        assert_eq!(parsed["curve"], "ed25519");
        assert!(parsed["share"].is_string());
    }
}
