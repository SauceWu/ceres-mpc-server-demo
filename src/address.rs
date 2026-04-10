use sha3::{Digest, Keccak256};

pub fn derive_evm_address(uncompressed_pubkey: &[u8]) -> Result<String, String> {
    if uncompressed_pubkey.len() != 65 || uncompressed_pubkey[0] != 0x04 {
        return Err("public key must be uncompressed secp256k1 (65 bytes)".to_string());
    }

    let hash = Keccak256::digest(&uncompressed_pubkey[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}
