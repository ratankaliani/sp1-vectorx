use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub mod types;

/// This function is useful for verifying that a Ed25519 signature is valid, it will panic if the signature is not valid
pub fn verify_signature(pubkey_bytes: &[u8; 32], signed_message: &[u8], signature: &[u8; 64]) {
    let pubkey = VerifyingKey::from_bytes(pubkey_bytes).unwrap();
    let verified = pubkey.verify(signed_message, &Signature::from_bytes(signature));
    if verified.is_err() {
        panic!("Signature is not valid");
    }
}
