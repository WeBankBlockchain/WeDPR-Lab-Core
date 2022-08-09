// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Config of anonymous ciphertext voting (ACV) solution.
#[cfg(feature = "wedpr_f_sm_signature")]
use wedpr_l_crypto_hash_sm3::WedprSm3;
#[cfg(feature = "wedpr_f_sm_signature")]
use wedpr_l_crypto_signature_sm2::WedprSm2p256v1;
#[cfg(feature = "wedpr_f_sm_signature")]
lazy_static! {
    /// Shared signature algorithm reference for quick implementation replacement.
    pub static ref SIGNATURE: WedprSm2p256v1 =
    WedprSm2p256v1::default();
    /// Shared hash algorithm reference for quick implementation replacement.
    pub static ref HASH: WedprSm3 = WedprSm3::default();
}

#[cfg(feature = "wedpr_f_secp256k1_signature")]
use wedpr_l_crypto_hash_keccak256::WedprKeccak256;
#[cfg(feature = "wedpr_f_secp256k1_signature")]
use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;
#[cfg(feature = "wedpr_f_secp256k1_signature")]
lazy_static! {
    /// Shared signature algorithm reference for quick implementation replacement.
    pub static ref SIGNATURE: WedprSecp256k1Recover =
       WedprSecp256k1Recover::default();
    /// Shared hash algorithm reference for quick implementation replacement.
    pub static ref HASH: WedprKeccak256 = WedprKeccak256::default();
}
