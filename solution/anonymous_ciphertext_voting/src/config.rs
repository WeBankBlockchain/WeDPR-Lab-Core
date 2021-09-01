// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Config of anonymous ciphertext voting (ACV) solution.

use wedpr_l_crypto_hash_keccak256::WedprKeccak256;
use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;

lazy_static! {
    /// Shared hash algorithm reference for quick implementation replacement.
    /// Other code should use this reference, and not directly use a specific implementation.
    pub static ref SIGNATURE_SECP256K1: WedprSecp256k1Recover =
        WedprSecp256k1Recover::default();
    pub static ref HASH_KECCAK256: WedprKeccak256 = WedprKeccak256::default();
}
