// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Data signature functions.

use wedpr_utils::error::WedprError;

pub mod secp256k1;

/// Trait of a replaceable signature algorithm.
pub trait Signature {
    /// Signs a message hash with the private key.
    fn sign(
        &self,
        private_key: &str,
        msg_hash_str: &str,
    ) -> Result<String, WedprError>;
    /// Verifies a message hash with the public key.
    fn verify(
        &self,
        public_key: &str,
        msg_hash_str: &str,
        signature: &str,
    ) -> bool;
}
