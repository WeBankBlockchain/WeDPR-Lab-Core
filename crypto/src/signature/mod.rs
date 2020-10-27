// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Data signature functions.

use wedpr_utils::error::WedprError;

pub mod secp256k1;

/// Trait of a replaceable signature algorithm.
pub trait Signature {
    /// Signs a message hash with the private key.
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError>;

    /// Verifies a message hash with the public key.
    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        msg_hash: &T,
        signature: &T,
    ) -> bool;

    /// Generates a new key pair for signature algorithm.
    // TODO: Replace output list with a struct or protobuf.
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
}
