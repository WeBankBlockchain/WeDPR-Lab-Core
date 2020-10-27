// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! ECIES (Elliptic Curve Integrated Encryption Scheme) functions.
//! ECIES is a public-key authenticated encryption scheme, which allows
//! using a public key to encrypt a message of any length and provide integrity
//! check.

use wedpr_utils::error::WedprError;

pub mod secp256k1;

/// Trait of a replaceable ECIES algorithm.
pub trait Ecies {
    /// Encrypts a message by ECIES with a public key.
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> Result<Vec<u8>, WedprError>;

    /// Decrypts a ciphertext by ECIES with a private key.
    fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        ciphertext: &T,
    ) -> Result<Vec<u8>, WedprError>;
}
