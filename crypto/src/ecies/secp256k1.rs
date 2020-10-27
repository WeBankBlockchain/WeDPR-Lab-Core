// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! ECIES functions on Secp256k1 curve.

extern crate ecies;

use wedpr_utils::error::WedprError;

use crate::ecies::Ecies;

#[derive(Default, Debug, Clone)]
pub struct WedprSecp256k1Ecies {}

/// Implements a ECIES instance on Secp256k1 curve.
impl Ecies for WedprSecp256k1Ecies {
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> Result<Vec<u8>, WedprError>
    {
        match ecies::encrypt(public_key.as_ref(), message.as_ref()) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => {
                wedpr_println!("secp256k1 ECIES encrypt failed");
                return Err(WedprError::FormatError);
            },
        }
    }

    fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        ciphertext: &T,
    ) -> Result<Vec<u8>, WedprError>
    {
        match ecies::decrypt(private_key.as_ref(), ciphertext.as_ref()) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => {
                wedpr_println!("secp256k1 ECIES decrypt failed");
                return Err(WedprError::FormatError);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constant::tests::{
            BASE64_ENCODED_TEST_MESSAGE, SECP256K1_TEST_PUBLIC_KEY,
            SECP256K1_TEST_SECRET_KEY,
        },
        utils::{bytes_to_string, string_to_bytes},
    };

    #[test]
    fn test_secp256k1_ecies() {
        let secp256k1_ecies = WedprSecp256k1Ecies::default();

        let encoded_msg = BASE64_ENCODED_TEST_MESSAGE;
        let ciphertext = secp256k1_ecies
            .encrypt(
                &string_to_bytes(SECP256K1_TEST_PUBLIC_KEY).unwrap(),
                &string_to_bytes(encoded_msg).unwrap(),
            )
            .unwrap();
        let decrypted_msg = secp256k1_ecies
            .decrypt(
                &string_to_bytes(SECP256K1_TEST_SECRET_KEY).unwrap(),
                &ciphertext,
            )
            .unwrap();
        assert_eq!(bytes_to_string(&decrypted_msg), encoded_msg);
    }
}
