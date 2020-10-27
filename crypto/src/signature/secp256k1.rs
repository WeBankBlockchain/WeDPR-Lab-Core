// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Secp256k1 signature functions.

use wedpr_utils::error::WedprError;
extern crate secp256k1;
use self::secp256k1::{
    recovery::{RecoverableSignature, RecoveryId},
    Message, PublicKey, SecretKey,
};

use crate::{
    constant::{SECP256K1_ALL, SECP256K1_VERIFY},
    signature::Signature,
};

#[derive(Default, Debug, Clone)]
pub struct WedprSecp256k1Recover {}

pub const FISCO_BCOS_SIGNATURE_DATA_LENGTH: usize = 65;
pub const FISCO_BCOS_SIGNATURE_END_INDEX: usize =
    FISCO_BCOS_SIGNATURE_DATA_LENGTH - 1;

/// Implements FISCO-BCOS-compatible Secp256k1 as a Signature instance.
/// The signature data contains two parts:
/// sig\[0..64\): signature for the message hash.
/// sig\[64\]: recovery id.
impl Signature for WedprSecp256k1Recover {
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError>
    {
        let secret_key = match SecretKey::from_slice(&private_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("Parsing private key failed");
                return Err(WedprError::FormatError);
            },
        };
        // Message hash length for Secp256k1 signature should be 32 bytes.
        let msg_hash_obj = match Message::from_slice(&msg_hash.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("Parsing message hash failed");
                return Err(WedprError::FormatError);
            },
        };
        let signature_obj =
            SECP256K1_ALL.sign_recoverable(&msg_hash_obj, &secret_key);
        let (recid, signature_bytes) = &signature_obj.serialize_compact();
        // Append recovery id to the end of signature bytes.
        let mut signature_output = signature_bytes.to_vec();
        signature_output.push(recid.to_i32() as u8);
        Ok(signature_output)
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        msg_hash: &T,
        signature: &T,
    ) -> bool
    {
        // Message hash length for Secp256k1 signature should be 32 bytes.
        let msg_hash_obj = match Message::from_slice(&msg_hash.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("Parsing message hash failed");
                return false;
            },
        };
        let inputted_pub_key = match PublicKey::from_slice(&public_key.as_ref())
        {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("Parsing public key failed");
                return false;
            },
        };
        if signature.as_ref().len() != FISCO_BCOS_SIGNATURE_DATA_LENGTH {
            wedpr_println!("Signature length is not 65");
            return false;
        };
        let recid = match RecoveryId::from_i32(
            signature.as_ref()[FISCO_BCOS_SIGNATURE_END_INDEX] as i32,
        ) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("Parsing RecoveryId failed");
                return false;
            },
        };

        // The last byte is recovery id, we only need to get the first 64 bytes
        // for signature data.
        let signature_byte =
            &signature.as_ref()[0..FISCO_BCOS_SIGNATURE_END_INDEX];

        let get_sign_final =
            match RecoverableSignature::from_compact(signature_byte, recid) {
                Ok(v) => v,
                Err(_) => {
                    wedpr_println!("Signature from_compact failed");
                    return false;
                },
            };
        let recovered_public_key =
            match SECP256K1_VERIFY.recover(&msg_hash_obj, &get_sign_final) {
                Ok(v) => v,
                Err(_) => {
                    wedpr_println!("Signature recover failed");
                    return false;
                },
            };
        if inputted_pub_key != recovered_public_key {
            wedpr_println!("Matching signature public key failed");
            return false;
        }
        return true;
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        loop {
            // "rand" feature of secp256k1 need to be enabled for this.
            let (secret_key, public_key) =
                SECP256K1_ALL.generate_keypair(&mut rng);
            // Drop weak secret key.
            if secret_key[0] > 15 {
                return (
                    public_key.serialize_uncompressed().to_vec(),
                    secret_key.as_ref().to_vec(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constant::{
            tests::{SECP256K1_TEST_PUBLIC_KEY, SECP256K1_TEST_SECRET_KEY},
            HASH,
        },
        hash::Hash,
        utils::string_to_bytes,
    };

    #[test]
    fn test_secp256k1_recover() {
        let secp256k1_recover = WedprSecp256k1Recover::default();

        // The message hash (NOT the original message) is required for
        // generating a valid signature.
        let msg = "WeDPR".as_bytes();
        let msg_hash = HASH.hash(msg);

        let signature = secp256k1_recover
            .sign(
                &string_to_bytes(SECP256K1_TEST_SECRET_KEY).unwrap(),
                &msg_hash,
            )
            .unwrap();
        assert_eq!(
            true,
            secp256k1_recover.verify(
                &string_to_bytes(SECP256K1_TEST_PUBLIC_KEY).unwrap(),
                &msg_hash,
                &signature
            )
        );
    }
}
