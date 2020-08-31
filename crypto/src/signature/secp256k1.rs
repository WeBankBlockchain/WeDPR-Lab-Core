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
    utils::{bytes_to_string, string_to_bytes},
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
    fn sign(
        &self,
        private_key: &str,
        msg_hash_str: &str,
    ) -> Result<String, WedprError>
    {
        let msg_hash = string_to_bytes(msg_hash_str)?;
        let sk_str_bytes = string_to_bytes(private_key)?;
        let secret_key = match SecretKey::from_slice(&sk_str_bytes) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("Getting private key failed");
                return Err(WedprError::FormatError);
            },
        };
        let message_send = Message::from_slice(&msg_hash).expect("32 bytes");
        let sig = SECP256K1_ALL.sign_recoverable(&message_send, &secret_key);
        let (recid, signature_bytes) = &sig.serialize_compact();
        let mut vec_sig = signature_bytes.to_vec();
        vec_sig.push(recid.to_i32() as u8);
        Ok(bytes_to_string(&vec_sig))
    }

    fn verify(
        &self,
        public_key: &str,
        msg_hash_str: &str,
        signature: &str,
    ) -> bool
    {
        let msg_hash = string_to_bytes!(msg_hash_str);

        let message_receive = Message::from_slice(&msg_hash).expect("32 bytes");
        let pk_str_bytes = string_to_bytes!(&public_key);
        let pub_str_get = match PublicKey::from_slice(&pk_str_bytes) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("Parsing public key to failed");
                return false;
            },
        };
        let sig_result_hex = string_to_bytes!(signature);
        if sig_result_hex.len() != FISCO_BCOS_SIGNATURE_DATA_LENGTH {
            wedpr_println!("Sigature length is not 65");
            return false;
        };
        let recid = match RecoveryId::from_i32(
            sig_result_hex[FISCO_BCOS_SIGNATURE_END_INDEX] as i32,
        ) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("Parsing RecoveryId failed");
                return false;
            },
        };

        // The last byte is recovery id, we only need to get the first 64 bytes
        // for signature data.
        let signature_byte = &sig_result_hex[0..FISCO_BCOS_SIGNATURE_END_INDEX];

        let get_sign_final =
            match RecoverableSignature::from_compact(signature_byte, recid) {
                Ok(v) => v,
                Err(_) => {
                    wedpr_println!("Signature from_compact failed");
                    return false;
                },
            };
        let pk_recover_get =
            match SECP256K1_VERIFY.recover(&message_receive, &get_sign_final) {
                Ok(v) => v,
                Err(_) => {
                    wedpr_println!("Signature recover failed");
                    return false;
                },
            };
        if pub_str_get != pk_recover_get {
            wedpr_println!("Signature recover failed");
            return false;
        }
        return true;
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
        utils::bytes_to_string,
    };

    #[test]
    fn test_secp256k1_recover() {
        let secp256k1_recover = WedprSecp256k1Recover::default();

        // The message hash (NOT the original message) is required for
        // generating a valid signature.
        let msg = "WeDPR";
        let msg_hash_str = bytes_to_string(&HASH.hash(msg));

        let signature = secp256k1_recover
            .sign(SECP256K1_TEST_SECRET_KEY, &msg_hash_str)
            .unwrap();
        assert_eq!(
            true,
            secp256k1_recover.verify(
                SECP256K1_TEST_PUBLIC_KEY,
                &msg_hash_str,
                &signature
            )
        );
    }
}
