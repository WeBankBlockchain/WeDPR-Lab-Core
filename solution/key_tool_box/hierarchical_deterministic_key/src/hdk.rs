// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Core functions of hierarchical deterministic key (HDK)

use wagyu_lib::{
    wordlist, HdkDerivationPath, HdkExtendedPrivateKey,
    HdkMnemonic, Mainnet,
};
use wagyu_model::{
    mnemonic::Mnemonic, ExtendedPrivateKey, MnemonicCount, MnemonicExtended,
};

use hex;
use rand::{rngs::StdRng, SeedableRng};
use std::{str, str::FromStr};

use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::hdk::ExtendedKeyPair;

/// Creates an English mnemonic for later generating the master key.
// TODO: Support more mnemonic languages.
pub fn create_mnemonic_en(word_count: u8) -> Result<String, WedprError> {
    let rng = &mut StdRng::from_entropy();
    let mnemonic =
        match HdkMnemonic::<Mainnet, wordlist::English>::new_with_count(
            rng, word_count,
        ) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "word_count check failed!, word_count = {}",
                    word_count
                );
                return Err(WedprError::ArgumentError);
            },
        };
    Ok(mnemonic.to_string())
}

/// Creates a master key from a English mnemonic and a password.
// TODO: Support more mnemonic languages.
pub fn create_master_key_en(
    password: &str,
    mnemonic_str: &str,
) -> Result<Vec<u8>, WedprError> {
    let mnemonic =
        match HdkMnemonic::<Mainnet, wordlist::English>::from_phrase(
            mnemonic_str,
        ) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "mnemonic check failed!, mnemonic = {}",
                    mnemonic_str
                );
                return Err(WedprError::ArgumentError);
            },
        };
    let master_extended_private_key = match mnemonic
        .to_extended_private_key(Some(password).clone())
    {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("password check failed!, password = {}", password);
            return Err(WedprError::ArgumentError);
        },
    };
    Ok(master_extended_private_key.to_string().as_bytes().to_vec())
}

/// Creates a key derivation path based on specific fields.
pub fn create_key_derivation_path(
    protocol_type: i32,
    asset_type: i32,
    account: i32,
    change: i32,
    address_index: i32,
) -> String {
    format!(
        "m/{}'/{}'/{}'/{}/{}",
        protocol_type, asset_type, account, change, address_index
    )
}

/// Derives an extended key pair based on a key derivation path.
pub fn derive_extended_key(
    master_key_bytes: &[u8],
    key_derivation_path: &str,
) -> Result<ExtendedKeyPair, WedprError> {
    let master_key_str = match str::from_utf8(&master_key_bytes) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!(
                "master_key_bytes check failed!, master_key_bytes = {:?}",
                master_key_bytes
            );
            return Err(WedprError::FormatError);
        },
    };
    let master_key =
        match HdkExtendedPrivateKey::<Mainnet>::from_str(master_key_str) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "master_key_str check failed!, master_key_str = {}",
                    master_key_str
                );
                return Err(WedprError::FormatError);
            },
        };

    let derivation_path =
        match HdkDerivationPath::from_str(&key_derivation_path) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "derivation_path_str check failed!, derivation_path_str = \
                     {}",
                    key_derivation_path
                );
                return Err(WedprError::FormatError);
            },
        };

    let extended_private_key = match master_key.derive(&derivation_path) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!(
                "derivation_path_str check failed!, derivation_path_str = {}",
                key_derivation_path
            );
            return Err(WedprError::FormatError);
        },
    };
    let private_key_hex = hex::encode(extended_private_key
        .to_private_key()
        .to_secp256k1_secret_key().serialize());

    let extended_private_key_bytes = match decode_hex_string(&private_key_hex) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!(
                "extended_private_key check failed!, extended_private_key = {}",
                extended_private_key
            );
            return Err(WedprError::DecodeError);
        },
    };

    let extended_public_key_uncompress_bytes = extended_private_key
        .to_public_key()
        .to_secp256k1_public_key()
        .serialize();
        // .serialize_uncompressed();

    // TODO: Replace with a better way to initialize PB if available.
    Ok(ExtendedKeyPair {
        extended_private_key: extended_private_key_bytes.to_vec(),
        extended_public_key: extended_public_key_uncompress_bytes.to_vec(),
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    })
}

/// Decodes hex string to bytes.
fn decode_hex_string(input: &str) -> Result<Vec<u8>, WedprError> {
    match hex::decode(input) {
        Ok(v) => return Ok(v),
        Err(_) => {
            wedpr_println!("hex decoding failed, input was: {}", input);
            return Err(WedprError::DecodeError);
        },
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_common_coder_base64::WedprBase64;
    use wedpr_l_crypto_ecies_secp256k1::WedprSecp256k1Ecies;
    use wedpr_l_crypto_hash_keccak256::WedprKeccak256;
    use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;
    use wedpr_l_utils::traits::{Coder, Ecies, Hash, Signature};

    #[test]
    fn test_hdk_usage() {
        // Create a master key.
        // let mnemonic = create_mnemonic_en(24).unwrap();
        let mnemonic = "engage wagon riot toe odor metal palm donor trumpet \
                        slight exercise taste burst sense smile curtain \
                        cheese sketch unable token suggest lab rain dolphin";
        // let password = "DO NOT USE REAL PASSWORD HERE";
        let password = "wi_wallet";

        let master_key = create_master_key_en(password, &mnemonic).unwrap();
        let coder = WedprBase64::default();
        println!("master_key = {:?}", coder.encode(&master_key));

        // Derive an extended key.
        let key_derivation_path =
            create_key_derivation_path(44, 513866, 1, 0, 1000);
        let extended_key =
            derive_extended_key(&master_key, &key_derivation_path).unwrap();
        let private_key = extended_key.get_extended_private_key();
        let public_key = extended_key.get_extended_public_key();

        println!("private_key = {:?}", hex::encode(private_key));
        println!("public_key = {:?}", hex::encode(public_key));

        // Test the derived key pair for signature functions.
        let message = "WeDPR TEST";
        let hash = WedprKeccak256::default();
        let msg_hash = hash.hash(message);

        let signature = WedprSecp256k1Recover::default();
        let msg_signature =
            signature.sign(&private_key, &msg_hash.as_slice()).unwrap();
        assert_eq!(
            true,
            signature.verify(
                &public_key,
                &msg_hash.as_slice(),
                &msg_signature.as_slice()
            )
        );

        // Test the derived key pair for ECIES functions.
        let ecies = WedprSecp256k1Ecies::default();
        let encrypted_msg_hash =
            ecies.encrypt(&public_key, &msg_hash.as_slice()).unwrap();
        let decrypted_msg_hash = ecies
            .decrypt(&private_key, &encrypted_msg_hash.as_slice())
            .unwrap();
        assert_eq!(decrypted_msg_hash, msg_hash);
    }
}
