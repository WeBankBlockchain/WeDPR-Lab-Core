// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use wagyu_bitcoin::{
    wordlist::*, BitcoinDerivationPath, BitcoinExtendedPrivateKey,
    BitcoinMnemonic,
};

use hex;
use rand::{rngs::StdRng, SeedableRng};
use std::{str, str::FromStr};
use wagyu_bitcoin::Mainnet;
use wagyu_model::{
    mnemonic::Mnemonic, ExtendedPrivateKey, MnemonicCount, MnemonicExtended,
};
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::hdw::ExtendedKeyPair;

/// Creates a mnemonic for users to generate master key.
pub fn create_mnemonic_en(word_count: u8) -> Result<String, WedprError> {
    let rng = &mut StdRng::from_entropy();
    let mnemonic = match BitcoinMnemonic::<Mainnet, English>::new_with_count(
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

/// Creates master key for users to extended wallet keys.
pub fn create_master_key_en(
    password: &str,
    mnemonic_str: &str,
) -> Result<Vec<u8>, WedprError> {
    let mnemonic =
        match BitcoinMnemonic::<Mainnet, English>::from_phrase(mnemonic_str) {
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

/// Derive extended keys for users to send transaction.
pub fn derive_extended_key(
    master_key_bytes: &[u8],
    protocol_type: i32,
    asset_type: i32,
    account: i32,
    change: i32,
    address_index: i32,
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
        match BitcoinExtendedPrivateKey::<Mainnet>::from_str(master_key_str) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "master_key_str check failed!, master_key_str = {}",
                    master_key_str
                );
                return Err(WedprError::FormatError);
            },
        };
    let derivation_path_str = format!(
        "m/{}'/{}'/{}'/{}/{}",
        protocol_type, asset_type, account, change, address_index
    );
    let derivation_path =
        match BitcoinDerivationPath::from_str(&derivation_path_str) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "derivation_path_str check failed!, derivation_path_str = \
                     {}",
                    derivation_path_str
                );
                return Err(WedprError::FormatError);
            },
        };

    let extended_private_key = match master_key.derive(&derivation_path) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!(
                "derivation_path_str check failed!, derivation_path_str = {}",
                derivation_path_str
            );
            return Err(WedprError::FormatError);
        },
    };
    let extended_public_key_uncompress_bytes = extended_private_key
        .to_public_key()
        .to_secp256k1_public_key()
        .serialize_uncompressed();
    // Convert to FISCO-BCOS-compatible key pair format.
    let fisco_private_key = extended_private_key
        .to_private_key()
        .to_secp256k1_secret_key()
        .to_string();

    let extended_private_key_bytes = match decode_hex_string(&fisco_private_key)
    {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!(
                "extended_private_key check failed!, extended_private_key = {}",
                extended_private_key
            );
            return Err(WedprError::DecodeError);
        },
    };
    Ok(ExtendedKeyPair {
        extended_private_key: extended_private_key_bytes.to_vec(),
        extended_public_key: extended_public_key_uncompress_bytes.to_vec(),
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    })
}

/// Decoded wagyu hex secret key.
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
    use wedpr_l_crypto_ecies_secp256k1::WedprSecp256k1Ecies;
    use wedpr_l_crypto_hash_keccak256::WedprKeccak256;
    use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;
    use wedpr_l_utils::traits::{Ecies, Hash, Signature};

    #[test]
    fn test_hd_wallet() {
        let mnemonic = create_mnemonic_en(24).unwrap();
        let ecies = WedprSecp256k1Ecies::default();
        let hash_obj = WedprKeccak256::default();
        let signature = WedprSecp256k1Recover::default();
        let password = "123456";
        let master_key = create_master_key_en(password, &mnemonic).unwrap();
        let extended_key =
            derive_extended_key(&master_key, 44, 1, 1, 1, 0).unwrap();
        let message = "wedpr test";
        let hash = hash_obj.hash(message);
        let private_key = extended_key.get_extended_private_key();
        let public_key = extended_key.get_extended_public_key();
        let sign = signature.sign(&private_key, &hash.as_slice()).unwrap();
        assert_eq!(
            true,
            signature.verify(&public_key, &hash.as_slice(), &sign.as_slice())
        );
        let encrypt_message =
            ecies.encrypt(&public_key, &hash.as_slice()).unwrap();
        let decrypt_message = ecies
            .decrypt(&private_key, &encrypt_message.as_slice())
            .unwrap();
        assert_eq!(decrypt_message, hash);
    }
}
