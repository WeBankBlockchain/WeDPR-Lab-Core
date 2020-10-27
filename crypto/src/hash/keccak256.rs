// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Keccak256 hash functions.

extern crate sha3;
use sha3::{Digest, Keccak256};

use crate::hash::Hash;

#[derive(Default, Debug, Clone)]
pub struct WedprKeccak256 {}

/// Implements FISCO-BCOS-compatible Keccak256 as a Hash instance.
impl Hash for WedprKeccak256 {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Keccak256::default();
        hash_algorithm.input(input);
        hash_algorithm.result().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constant::tests::BASE64_ENCODED_TEST_MESSAGE,
        utils::{bytes_to_string, string_to_bytes},
    };

    #[test]
    fn test_keccak256() {
        let keccak256 = WedprKeccak256::default();
        let msg = BASE64_ENCODED_TEST_MESSAGE;
        let expected_hash = "5S04Vv6HBCWG6xNARqwPb294Hz/3BlaFVwKvAJByd9Q=";
        assert_eq!(
            expected_hash,
            bytes_to_string(&keccak256.hash(&string_to_bytes(&msg).unwrap()))
        );
    }
}
