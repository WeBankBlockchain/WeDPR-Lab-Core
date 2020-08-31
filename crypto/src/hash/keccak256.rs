// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Keccak256 hash functions.

extern crate sha3;
use sha3::{Digest, Keccak256};

use crate::hash::Hash;

#[derive(Default, Debug, Clone)]
pub struct WedprKeccak256 {}

/// Implements FISCO-BCOS-compatible Keccak256 as a Hash instance.
impl Hash for WedprKeccak256 {
    fn hash(&self, msg: &str) -> Vec<u8> {
        let mut mes = Keccak256::default();
        mes.input(msg);
        mes.result().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bytes_to_string;

    #[test]
    fn test_keccak256() {
        let keccak256 = WedprKeccak256::default();
        let msg = "WeDPR";
        let computed_hash = bytes_to_string(&keccak256.hash(msg));
        let expected_hash = "g6sLGLyLvnkOSvBcQdKNSPx8m4XmAogueNMmE6V0Ico=";
        assert_eq!(expected_hash, computed_hash);
    }
}
