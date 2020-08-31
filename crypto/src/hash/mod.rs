// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Data hash functions.

pub mod keccak256;

/// Trait of a replaceable hash algorithm.
pub trait Hash {
    /// Generates a fixed length hash bytes vector from any string.
    fn hash(&self, msg: &str) -> Vec<u8>;
}
