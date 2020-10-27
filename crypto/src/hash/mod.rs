// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Data hash functions.

pub mod keccak256;

/// Trait of a replaceable hash algorithm.
pub trait Hash {
    /// Generates a fixed length hash bytes vector from a bytes array of any
    /// length.
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8>;
}
