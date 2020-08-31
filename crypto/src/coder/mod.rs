// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Data encoding and decoding functions.

pub mod base_x;

use wedpr_utils::error::WedprError;

/// Trait of a replaceable coder algorithm.
pub trait Coder {
    /// Converts bytes to an encoded string.
    fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> String;
    /// Decodes an encoded string to a bytes vector.
    fn decode(&self, input: &str) -> Result<Vec<u8>, WedprError>;
}
