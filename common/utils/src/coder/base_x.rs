// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! BaseX encoding and decoding functions.

extern crate base64;

use crate::{coder::Coder, error::WedprError};

#[derive(Default, Debug, Clone)]
pub struct WedprBase64 {}

/// Implements Base64 as a Coder instance.
impl Coder for WedprBase64 {
    fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> String {
        base64::encode(input)
    }

    fn decode(&self, input: &str) -> Result<Vec<u8>, WedprError> {
        match base64::decode(input) {
            Ok(v) => return Ok(v),
            Err(_) => {
                wedpr_println!("Base64 decoding failed, input was: {}", input);
                return Err(WedprError::DecodeError);
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64() {
        let base64 = WedprBase64::default();
        let str = "g6sLGLyLvnkmE6V0Ico=";
        let bytes = base64.decode(&str).unwrap();
        let recovered_str = base64.encode(&bytes);
        assert_eq!(str, recovered_str);
    }
}
