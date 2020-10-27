// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Basic encoding and decoding functions.

extern crate hex;

use crate::{coder::Coder, error::WedprError};

#[derive(Default, Debug, Clone)]
pub struct WedprHex {}

/// Implements Hex as a Coder instance.
impl Coder for WedprHex {
    fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> String {
        hex::encode(input)
    }

    fn decode(&self, input: &str) -> Result<Vec<u8>, WedprError> {
        match hex::decode(input) {
            Ok(v) => return Ok(v),
            Err(_) => {
                wedpr_println!("hex decoding failed, input was: {}", input);
                return Err(WedprError::DecodeError);
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let hex = WedprHex::default();
        let str = "5c74d17c6a";
        let bytes = hex.decode(&str).unwrap();
        let recovered_str = hex.encode(&bytes);
        assert_eq!(str, recovered_str);
    }
}
