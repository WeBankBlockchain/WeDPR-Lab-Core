// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Common utility functions.

use crate::{
    constant::{CODER, HASH, RISTRETTO_POINT_SIZE_IN_BYTES},
    hash::Hash,
};
use bulletproofs::RangeProof;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use std::convert::TryInto;
use wedpr_utils::{coder::Coder, error::WedprError};

/// Converts bytes to an encoded string.
pub fn bytes_to_string<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    CODER.encode(input)
}

/// Converts an encoded string to a bytes vector.
pub fn string_to_bytes(input: &str) -> Result<Vec<u8>, WedprError> {
    CODER.decode(input)
}

/// Converts bytes to a UTF8 string.
pub fn bytes_to_utf8<T: ?Sized + AsRef<[u8]>>(
    input: &T,
) -> Result<String, WedprError> {
    match String::from_utf8(input.as_ref().to_vec()) {
        Ok(v) => Ok(v),
        Err(_) => {
            wedpr_println!(
                "UTF8 encoding failed, input was: {}",
                bytes_to_string(input)
            );
            return Err(WedprError::DecodeError);
        },
    }
}

/// Converts a UTF8 string to a bytes vector.
pub fn utf8_to_bytes(input: &str) -> Vec<u8> {
    String::from(input).into_bytes()
}

/// Converts Scalar to an encoded string.
pub fn scalar_to_string(number: &Scalar) -> String {
    bytes_to_string(&number.to_bytes())
}

/// Converts an encoded string to Scalar.
pub fn string_to_scalar(num: &str) -> Result<Scalar, WedprError> {
    let num_u8 = match string_to_bytes(num) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("string_to_scalar failed, string: {}", num);
            return Err(WedprError::FormatError);
        },
    };
    let get_num_u8 = to_bytes32_slice(&num_u8)?;
    let scalar_num = Scalar::from_bits(*get_num_u8);
    Ok(scalar_num)
}

/// Converts RistrettoPoint to an encoded string.
pub fn point_to_string(point: &RistrettoPoint) -> String {
    bytes_to_string(&point.compress().to_bytes())
}

/// Converts an encoded string to RistrettoPoint.
pub fn string_to_point(point: &str) -> Result<RistrettoPoint, WedprError> {
    let decode_tmp = string_to_bytes(point)?;
    if decode_tmp.len() != RISTRETTO_POINT_SIZE_IN_BYTES {
        wedpr_println!("string_to_point decode failed");
        return Err(WedprError::FormatError);
    }
    let point_value =
        match CompressedRistretto::from_slice(&decode_tmp).decompress() {
            Some(v) => v,
            None => {
                wedpr_println!(
                    "string_to_point decompress CompressedRistretto failed"
                );
                return Err(WedprError::FormatError);
            },
        };

    Ok(point_value)
}

/// Converts RangeProof to an encoded string.
pub fn rangeproof_to_string(proof: &RangeProof) -> String {
    bytes_to_string(&proof.to_bytes())
}

/// Converts an arbitrary string to Scalar.
/// It will hash it first, and transform the numeric value of hash output to
/// Scalar.
pub fn hash_to_scalar(value: &str) -> Scalar {
    let mut array = [0; 32];
    array.clone_from_slice(&HASH.hash(value.as_bytes()));
    Scalar::from_bytes_mod_order(array)
}

/// Gets a random Scalar.
pub fn get_random_scalar() -> Scalar {
    Scalar::random(&mut rand::thread_rng())
}

/// Makes a commitment for value in point format.
pub fn make_commitment_point(
    value: u64,
    blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> RistrettoPoint {
    RistrettoPoint::multiscalar_mul(&[Scalar::from(value), *blinding], &[
        *value_basepoint,
        *blinding_basepoint,
    ])
}

// Private utility functions.

/// Extracts a slice of &[u8; 32] from the given slice.
fn to_bytes32_slice(barry: &[u8]) -> Result<&[u8; 32], WedprError> {
    let pop_u8 = match barry.try_into() {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };
    Ok(pop_u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_conversion() {
        let num = get_random_scalar();
        let num_str = scalar_to_string(&num);
        let recovered_num = string_to_scalar(&num_str).unwrap();
        assert_eq!(num, recovered_num);

        let bad_str = "bad";
        assert_eq!(
            WedprError::FormatError,
            string_to_scalar(bad_str).unwrap_err()
        );
    }

    #[test]
    pub fn test_bytes_conversion() {
        let str = "test";
        let bytes = string_to_bytes(&str).unwrap();
        let recovered_str = bytes_to_string(&bytes);
        assert_eq!(str, recovered_str);
    }

    #[test]
    pub fn test_utf8_conversion() {
        let str = "test";
        let bytes = utf8_to_bytes(&str);
        let recovered_str = bytes_to_utf8(&bytes).unwrap();
        assert_eq!(str, recovered_str);
    }

    #[test]
    pub fn test_point_conversion() {
        let point = RistrettoPoint::default();
        let point_str = point_to_string(&point);
        let recovered_point = string_to_point(&point_str).unwrap();
        assert_eq!(point, recovered_point);
    }
}
