// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Zero-knowledge proof (ZKP) functions.

use crate::{
    constant::BASEPOINT_G2,
    utils::{
        get_random_scalar, hash_to_scalar, make_commitment_point,
        point_to_string, rangeproof_to_string, scalar_to_string,
        string_to_bytes, string_to_scalar,
    },
};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use merlin::Transcript;
use rand::thread_rng;
use wedpr_protos::generated::zkp::BalanceProof;
use wedpr_utils::error::WedprError;

/// Uses a smaller value to reduce time cost of using range proofs.
/// Uses a larger value to increase value limit of using range proofs.
/// This is a critical parameter which is recommended to be fixed to
/// prevent unexpected proof validity issues.
const RANGE_SIZE_IN_BITS: usize = 32;
const DEFAULT_BYTES_MESSAGE: &[u8] = b"WeDPR";

/// Proves whether a value belongs to (0, 2^RANGE_SIZE_IN_BITS - 1], and create
/// a commitment for the value. It returns:
/// 1) the encoded string for the proof.
/// 2) the point representing the commitment created for the value.
/// 3) the random blinding value used in the above commitment.
pub fn prove_value_range(value: u64) -> (String, RistrettoPoint, Scalar) {
    let blinding = Scalar::random(&mut thread_rng());
    let (proof_str, value_commitment_point) =
        prove_value_range_with_blinding(value, &blinding);

    (proof_str, value_commitment_point, blinding)
}

/// Proves whether a value belongs to (0, 2^RANGE_SIZE_IN_BITS - 1], and create
/// a commitment for the value with provided random blinding value. It returns:
/// 1) the encoded string for the proof.
/// 2) the point representing the commitment created for the value.
pub fn prove_value_range_with_blinding(
    value: u64,
    blinding: &Scalar,
) -> (String, RistrettoPoint) {
    let (proof_str, value_commitment_point) =
        prove_value_range_with_blinding_and_blinding_basepoint(
            value,
            &blinding,
            // Cannot use BASEPOINT_G1 which has already been used by
            // commitment generation.
            &BASEPOINT_G2,
        );
    (proof_str, value_commitment_point)
}

/// Proves whether a value belongs to (0, 2^RANGE_SIZE_IN_BITS - 1], and create
/// a commitment for the value with provided random blinding value and blinding
/// basepoint. It returns:
/// 1) the encoded string for the proof.
/// 2) the point representing the commitment created for the value.
pub fn prove_value_range_with_blinding_and_blinding_basepoint(
    value: u64,
    blinding: &Scalar,
    blinding_basepoint: &RistrettoPoint,
) -> (String, RistrettoPoint) {
    let mut pc_gens = PedersenGens::default();
    // Allow replacing the blinding basepoint for customized protocol design.
    pc_gens.B_blinding = blinding_basepoint.clone();
    let bp_gens = BulletproofGens::new(RANGE_SIZE_IN_BITS, 1);
    let secret_value = value;
    let mut prover_transcript = Transcript::new(DEFAULT_BYTES_MESSAGE);
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        RANGE_SIZE_IN_BITS,
    )
    .expect("RangeProof prove_single should not fail");

    (
        rangeproof_to_string(&proof),
        committed_value
            .decompress()
            .expect("CompressedRistretto decompress should not fail"),
    )
}

/// Verifies whether a value embedded in the commentment belongs to
/// (0, 2^RANGE_SIZE_IN_BITS - 1].
pub fn verify_value_range(commitment: &RistrettoPoint, proof: &str) -> bool {
    // Cannot use BASEPOINT_G1 which has already been used by commitment
    // generation.
    verify_value_range_with_blinding_basepoint(commitment, proof, &BASEPOINT_G2)
}

/// Verifies whether a value embedded in the commentment belongs to
/// (0, 2^RANGE_SIZE_IN_BITS - 1], and use provided blinding basepoint.
pub fn verify_value_range_with_blinding_basepoint(
    commitment: &RistrettoPoint,
    proof: &str,
    blinding_basepoint: &RistrettoPoint,
) -> bool {
    let mut pc_gens = PedersenGens::default();
    // Allow replacing the blinding basepoint for customized protocol design.
    pc_gens.B_blinding = blinding_basepoint.clone();
    let bp_gens = BulletproofGens::new(RANGE_SIZE_IN_BITS, 1);
    let mut verifier_transcript = Transcript::new(DEFAULT_BYTES_MESSAGE);
    let decode_proof_result = string_to_bytes!(proof);
    let get_proof = match RangeProof::from_bytes(&decode_proof_result) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("RangeProof from_bytes failed");
            return false;
        },
    };
    let commitment_value = commitment.compress();

    match get_proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &commitment_value,
        RANGE_SIZE_IN_BITS,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Proves whether all values in the list belongs to
/// (0, 2^RANGE_SIZE_IN_BITS - 1], and create commitments for them with provided
/// random blinding values and blinding basepoint.
/// It returns:
/// 1) the encoded string for the aggregated proof.
/// 2) the point list representing the commitments created for the values.
pub fn prove_value_range_in_batch(
    values: &[u64],
    blindings: &[Scalar],
    blinding_basepoint: &RistrettoPoint,
) -> Result<(String, Vec<RistrettoPoint>), WedprError> {
    // Two slices should have the same length, and the length should be a
    // multiple of 2.
    if values.len() != blindings.len() || values.len() & 0x1 != 0 {
        return Err(WedprError::ArgumentError);
    }
    let mut pc_gens = PedersenGens::default();
    // Allow replacing the blinding basepoint for customized protocol design.
    pc_gens.B_blinding = blinding_basepoint.clone();
    let bp_gens = BulletproofGens::new(RANGE_SIZE_IN_BITS, values.len());
    let mut prover_transcript = Transcript::new(DEFAULT_BYTES_MESSAGE);
    let (proof, committed_value) = match RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        values,
        &blindings,
        RANGE_SIZE_IN_BITS,
    ) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("prove_value_range_in_batch failed");
            return Err(WedprError::FormatError);
        },
    };
    let vector_commitment = committed_value
        .iter()
        .map(|i| {
            i.decompress()
                .expect("CompressedRistretto decompress should not fail")
        })
        .collect();
    Ok((rangeproof_to_string(&proof), vector_commitment))
}

/// Verifies whether all values embedded in the commentment list belongs to
/// (0, 2^RANGE_SIZE_IN_BITS - 1].
pub fn verify_value_range_in_batch(
    commitments: &Vec<RistrettoPoint>,
    proof: &str,
    blinding_basepoint: &RistrettoPoint,
) -> bool {
    let mut pc_gens = PedersenGens::default();
    // Allow replacing the blinding basepoint for customized protocol design.
    pc_gens.B_blinding = blinding_basepoint.clone();
    let bp_gens = BulletproofGens::new(RANGE_SIZE_IN_BITS, commitments.len());
    let mut verifier_transcript = Transcript::new(DEFAULT_BYTES_MESSAGE);
    let decode_proof_result = string_to_bytes!(proof);
    // The length of decode_proof_result should be a multiple of 32 bytes.
    let get_proof = match RangeProof::from_bytes(&decode_proof_result) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("RangeProof from_bytes failed");
            return false;
        },
    };

    let decode_commit: Vec<CompressedRistretto> =
        commitments.iter().map(|i| i.compress()).collect();

    match get_proof.verify_multiple(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &decode_commit,
        RANGE_SIZE_IN_BITS,
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Proves three commitments satisfying a sum relationship, i.e.
/// the values embedded in them satisfying c1_value + c2_value = c3_value.
/// c3_value is not in the argument list, and will be directly computed from
/// c1_value + c2_value.
/// c?_blinding are random blinding values used in the commitments.
/// The commitments (c?_value*value_basepoint+c?_blinding*blinding_basepoint)
/// are not in the argument list, as they are not directly used by the proof
/// generation.
/// It returns a proof for the above sum relationship.
pub fn prove_sum_relationship(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &Scalar,
    c2_blinding: &Scalar,
    c3_blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> BalanceProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let blinding_c = get_random_scalar();
    let blinding_d = get_random_scalar();
    let blinding_e = get_random_scalar();
    let c1_point = make_commitment_point(
        c1_value,
        &c1_blinding,
        &value_basepoint,
        &blinding_basepoint,
    );
    let c2_point = make_commitment_point(
        c2_value,
        &c2_blinding,
        &value_basepoint,
        &blinding_basepoint,
    );
    let c3_point = RistrettoPoint::multiscalar_mul(
        &[
            Scalar::from(c1_value) + Scalar::from(c2_value),
            *c3_blinding,
        ],
        &[*value_basepoint, *blinding_basepoint],
    );
    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t2_p = RistrettoPoint::multiscalar_mul(&[blinding_c, blinding_d], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t3_p = RistrettoPoint::multiscalar_mul(
        &[(blinding_a + blinding_c), blinding_e],
        &[*value_basepoint, *blinding_basepoint],
    );
    let hash_str = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        &point_to_string(&t1_p),
        &point_to_string(&t2_p),
        &point_to_string(&t3_p),
        &point_to_string(&c1_point),
        &point_to_string(&c2_point),
        &point_to_string(&c3_point),
        &point_to_string(&value_basepoint),
        &point_to_string(&blinding_basepoint)
    );
    let check = hash_to_scalar(&hash_str);
    let m1 = blinding_a - (check * (Scalar::from(c1_value)));
    let m2 = blinding_b - (check * c1_blinding);
    let m3 = blinding_c - (check * (Scalar::from(c2_value)));
    let m4 = blinding_d - (check * (c2_blinding));
    let m5 = blinding_e - (check * (c3_blinding));

    let mut proof = BalanceProof::new();
    proof.set_c(scalar_to_string(&check));
    proof.set_m1(scalar_to_string(&m1));
    proof.set_m2(scalar_to_string(&m2));
    proof.set_m3(scalar_to_string(&m3));
    proof.set_m4(scalar_to_string(&m4));
    proof.set_m5(scalar_to_string(&m5));
    proof
}

/// Verifies three commitments satisfying a sum relationship, i.e.
/// the values embedded in c1_point, c2_point, c3_point satisfying
/// c1_value + c2_value = c3_value.
pub fn verify_sum_relationship(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &BalanceProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> bool {
    let check = string_to_scalar!(proof.get_c());
    let m1 = string_to_scalar!(proof.get_m1());
    let m2 = string_to_scalar!(proof.get_m2());
    let m3 = string_to_scalar!(proof.get_m3());
    let m4 = string_to_scalar!(proof.get_m4());
    let m5 = string_to_scalar!(proof.get_m5());
    let t1_v = RistrettoPoint::multiscalar_mul(&[m1, m2, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c1_point,
    ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[m3, m4, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c2_point,
    ]);
    let t3_v = RistrettoPoint::multiscalar_mul(&[m1 + (m3), m5, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c3_point,
    ]);
    let hash_str = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        &point_to_string(&t1_v),
        &point_to_string(&t2_v),
        &point_to_string(&t3_v),
        &point_to_string(&c1_point),
        &point_to_string(&c2_point),
        &point_to_string(&c3_point),
        &point_to_string(&value_basepoint),
        &point_to_string(&blinding_basepoint)
    );

    let computed = hash_to_scalar(&hash_str);
    computed.eq(&check)
}

/// Proves three commitments satisfying a product relationship, i.e.
/// the values embedded in them satisfying c1_value * c2_value = c3_value.
/// c3_value is not in the argument list, and will be directly computed from
/// c1_value * c2_value.
/// c?_blinding are random blinding values used in the commitments.
/// The commitments (c?_value*value_basepoint+c?_blinding*blinding_basepoint)
/// are not in the argument list, as they are not directly used by the proof
/// generation.
/// It returns a proof for the above product relationship.
pub fn prove_product_relationship(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &Scalar,
    c2_blinding: &Scalar,
    c3_blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> BalanceProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let blinding_c = get_random_scalar();
    let blinding_d = get_random_scalar();
    let blinding_e = get_random_scalar();
    let c1_point = make_commitment_point(
        c1_value,
        &c1_blinding,
        &value_basepoint,
        &blinding_basepoint,
    );
    let c2_point = make_commitment_point(
        c2_value,
        &c2_blinding,
        &value_basepoint,
        &blinding_basepoint,
    );
    let c3_point = RistrettoPoint::multiscalar_mul(
        &[
            Scalar::from(c1_value) * Scalar::from(c2_value),
            *c3_blinding,
        ],
        &[*value_basepoint, *blinding_basepoint],
    );

    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t2_p = RistrettoPoint::multiscalar_mul(&[blinding_c, blinding_d], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t3_p = RistrettoPoint::multiscalar_mul(
        &[blinding_a * (blinding_c), blinding_e],
        &[*value_basepoint, *blinding_basepoint],
    );
    let hash_str = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        &point_to_string(&t1_p),
        &point_to_string(&t2_p),
        &point_to_string(&t3_p),
        &point_to_string(&c1_point),
        &point_to_string(&c2_point),
        &point_to_string(&c3_point),
        &point_to_string(&value_basepoint),
        &point_to_string(&blinding_basepoint)
    );

    let check = hash_to_scalar(&hash_str);
    let value1 = Scalar::from(c1_value);
    let value2 = Scalar::from(c2_value);
    let m1 = blinding_a - (check * (value1));
    let m2 = blinding_b - (check * c1_blinding);
    let m3 = blinding_c - (check * (value2));
    let m4 = blinding_d - (check * c2_blinding);
    let c_index2 = check * check;
    let m5 = blinding_e
        + c_index2
            * ((value1 * c2_blinding) - c3_blinding + (value2 * c1_blinding))
        - check * ((blinding_a * c2_blinding) + (blinding_c * c1_blinding));

    let mut proof = BalanceProof::new();
    proof.set_c(scalar_to_string(&check));
    proof.set_m1(scalar_to_string(&m1));
    proof.set_m2(scalar_to_string(&m2));
    proof.set_m3(scalar_to_string(&m3));
    proof.set_m4(scalar_to_string(&m4));
    proof.set_m5(scalar_to_string(&m5));
    proof
}

/// Verifies three commitments satisfying a product relationship, i.e.
/// the values embedded in c1_point, c2_point, c3_point satisfying
/// c1_value * c2_value = c3_value.
pub fn verify_product_relationship(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &BalanceProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> bool {
    let check = string_to_scalar!(proof.get_c());
    let m1 = string_to_scalar!(proof.get_m1());
    let m2 = string_to_scalar!(proof.get_m2());
    let m3 = string_to_scalar!(proof.get_m3());
    let m4 = string_to_scalar!(proof.get_m4());
    let m5 = string_to_scalar!(proof.get_m5());

    let t1_v = RistrettoPoint::multiscalar_mul(&[m1, m2, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c1_point,
    ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[m3, m4, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c2_point,
    ]);
    let t3_v = RistrettoPoint::multiscalar_mul(
        &[m1 * m3, m5, check * check, check * m3, check * m1],
        &[
            *value_basepoint,
            *blinding_basepoint,
            *c3_point,
            *c1_point,
            *c2_point,
        ],
    );
    let hash_str = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        &point_to_string(&t1_v),
        &point_to_string(&t2_v),
        &point_to_string(&t3_v),
        &point_to_string(&c1_point),
        &point_to_string(&c2_point),
        &point_to_string(&c3_point),
        &point_to_string(&value_basepoint),
        &point_to_string(&blinding_basepoint)
    );

    let computed = hash_to_scalar(&hash_str);
    computed.eq(&check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constant::{BASEPOINT_G1, BASEPOINT_G2},
        utils::{get_random_scalar, make_commitment_point},
    };

    #[test]
    fn test_range_proof() {
        // Range proof for a single value.
        let (proof_c1, c1_point, _) = prove_value_range(1);
        assert_eq!(true, verify_value_range(&c1_point, &proof_c1));

        // A negative value will fail when it is out of the expected range after
        // the conversion.
        let (proof_c2, c2_point, _) = prove_value_range(-1i64 as u64);
        assert_eq!(false, verify_value_range(&c2_point, &proof_c2));

        // Range proof for a list of values.
        let blinding_basepoint = *BASEPOINT_G2;
        let values: Vec<u64> = vec![1, 2, 3, 4];
        let blindings: Vec<Scalar> =
            (0..values.len()).map(|_| get_random_scalar()).collect();

        let (proof_batch, point_list) = prove_value_range_in_batch(
            &values,
            &blindings,
            &blinding_basepoint,
        )
        .unwrap();

        assert_eq!(
            true,
            verify_value_range_in_batch(
                &point_list,
                &proof_batch,
                &blinding_basepoint,
            )
        );

        // Since the input size is not a multiple of 2, the batch prove function
        // will fail.
        let values2: Vec<u64> = vec![1, 2, 3];
        let blindings2: Vec<Scalar> =
            (0..values2.len()).map(|_| get_random_scalar()).collect();

        assert_eq!(
            WedprError::ArgumentError,
            prove_value_range_in_batch(
                &values2,
                &blindings2,
                &blinding_basepoint,
            )
            .unwrap_err()
        );
    }

    #[test]
    fn test_sum_relationship_proof() {
        let c1_value = 30u64;
        let c2_value = 10u64;
        let c1_blinding = get_random_scalar();
        let c2_blinding = get_random_scalar();
        let c3_blinding = get_random_scalar();
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        let proof = prove_sum_relationship(
            c1_value,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        let c1_point = make_commitment_point(
            c1_value,
            &c1_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        let c2_point = make_commitment_point(
            c2_value,
            &c2_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        // c3 = c1 + c2
        let c3_point = make_commitment_point(
            c1_value + c2_value,
            &c3_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );

        assert_eq!(
            true,
            verify_sum_relationship(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
        );
    }

    #[test]
    fn test_product_relationship_proof() {
        let c1_value = 30u64;
        let c2_value = 10u64;
        let c1_blinding = get_random_scalar();
        let c2_blinding = get_random_scalar();
        let c3_blinding = get_random_scalar();
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        let proof = prove_product_relationship(
            c1_value,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        let c1_point = make_commitment_point(
            c1_value,
            &c1_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        let c2_point = make_commitment_point(
            c2_value,
            &c2_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        // c3 = c1 * c2
        let c3_point = make_commitment_point(
            c1_value * c2_value,
            &c3_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );

        assert_eq!(
            true,
            verify_product_relationship(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
        );
    }
}
