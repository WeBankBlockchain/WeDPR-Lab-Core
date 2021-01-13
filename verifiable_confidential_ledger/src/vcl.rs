// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Core functions of verifiable confidential ledger (VCL).

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use std::fmt;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, get_random_scalar, point_to_bytes,
    scalar_to_bytes, BASEPOINT_G1, BASEPOINT_G2,
};

use curve25519_dalek::traits::MultiscalarMul;
use wedpr_l_crypto_zkp_discrete_logarithm_proof;
use wedpr_l_crypto_zkp_range_proof;
use wedpr_l_protos::generated::zkp::BalanceProof;
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::vcl::{
    EncodedConfidentialCredit, EncodedOwnerSecret,
};

/// Owner secret used to spend a confidential credit.
#[derive(Default, Debug, Clone)]
pub struct OwnerSecret {
    credit_value: u64,
    secret_blinding: Scalar,
}

/// Confidential credit record stored in VCL.
#[derive(Default, Debug, Clone)]
pub struct ConfidentialCredit {
    point: RistrettoPoint,
}

impl fmt::Display for OwnerSecret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "credit_value = {}, secret_blinding = {:?}",
            self.credit_value,
            scalar_to_bytes(&self.secret_blinding)
        )
    }
}

impl OwnerSecret {
    /// Encodes the struct to its protobuf form.
    // TODO: Make it serde compatible and try Flexbuffers.
    pub fn encode(&self) -> EncodedOwnerSecret {
        EncodedOwnerSecret {
            credit_value: self.credit_value as i64,
            secret_blinding: scalar_to_bytes(&self.secret_blinding),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        }
    }

    /// Decodes the protobuf to its struct form.
    // TODO: Make it serde compatible and try Flexbuffers.
    pub fn decode(
        encoded_owner_secret: &EncodedOwnerSecret,
    ) -> Result<OwnerSecret, WedprError> {
        Ok(OwnerSecret {
            credit_value: encoded_owner_secret.get_credit_value() as u64,
            secret_blinding: bytes_to_scalar(
                encoded_owner_secret.get_secret_blinding(),
            )?,
        })
    }
}

impl ConfidentialCredit {
    /// Gets the point representing the credit.
    pub fn get_point(&self) -> RistrettoPoint {
        self.point
    }

    /// Encodes the struct to its protobuf form.
    // TODO: Make it serde compatible and try Flexbuffers.
    pub fn encode(&self) -> EncodedConfidentialCredit {
        EncodedConfidentialCredit {
            point: point_to_bytes(&self.point),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        }
    }

    // Decodes the protobuf to its struct form.
    // TODO: Make it serde compatible and try Flexbuffers.
    pub fn decode(
        encoded_confidential_credit: &EncodedConfidentialCredit,
    ) -> Result<ConfidentialCredit, WedprError> {
        Ok(ConfidentialCredit {
            point: bytes_to_point(encoded_confidential_credit.get_point())?,
        })
    }
}

impl fmt::Display for ConfidentialCredit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "point = {:?}", point_to_bytes(&self.point))
    }
}

/// Makes a confidential credit record and owner secret for a numeric value.
pub fn make_credit(value: u64) -> (ConfidentialCredit, OwnerSecret) {
    let blinding_r = get_random_scalar();
    let commitment_point =
        RistrettoPoint::multiscalar_mul(&[Scalar::from(value), blinding_r], &[
            *BASEPOINT_G1,
            *BASEPOINT_G2,
        ]);

    (
        ConfidentialCredit {
            point: commitment_point,
        },
        OwnerSecret {
            credit_value: value,
            secret_blinding: blinding_r,
        },
    )
}

/// Proves three confidential credit records satisfying a sum relationship, i.e.
/// the values embedded in them satisfying c1_value + c2_value = c3_value.
/// c?_secret are the owner secrets for spending those commitments.
/// It returns a proof for the above sum relationship.
pub fn prove_sum_balance(
    c1_secret: &OwnerSecret,
    c2_secret: &OwnerSecret,
    c3_secret: &OwnerSecret,
) -> BalanceProof {
    wedpr_l_crypto_zkp_discrete_logarithm_proof::prove_sum_relationship(
        c1_secret.credit_value,
        c2_secret.credit_value,
        &c1_secret.secret_blinding,
        &c2_secret.secret_blinding,
        &c3_secret.secret_blinding,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    )
}

/// Verifies three commitments satisfying a sum relationship, i.e.
/// the values embedded in c1_credit, c2_credit, c3_credit satisfying
/// c1_value + c2_value = c3_value.
pub fn verify_sum_balance(
    c1_credit: &ConfidentialCredit,
    c2_credit: &ConfidentialCredit,
    c3_credit: &ConfidentialCredit,
    proof: &BalanceProof,
) -> Result<bool, WedprError> {
    wedpr_l_crypto_zkp_discrete_logarithm_proof::verify_sum_relationship(
        &c1_credit.get_point(),
        &c2_credit.get_point(),
        &c3_credit.get_point(),
        proof,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    )
}

/// Proves three confidential credit records satisfying a product relationship,
/// i.e. the values embedded in them satisfying c1_value * c2_value = c3_value.
/// c?_secret are the owner secrets for spending those commitments.
/// It returns a proof for the above product relationship.
pub fn prove_product_balance(
    c1_secret: &OwnerSecret,
    c2_secret: &OwnerSecret,
    c3_secret: &OwnerSecret,
) -> BalanceProof {
    wedpr_l_crypto_zkp_discrete_logarithm_proof::prove_product_relationship(
        c1_secret.credit_value,
        c2_secret.credit_value,
        &c1_secret.secret_blinding,
        &c2_secret.secret_blinding,
        &c3_secret.secret_blinding,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    )
}

/// Verifies three commitments satisfying a product relationship, i.e.
/// the values embedded in c1_credit, c2_credit, c3_credit satisfying
/// c1_value * c2_value = c3_value.
pub fn verify_product_balance(
    c1_credit: &ConfidentialCredit,
    c2_credit: &ConfidentialCredit,
    c3_credit: &ConfidentialCredit,
    proof: &BalanceProof,
) -> Result<bool, WedprError> {
    wedpr_l_crypto_zkp_discrete_logarithm_proof::verify_product_relationship(
        &c1_credit.get_point(),
        &c2_credit.get_point(),
        &c3_credit.get_point(),
        proof,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    )
}

/// Proves whether the value embedded in a confidential credit record belongs
/// to (0, 2^RANGE_SIZE_IN_BITS - 1].
pub fn prove_range(secret: &OwnerSecret) -> Vec<u8> {
    let (proof, _) =
        wedpr_l_crypto_zkp_range_proof::prove_value_range_with_blinding(
            secret.credit_value,
            &secret.secret_blinding,
        );
    proof.as_slice().to_vec()
}

/// Verifies whether the value embedded in a confidential credit record belongs
/// to (0, 2^RANGE_SIZE_IN_BITS - 1].
pub fn verify_range(c1: &ConfidentialCredit, proof: &[u8]) -> bool {
    wedpr_l_crypto_zkp_range_proof::verify_value_range(&c1.get_point(), proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_common_coder_base64::WedprBase64;
    use wedpr_l_utils::traits::Coder;
    extern crate wedpr_l_crypto_zkp_utils;
    use wedpr_l_crypto_zkp_utils::point_to_bytes;

    extern crate wedpr_l_protos;
    use protobuf::Message;

    #[test]
    fn test_vcl_data() {
        let base64 = WedprBase64::default();
        let mut c1_credit_vec = Vec::new();
        let mut c2_credit_vec = Vec::new();
        let mut c3_credit_vec = Vec::new();
        let mut proof_vec = Vec::new();
        for _i in 0..100 {
            let (c1_credit, c1_secret) = make_credit(10);
            c1_credit_vec
                .push(base64.encode(&point_to_bytes(&c1_credit.get_point())));

            let (c2_credit, c2_secret) = make_credit(20);
            c2_credit_vec
                .push(base64.encode(&point_to_bytes(&c2_credit.get_point())));

            // 10 + 20 = 30
            let (c3_credit, c3_secret) = make_credit(30);
            c3_credit_vec
                .push(base64.encode(&point_to_bytes(&c3_credit.get_point())));

            let proof = prove_sum_balance(&c1_secret, &c2_secret, &c3_secret);
            let proof_str = base64.encode(&proof.write_to_bytes().unwrap());
            proof_vec.push(proof_str);
        }
        println!("{:?}", c1_credit_vec);
        println!("{:?}", c2_credit_vec);
        println!("{:?}", c3_credit_vec);
        println!("{:?}", proof_vec);
    }

    #[test]
    fn test_sum_balance_proof() {
        let (c1_credit, c1_secret) = make_credit(10);
        let (c2_credit, c2_secret) = make_credit(20);

        // 10 + 20 = 30
        let (correct_c3_credit, correct_c3_secret) = make_credit(30);
        let correct_proof =
            prove_sum_balance(&c1_secret, &c2_secret, &correct_c3_secret);

        // 10 + 20 != 31
        let (wrong_c3_credit, wrong_c3_secret) = make_credit(31);
        let wrong_proof =
            prove_sum_balance(&c1_secret, &c2_secret, &wrong_c3_secret);

        assert_eq!(
            true,
            verify_sum_balance(
                &c1_credit,
                &c2_credit,
                &correct_c3_credit,
                &correct_proof
            )
            .unwrap()
        );

        // Incorrect proof combinations.
        assert_eq!(
            false,
            verify_sum_balance(
                &c1_credit,
                &c2_credit,
                &wrong_c3_credit,
                &wrong_proof
            )
            .unwrap()
        );
        assert_eq!(
            false,
            verify_sum_balance(
                &c1_credit,
                &c2_credit,
                &correct_c3_credit,
                &wrong_proof
            )
            .unwrap()
        );
        assert_eq!(
            false,
            verify_sum_balance(
                &c1_credit,
                &c2_credit,
                &wrong_c3_credit,
                &correct_proof
            )
            .unwrap()
        );
    }

    #[test]
    fn test_product_balance_proof() {
        let (c1_credit, c1_secret) = make_credit(10);
        let (c2_credit, c2_secret) = make_credit(20);
        let (correct_c3_credit, correct_c3_secret) = make_credit(200);
        let (wrong_c3_credit, wrong_c3_secret) = make_credit(31);
        // 10 * 20 = 200
        let correct_proof =
            prove_product_balance(&c1_secret, &c2_secret, &correct_c3_secret);
        // 10 * 20 != 31
        let wrong_proof =
            prove_product_balance(&c1_secret, &c2_secret, &wrong_c3_secret);

        assert_eq!(
            true,
            verify_product_balance(
                &c1_credit,
                &c2_credit,
                &correct_c3_credit,
                &correct_proof
            )
            .unwrap()
        );

        // Incorrect proof combinations.
        assert_eq!(
            false,
            verify_product_balance(
                &c1_credit,
                &c2_credit,
                &wrong_c3_credit,
                &wrong_proof
            )
            .unwrap()
        );
        assert_eq!(
            false,
            verify_product_balance(
                &c1_credit,
                &c2_credit,
                &correct_c3_credit,
                &wrong_proof
            )
            .unwrap()
        );
        assert_eq!(
            false,
            verify_product_balance(
                &c1_credit,
                &c2_credit,
                &wrong_c3_credit,
                &correct_proof
            )
            .unwrap()
        );
    }

    #[test]
    fn test_range_proof() {
        let (c1_credit, c1_secret) = make_credit(65535);
        let (c2_credit, c2_secret) = make_credit(20);

        let range_proof_c1 = prove_range(&c1_secret);
        let range_proof_c2 = prove_range(&c2_secret);

        assert_eq!(true, verify_range(&c1_credit, &range_proof_c1));
        assert_eq!(true, verify_range(&c2_credit, &range_proof_c2));

        assert_eq!(false, verify_range(&c2_credit, &range_proof_c1));
        assert_eq!(false, verify_range(&c1_credit, &range_proof_c2));
    }
}
