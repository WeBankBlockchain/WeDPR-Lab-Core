// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Core functions of verifiable confidential ledger (VCL).

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use std::fmt;
use wedpr_crypto::{
    self,
    constant::{BASEPOINT_G1, BASEPOINT_G2},
    utils::{point_to_string, scalar_to_string},
};
use wedpr_protos::generated::zkp::BalanceProof;

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
            "credit_value = {}, secret_blinding = {}",
            self.credit_value,
            scalar_to_string(&self.secret_blinding)
        )
    }
}

impl ConfidentialCredit {
    pub fn get_point(&self) -> RistrettoPoint {
        self.point
    }
}

impl fmt::Display for ConfidentialCredit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "point = {}", point_to_string(&self.point))
    }
}

/// Makes a confidential credit record and owner secret for a numberic value.
pub fn make_credit(value: u64) -> (ConfidentialCredit, OwnerSecret) {
    let blinding_r = wedpr_crypto::utils::get_random_scalar();
    let commitment_point = wedpr_crypto::utils::make_commitment_point(
        value,
        &blinding_r,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    );

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
/// the values embeded in them satisfying c1_value + c2_value = c3_value.
/// c?_secret are the owner secrets for spending those commitments.
/// It returns a proof for the above sum relationship.
pub fn prove_sum_balance(
    c1_secret: &OwnerSecret,
    c2_secret: &OwnerSecret,
    c3_secret: &OwnerSecret,
) -> BalanceProof
{
    wedpr_crypto::zkp::prove_sum_relationship(
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
/// the values embeded in c1_credit, c2_credit, c3_credit satisfying
/// c1_value + c2_value = c3_value.
pub fn verify_sum_balance(
    c1_credit: &ConfidentialCredit,
    c2_credit: &ConfidentialCredit,
    c3_credit: &ConfidentialCredit,
    proof: &BalanceProof,
) -> bool
{
    wedpr_crypto::zkp::verify_sum_relationship(
        &c1_credit.get_point(),
        &c2_credit.get_point(),
        &c3_credit.get_point(),
        proof,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    )
}

/// Proves three confidential credit records satisfying a product relationship,
/// i.e. the values embeded in them satisfying c1_value * c2_value = c3_value.
/// c?_secret are the owner secrets for spending those commitments.
/// It returns a proof for the above product relationship.
pub fn prove_product_balance(
    c1_secret: &OwnerSecret,
    c2_secret: &OwnerSecret,
    c3_secret: &OwnerSecret,
) -> BalanceProof
{
    wedpr_crypto::zkp::prove_product_relationship(
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
/// the values embeded in c1_credit, c2_credit, c3_credit satisfying
/// c1_value * c2_value = c3_value.
pub fn verify_product_balance(
    c1_credit: &ConfidentialCredit,
    c2_credit: &ConfidentialCredit,
    c3_credit: &ConfidentialCredit,
    proof: &BalanceProof,
) -> bool
{
    wedpr_crypto::zkp::verify_product_relationship(
        &c1_credit.get_point(),
        &c2_credit.get_point(),
        &c3_credit.get_point(),
        proof,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
    )
}

/// Proves whether the value embeded in a confidential credit record belongs
/// to (0, 2^RANGE_SIZE_IN_BITS - 1].
pub fn prove_range(secret: &OwnerSecret) -> String {
    let (proof, _) = wedpr_crypto::zkp::prove_value_range_with_blinding(
        secret.credit_value,
        &secret.secret_blinding,
    );
    proof
}

/// Verifies whether the value embeded in a confidential credit record belongs
/// to (0, 2^RANGE_SIZE_IN_BITS - 1].
pub fn verify_range(c1: &ConfidentialCredit, proof: &str) -> bool {
    wedpr_crypto::zkp::verify_value_range(&c1.get_point(), proof)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        );
        assert_eq!(
            false,
            verify_sum_balance(
                &c1_credit,
                &c2_credit,
                &correct_c3_credit,
                &wrong_proof
            )
        );
        assert_eq!(
            false,
            verify_sum_balance(
                &c1_credit,
                &c2_credit,
                &wrong_c3_credit,
                &correct_proof
            )
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
        );
        assert_eq!(
            false,
            verify_product_balance(
                &c1_credit,
                &c2_credit,
                &correct_c3_credit,
                &wrong_proof
            )
        );
        assert_eq!(
            false,
            verify_product_balance(
                &c1_credit,
                &c2_credit,
                &wrong_c3_credit,
                &correct_proof
            )
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
