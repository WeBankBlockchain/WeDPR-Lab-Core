// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous ciphertext voting (ACV) solution.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{
    verify_equality_relationship_proof, verify_format_proof,
    verify_sum_relationship,
};
use wedpr_l_crypto_zkp_range_proof::verify_value_range_in_batch;
use wedpr_l_crypto_zkp_utils::{bytes_to_point, BASEPOINT_G1, BASEPOINT_G2};
use wedpr_l_protos::{
    bytes_to_proto,
    generated::zkp::{BalanceProof, EqualityProof},
};
use wedpr_l_utils::{
    error::WedprError,
    traits::{Hash, Signature},
};

use wedpr_s_protos::generated::acv::{
    Ballot, CountingPart, DecryptedResultPartStorage, SystemParametersStorage,
    VoteRequest, VoteResultStorage, VoteStorage,
};

use crate::config::{HASH_KECCAK256, SIGNATURE_SECP256K1};

/// Verifies a group of zero-knowledge proofs in the vote request from each
/// voter to confirm whether each ballot of voter is correct, specifically
/// refers to the format, the accounting balance and the numerical range of each
/// ciphertext ballot.
pub fn verify_bounded_vote_request(
    param: &SystemParametersStorage,
    request: &VoteRequest,
    public_key: &[u8],
) -> Result<bool, WedprError> {
    let poll_point = bytes_to_point(param.get_poll_point())?;
    let signature = request.get_vote().get_signature();
    let blank_ballot = request.get_vote().get_blank_ballot();
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut blank_ballot.get_ciphertext1().to_vec());
    hash_vec.append(&mut blank_ballot.get_ciphertext2().to_vec());
    let message_hash: Vec<u8> = HASH_KECCAK256.hash(&hash_vec);

    if !SIGNATURE_SECP256K1.verify(
        &public_key,
        &message_hash.as_ref(),
        &signature,
    ) {
        return Err(WedprError::VerificationError);
    }

    let range_proof = request.get_range_proof();
    let mut commitments: Vec<RistrettoPoint> = Vec::new();
    let mut voted_ballot_sum = RistrettoPoint::default();
    for candidate_ballot_pair in request.get_vote().get_voted_ballot() {
        let ballot = candidate_ballot_pair.get_ballot();
        commitments.push(bytes_to_point(&ballot.get_ciphertext1())?);
        voted_ballot_sum += bytes_to_point(&ballot.get_ciphertext1())?;
    }

    let rest_ballot = request.get_vote().get_rest_ballot().get_ciphertext1();
    let rest_ballot_point = bytes_to_point(rest_ballot.clone())?;
    commitments.push(rest_ballot_point);
    pending_commitment_vec(&mut commitments);
    if !verify_value_range_in_batch(&commitments, range_proof, &poll_point) {
        wedpr_println!("verify range proof failed!");
        return Err(WedprError::VerificationError);
    }

    for candidate_ballot in request.get_ballot_proof() {
        let candidate = candidate_ballot.get_key();
        let ballot_proof = candidate_ballot.get_value();
        let mut candidate_ballot = Ballot::new();
        for candidate_ballot_pair in request.get_vote().get_voted_ballot() {
            if candidate_ballot_pair.get_candidate() == candidate {
                candidate_ballot = candidate_ballot_pair.get_ballot().clone();
            }
        }

        let ciphertext1 = bytes_to_point(&candidate_ballot.get_ciphertext1())?;
        let ciphertext2 = bytes_to_point(&candidate_ballot.get_ciphertext2())?;
        let format_proof_bytes = ballot_proof.get_format_proof();
        let format_proof = bytes_to_proto::<BalanceProof>(format_proof_bytes)?;
        if !verify_format_proof(
            &ciphertext1,
            &ciphertext2,
            &format_proof,
            &*BASEPOINT_G1,
            &*BASEPOINT_G2,
            &poll_point,
        )? {
            wedpr_println!("verify_format failed!");
            return Err(WedprError::VerificationError);
        }
    }
    let balance_proof_bytes = request.get_sum_balance_proof();
    let balance_proof = bytes_to_proto::<BalanceProof>(balance_proof_bytes)?;
    if !verify_sum_relationship(
        &voted_ballot_sum,
        &bytes_to_point(&rest_ballot)?,
        &bytes_to_point(&blank_ballot.get_ciphertext1())?,
        &balance_proof,
        &BASEPOINT_G1,
        &poll_point,
    )? {
        wedpr_println!("verify_balance failed!");
        return Err(WedprError::VerificationError);
    }
    Ok(true)
}

/// Verifies zero-knowledge proof in the count request from each counter to
/// confirm whether the counting process is correct, specifically refers to that
/// whether each counter used correct secret key when counting.
pub fn verify_count_request(
    param: &SystemParametersStorage,
    encrypted_vote_sum: &VoteStorage,
    counter_share: &RistrettoPoint,
    request: &DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    let blank_c2_sum = bytes_to_point(
        &encrypted_vote_sum.get_blank_ballot().get_ciphertext2(),
    )?;
    let blank_equality_proof_bytes =
        request.get_blank_part().get_equality_proof();
    let blank_c2_r =
        bytes_to_point(&request.get_blank_part().get_blinding_c2())?;
    let blank_equality_proof =
        bytes_to_proto::<EqualityProof>(&blank_equality_proof_bytes)?;
    if !verify_equality_relationship_proof(
        &counter_share,
        &blank_c2_r,
        &blank_equality_proof,
        &BASEPOINT_G2,
        &blank_c2_sum,
    )? {
        return Ok(false);
    }
    for candidate in param.get_candidates().get_candidate() {
        let mut candidate_ballot = Ballot::new();
        for pair in encrypted_vote_sum.get_voted_ballot() {
            if candidate == pair.get_candidate() {
                candidate_ballot = pair.get_ballot().clone();
            }
        }
        let candidate_c2_sum =
            bytes_to_point(&candidate_ballot.get_ciphertext2())?;
        let mut counting_part = CountingPart::new();
        for pair in request.get_candidate_part() {
            if candidate == pair.get_key() {
                counting_part = pair.get_value().clone();
            }
        }
        let candidate_c2_r = bytes_to_point(&counting_part.get_blinding_c2())?;
        let candidate_equality_proof_bytes = counting_part.get_equality_proof();
        let candidate_equality_proof =
            bytes_to_proto::<EqualityProof>(candidate_equality_proof_bytes)?;

        if !verify_equality_relationship_proof(
            &counter_share,
            &candidate_c2_r,
            &candidate_equality_proof.clone(),
            &BASEPOINT_G2,
            &candidate_c2_sum,
        )? {
            wedpr_println!("verify_equality failed!");
            return Ok(false);
        }
    }
    Ok(true)
}

/// Verifies whether the final score of each candidate is correct.
pub fn verify_vote_result(
    param: &SystemParametersStorage,
    vote_sum: &VoteStorage,
    counting_result_sum: &DecryptedResultPartStorage,
    vote_result_request: &VoteResultStorage,
) -> Result<bool, WedprError> {
    let blank_c1_sum =
        bytes_to_point(&vote_sum.get_blank_ballot().get_ciphertext1())?;
    let blank_c2_r_sum = bytes_to_point(
        &counting_result_sum.get_blank_part().get_blinding_c2(),
    )?;
    let expected_blank_ballot_result = blank_c1_sum - (blank_c2_r_sum);
    let mut get_blank_result: i64 = 0;
    for tmp in vote_result_request.get_result() {
        if tmp.get_key() == "Wedpr_voting_total_ballots" {
            get_blank_result = tmp.get_value();
        }
    }

    if expected_blank_ballot_result
        .ne(&(*BASEPOINT_G1 * (Scalar::from(get_blank_result as u64))))
    {
        wedpr_println!("verify blank_ballot_result failed!");
        return Ok(false);
    }

    for candidate in param.get_candidates().get_candidate() {
        let mut ballot = Ballot::new();
        for tmp_pair in vote_sum.get_voted_ballot() {
            if candidate == tmp_pair.get_candidate() {
                ballot = tmp_pair.get_ballot().clone();
            }
        }

        let mut candidate_counting_part = CountingPart::new();
        for tmp_pair in counting_result_sum.get_candidate_part() {
            if candidate == tmp_pair.get_key() {
                candidate_counting_part = tmp_pair.get_value().clone();
            }
        }

        let candidate_c2_r_sum =
            bytes_to_point(&candidate_counting_part.get_blinding_c2())?;

        let expected_candidate_ballot_result =
            bytes_to_point(&ballot.get_ciphertext1())? - (candidate_c2_r_sum);

        let mut get_candidate_result: i64 = 0;
        for tmp in vote_result_request.get_result() {
            if tmp.get_key() == candidate {
                get_candidate_result = tmp.get_value();
            }
        }
        if !expected_candidate_ballot_result
            .eq(&(*BASEPOINT_G1 * (Scalar::from(get_candidate_result as u64))))
        {
            wedpr_println!("verify candidate {} failed!", candidate);
            return Ok(false);
        }
    }
    Ok(true)
}

fn pending_commitment_vec(v: &mut Vec<RistrettoPoint>) {
    let length = v.len() as i32;
    let log_length = (length as f64).log2().ceil() as u32;
    let expected_len = 2_i32.pow(log_length);
    if expected_len == length {
        return;
    }
    let pending_length = expected_len - length;
    let tmp = RistrettoPoint::default();
    for _ in 0..pending_length {
        v.push(tmp);
    }
}
