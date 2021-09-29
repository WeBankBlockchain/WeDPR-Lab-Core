// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a poll verifier.

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
    DecryptedResultPartStorage, PollParametersStorage, VoteRequest,
    VoteResultStorage, VoteStorage,
};

use crate::{
    config::{HASH, POLL_RESULT_KEY_TOTAL_BALLOTS, SIGNATURE},
    utils::{
        align_commitment_list_if_needed, get_ballot_by_candidate,
        get_counting_part_by_candidate, get_int64_by_candidate,
    },
};

/// Verifies whether ciphertext ballots from a certified voter are valid.
pub fn verify_vote_request(
    poll_parameters: &PollParametersStorage,
    vote_request: &VoteRequest,
    public_key: &[u8],
) -> Result<bool, WedprError> {
    let poll_point = bytes_to_point(poll_parameters.get_poll_point())?;
    let signature = vote_request.get_vote().get_signature();
    let blank_ballot = vote_request.get_vote().get_blank_ballot();
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut blank_ballot.get_ciphertext1().to_vec());
    hash_vec.append(&mut blank_ballot.get_ciphertext2().to_vec());
    let message_hash: Vec<u8> = HASH.hash(&hash_vec);
    if !SIGNATURE.verify(&public_key, &message_hash.as_ref(), &signature) {
        return Err(WedprError::VerificationError);
    }

    let mut commitments: Vec<RistrettoPoint> = Vec::new();
    let mut voted_ballot_sum = RistrettoPoint::default();
    for candidate_ballot_pair in vote_request.get_vote().get_voted_ballot() {
        let ballot = candidate_ballot_pair.get_ballot();
        commitments.push(bytes_to_point(&ballot.get_ciphertext1())?);
        voted_ballot_sum += bytes_to_point(&ballot.get_ciphertext1())?;
    }

    let rest_ballot =
        vote_request.get_vote().get_rest_ballot().get_ciphertext1();
    let rest_ballot_point = bytes_to_point(rest_ballot)?;
    commitments.push(rest_ballot_point);
    align_commitment_list_if_needed(&mut commitments);
    let range_proof = vote_request.get_range_proof();
    if !verify_value_range_in_batch(&commitments, range_proof, &poll_point) {
        wedpr_println!("verify range proof failed!");
        return Err(WedprError::VerificationError);
    }

    for candidate_ballot in vote_request.get_ballot_proof() {
        let candidate = candidate_ballot.get_key();
        let ballot_proof = candidate_ballot.get_value();
        let candidate_ballot =
            get_ballot_by_candidate(&vote_request.get_vote(), candidate)?;

        let ciphertext1 = bytes_to_point(&candidate_ballot.get_ciphertext1())?;
        let ciphertext2 = bytes_to_point(&candidate_ballot.get_ciphertext2())?;
        let format_proof =
            bytes_to_proto::<BalanceProof>(ballot_proof.get_format_proof())?;
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

    let balance_proof =
        bytes_to_proto::<BalanceProof>(vote_request.get_sum_balance_proof())?;
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

/// Verifies whether a partially decrypted result from a counter is valid.
pub fn verify_count_request(
    poll_parameters: &PollParametersStorage,
    encrypted_vote_sum: &VoteStorage,
    counter_share: &RistrettoPoint,
    partially_decrypted_result: &DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    // Verify the total votes.
    let blank_c2_sum = bytes_to_point(
        &encrypted_vote_sum.get_blank_ballot().get_ciphertext2(),
    )?;
    let blank_equality_proof_bytes = partially_decrypted_result
        .get_blank_part()
        .get_equality_proof();
    let blank_c2_r = bytes_to_point(
        &partially_decrypted_result
            .get_blank_part()
            .get_blinding_c2(),
    )?;
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

    // Verify the votes for each candidate.
    for candidate in poll_parameters.get_candidates().get_candidate() {
        let candidate_ballot =
            get_ballot_by_candidate(encrypted_vote_sum, candidate)?;
        let candidate_c2_sum =
            bytes_to_point(&candidate_ballot.get_ciphertext2())?;
        let counting_part = get_counting_part_by_candidate(
            partially_decrypted_result,
            candidate,
        )?;
        let candidate_c2_r = bytes_to_point(&counting_part.get_blinding_c2())?;
        let candidate_equality_proof = bytes_to_proto::<EqualityProof>(
            counting_part.get_equality_proof(),
        )?;
        if !verify_equality_relationship_proof(
            &counter_share,
            &candidate_c2_r,
            &candidate_equality_proof,
            &BASEPOINT_G2,
            &candidate_c2_sum,
        )? {
            wedpr_println!("verify_equality failed!");
            return Ok(false);
        }
    }
    Ok(true)
}

/// Verifies whether the final vote result is valid.
pub fn verify_vote_result(
    poll_parameters: &PollParametersStorage,
    vote_sum: &VoteStorage,
    aggregated_decrypted_result: &DecryptedResultPartStorage,
    vote_result: &VoteResultStorage,
) -> Result<bool, WedprError> {
    let blank_c1_sum =
        bytes_to_point(&vote_sum.get_blank_ballot().get_ciphertext1())?;
    let blank_c2_r_sum = bytes_to_point(
        &aggregated_decrypted_result
            .get_blank_part()
            .get_blinding_c2(),
    )?;

    let blank_result =
        get_int64_by_candidate(vote_result, POLL_RESULT_KEY_TOTAL_BALLOTS)?;
    let expected_blank_ballot_result = blank_c1_sum - (blank_c2_r_sum);
    if expected_blank_ballot_result
        .ne(&(*BASEPOINT_G1 * (Scalar::from(blank_result as u64))))
    {
        wedpr_println!("verify blank_ballot_result failed!");
        return Ok(false);
    }

    for candidate in poll_parameters.get_candidates().get_candidate() {
        let ballot = get_ballot_by_candidate(vote_sum, candidate)?;
        let candidate_counting_part = get_counting_part_by_candidate(
            aggregated_decrypted_result,
            candidate,
        )?;
        let candidate_c2_r_sum =
            bytes_to_point(&candidate_counting_part.get_blinding_c2())?;

        let candidate_result = get_int64_by_candidate(vote_result, candidate)?;
        let expected_candidate_ballot_result =
            bytes_to_point(&ballot.get_ciphertext1())? - (candidate_c2_r_sum);
        if !expected_candidate_ballot_result
            .eq(&(*BASEPOINT_G1 * (Scalar::from(candidate_result as u64))))
        {
            wedpr_println!("verify candidate {} failed!", candidate);
            return Ok(false);
        }
    }
    Ok(true)
}
