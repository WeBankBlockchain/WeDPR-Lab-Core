// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a poll coordinator.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_crypto_zkp_utils::{bytes_to_point, point_to_bytes, BASEPOINT_G1};
use wedpr_l_utils::{
    error::WedprError,
    traits::{Hash, Signature},
};

use wedpr_s_protos::generated::acv::{
    Ballot, CandidateBallot, CandidateList, CounterParametersStorage,
    CountingPart, DecryptedResultPartStorage, PollParametersStorage,
    RegistrationRequest, RegistrationResponse, StringToCountingPartPair,
    StringToInt64Pair, VoteResultStorage, VoteStorage,
};

use crate::{
    config::{HASH, POLL_RESULT_KEY_TOTAL_BALLOTS, SIGNATURE},
    utils::{get_ballot_by_candidate, get_counting_part_by_candidate},
};

/// Makes system parameters for a new poll.
pub fn make_poll_parameters(
    candidate_list: &CandidateList,
    counter_parameters: &CounterParametersStorage,
) -> Result<PollParametersStorage, WedprError> {
    let mut poll_point = RistrettoPoint::default();
    for share in counter_parameters.get_counter_parameters_share() {
        poll_point += bytes_to_point(share.get_poll_point_share())?;
    }

    let mut storage = PollParametersStorage::default();
    storage.set_candidates(candidate_list.clone());
    storage.set_poll_point(point_to_bytes(&poll_point));
    Ok(storage)
}

/// Certifies a voter's registration. It confirm its weight which indicates the
/// maximum votes that the voter can vote for all candidates in a poll.
pub fn certify_voter(
    secret_key: &[u8],
    registration_request: &RegistrationRequest,
    voter_weight: u32,
) -> Result<RegistrationResponse, WedprError> {
    let blinding_poll_point = bytes_to_point(
        registration_request
            .get_weight_point()
            .get_blinding_poll_point(),
    )?;
    let ciphertext1 =
        blinding_poll_point + (*BASEPOINT_G1 * Scalar::from(voter_weight));
    let mut ballot = Ballot::new();
    ballot.set_ciphertext1(point_to_bytes(&ciphertext1));
    ballot.set_ciphertext2(
        registration_request
            .get_weight_point()
            .get_blinding_basepoint_g2()
            .to_vec(),
    );
    // Sign the above data.
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut ballot.get_ciphertext1().to_vec());
    hash_vec.append(&mut ballot.get_ciphertext2().to_vec());
    let message_hash = HASH.hash(&hash_vec);
    let signature = SIGNATURE.sign(secret_key, &message_hash)?;

    let mut response = RegistrationResponse::new();
    response.set_signature(signature);
    response.set_ballot(ballot);
    response.set_voter_weight(voter_weight);
    Ok(response)
}

/// Aggregates all ciphertext ballots from a voter.
pub fn aggregate_vote_sum_response(
    poll_parameters: &PollParametersStorage,
    vote_part: &VoteStorage,
    vote_sum: &mut VoteStorage,
) -> Result<bool, WedprError> {
    // Initialize for the first part.
    if !vote_sum.has_blank_ballot() {
        let blank_ballot = vote_sum.mut_blank_ballot();
        blank_ballot
            .set_ciphertext1(point_to_bytes(&RistrettoPoint::default()));
        blank_ballot
            .set_ciphertext2(point_to_bytes(&RistrettoPoint::default()));
        for candidate in poll_parameters.get_candidates().get_candidate() {
            let mut ballot = Ballot::new();
            ballot.set_ciphertext1(point_to_bytes(&RistrettoPoint::default()));
            ballot.set_ciphertext2(point_to_bytes(&RistrettoPoint::default()));
            let mut ballot_pair = CandidateBallot::new();
            ballot_pair.set_candidate(candidate.to_string());
            ballot_pair.set_ballot(ballot);
            vote_sum.mut_voted_ballot().push(ballot_pair);
        }
    }

    let c1_point =
        bytes_to_point(&vote_part.get_blank_ballot().get_ciphertext1())?;
    let blank_c1_sum =
        bytes_to_point(&vote_sum.get_blank_ballot().get_ciphertext1())?
            + c1_point;
    let c2_point =
        bytes_to_point(&vote_part.get_blank_ballot().get_ciphertext2())?;
    let blank_c2_sum =
        bytes_to_point(&vote_sum.get_blank_ballot().get_ciphertext2())?
            + c2_point;

    let mut output_vote_sum = VoteStorage::new();
    for candidate in poll_parameters.get_candidates().get_candidate() {
        let sum_ballot = get_ballot_by_candidate(&vote_sum, candidate)?;
        let new_ballot = get_ballot_by_candidate(&vote_part, candidate)?;
        let candidate_voted_c1_sum =
            bytes_to_point(&sum_ballot.get_ciphertext1())?
                + bytes_to_point(&new_ballot.get_ciphertext1())?;
        let candidate_voted_c2_sum =
            bytes_to_point(&sum_ballot.get_ciphertext2())?
                + bytes_to_point(&new_ballot.get_ciphertext2())?;

        // Write back.
        let mut new_sum_ballot = Ballot::new();
        new_sum_ballot.set_ciphertext1(point_to_bytes(&candidate_voted_c1_sum));
        new_sum_ballot.set_ciphertext2(point_to_bytes(&candidate_voted_c2_sum));
        let mut new_pair = CandidateBallot::new();
        new_pair.set_candidate(candidate.to_string());
        new_pair.set_ballot(new_sum_ballot);
        output_vote_sum.mut_voted_ballot().push(new_pair);
    }
    let blank_ballot = output_vote_sum.mut_blank_ballot();
    blank_ballot.set_ciphertext1(point_to_bytes(&blank_c1_sum));
    blank_ballot.set_ciphertext2(point_to_bytes(&blank_c2_sum));
    *vote_sum = output_vote_sum;
    Ok(true)
}

/// Aggregates a partially decrypted result from a counter.
pub fn aggregate_decrypted_part_sum(
    poll_parameters: &PollParametersStorage,
    partially_decrypted_result: &DecryptedResultPartStorage,
    aggregated_decrypted_result: &mut DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    // Initialize for the first part.
    if !aggregated_decrypted_result.has_blank_part() {
        let blank_part = aggregated_decrypted_result.mut_blank_part();
        blank_part.set_counter_id("sum".to_string());
        blank_part.set_blinding_c2(point_to_bytes(&RistrettoPoint::default()));
        for candidate in poll_parameters.get_candidates().get_candidate() {
            let mut counting_part = CountingPart::new();
            counting_part
                .set_blinding_c2(point_to_bytes(&RistrettoPoint::default()));
            let mut new_pair = StringToCountingPartPair::new();
            new_pair.set_key(candidate.to_string());
            new_pair.set_value(counting_part);
            aggregated_decrypted_result
                .mut_candidate_part()
                .push(new_pair);
        }
    }

    let blank_part_share = bytes_to_point(
        &partially_decrypted_result
            .get_blank_part()
            .get_blinding_c2(),
    )?;
    let blank_c2_r_sum = bytes_to_point(
        &aggregated_decrypted_result
            .get_blank_part()
            .get_blinding_c2(),
    )? + blank_part_share;
    aggregated_decrypted_result
        .mut_blank_part()
        .set_blinding_c2(point_to_bytes(&blank_c2_r_sum));

    let mut output_decrypted_result = aggregated_decrypted_result.clone();
    output_decrypted_result.clear_candidate_part();
    for candidate in poll_parameters.get_candidates().get_candidate() {
        let aggregated_part = get_counting_part_by_candidate(
            &aggregated_decrypted_result,
            candidate,
        )?;
        let new_part = get_counting_part_by_candidate(
            &partially_decrypted_result,
            candidate,
        )?;
        let candidate_c2_r = bytes_to_point(&new_part.get_blinding_c2())?;
        let candidate_c2_r_sum =
            bytes_to_point(&aggregated_part.get_blinding_c2())?
                + candidate_c2_r;

        // Write back.
        let mut candidate_part = CountingPart::new();
        candidate_part.set_blinding_c2(point_to_bytes(&candidate_c2_r_sum));
        let mut new_pair = StringToCountingPartPair::new();
        new_pair.set_key(candidate.to_string());
        new_pair.set_value(candidate_part);
        output_decrypted_result.mut_candidate_part().push(new_pair);
    }
    *aggregated_decrypted_result = output_decrypted_result;
    Ok(true)
}

/// Computes the final vote result from aggregated partially decrypted results.
pub fn finalize_vote_result(
    poll_parameters: &PollParametersStorage,
    vote_sum: &VoteStorage,
    aggregated_decrypted_result: &DecryptedResultPartStorage,
    max_vote_limit: i64,
) -> Result<VoteResultStorage, WedprError> {
    let mut result = VoteResultStorage::new();
    let blank_c1_sum =
        bytes_to_point(vote_sum.get_blank_ballot().get_ciphertext1())?;
    let blank_c2_r_sum = bytes_to_point(
        aggregated_decrypted_result
            .get_blank_part()
            .get_blinding_c2(),
    )?;

    // Compute the total votes.
    let target_total = blank_c1_sum - blank_c2_r_sum;
    for i in 1..=max_vote_limit {
        if target_total.eq(&(*BASEPOINT_G1 * Scalar::from(i as u64))) {
            let mut new_pair = StringToInt64Pair::new();
            new_pair.set_key(POLL_RESULT_KEY_TOTAL_BALLOTS.to_string());
            new_pair.set_value(i);
            result.mut_result().push(new_pair);
            break;
        }
    }

    // Compute the votes for each candidate.
    for candidate in poll_parameters.get_candidates().get_candidate() {
        let ballot = get_ballot_by_candidate(vote_sum, candidate)?;
        let candidate_counting_part = get_counting_part_by_candidate(
            aggregated_decrypted_result,
            candidate,
        )?;
        let candidate_c2_r_sum =
            bytes_to_point(candidate_counting_part.get_blinding_c2())?;
        let target_candidate =
            bytes_to_point(ballot.get_ciphertext1())? - candidate_c2_r_sum;

        for i in 0..=max_vote_limit {
            if target_candidate.eq(&(*BASEPOINT_G1 * Scalar::from(i as u64))) {
                let mut new_pair = StringToInt64Pair::new();
                new_pair.set_key(candidate.to_string());
                new_pair.set_value(i);
                result.mut_result().push(new_pair);
                break;
            }
        }
    }
    Ok(result)
}
