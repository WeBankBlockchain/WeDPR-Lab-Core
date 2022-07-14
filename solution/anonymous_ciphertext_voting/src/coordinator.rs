// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a poll coordinator.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_crypto_zkp_utils::{bytes_to_point, point_to_bytes, BASEPOINT_G1};
use wedpr_l_utils::error::WedprError;

use wedpr_s_protos::{
    generate_ballot_signature, generate_ballots_signature,
    generated::acv::{
        Ballot, CandidateBallot, CandidateList, CounterParametersStorage,
        CountingPart, DecryptedResultPartStorage, PollParametersStorage,
        RegistrationRequest, RegistrationResponse, StringToCountingPartPair,
        StringToInt64Pair, UnlistedBallotDecryptedResult, UnlistedVoteChoice,
        VoteResultStorage, VoteStorage,
    },
};

use crate::{
    config::POLL_RESULT_KEY_TOTAL_BALLOTS,
    utils::{get_ballot_by_candidate, get_counting_part_by_candidate},
};

use std::collections::BTreeMap;

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
    let mut response = RegistrationResponse::new();
    // Sign the above data.
    response.set_signature(generate_ballot_signature(secret_key, &ballot)?);
    response.set_ballot(ballot);
    response.set_voter_weight(voter_weight as u32);
    Ok(response)
}

pub fn certify_unbounded_voter(
    secret_key: &[u8],
    registration_request: &RegistrationRequest,
    value: u32,
) -> Result<RegistrationResponse, WedprError> {
    // generate weight ballot
    let blinding_poll_point = bytes_to_point(
        registration_request
            .get_weight_point()
            .get_blinding_poll_point(),
    )?;
    let weight_ciphertext1 =
        blinding_poll_point + (*BASEPOINT_G1 * (Scalar::from(value as u64)));
    let mut weight_ballot = Ballot::new();
    weight_ballot.set_ciphertext1(point_to_bytes(&weight_ciphertext1));
    weight_ballot.set_ciphertext2(
        registration_request
            .get_weight_point()
            .get_blinding_basepoint_g2()
            .to_vec(),
    );
    // generate zero ballot
    let mut zero_ballot = Ballot::new();
    zero_ballot.set_ciphertext1(
        registration_request
            .get_zero_point()
            .get_blinding_poll_point()
            .to_vec(),
    );
    zero_ballot.set_ciphertext2(
        registration_request
            .get_zero_point()
            .get_blinding_basepoint_g2()
            .to_vec(),
    );

    let mut response = RegistrationResponse::new();
    response.set_signature(generate_ballots_signature(
        secret_key,
        &weight_ballot,
        &zero_ballot,
    )?);
    response.set_ballot(weight_ballot);
    response.set_zero_ballot(zero_ballot);
    response.set_voter_weight(value);
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

pub fn aggregate_vote_sum_response_unlisted(
    poll_parameters: &PollParametersStorage,
    vote_part: &VoteStorage,
    vote_sum: &mut VoteStorage,
) -> Result<bool, WedprError> {
    aggregate_vote_sum_response(poll_parameters, vote_part, vote_sum)?;
    // aggregate all unlisted voting cipher ballot in vote_part
    for unlisted_ballot in vote_part.get_voted_ballot_unlisted() {
        vote_sum
            .mut_voted_ballot_unlisted()
            .push(unlisted_ballot.clone());
    }
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

pub fn aggregate_decrypted_part_for_specify_unlisted_candidate(
    decrypted_part: &UnlistedBallotDecryptedResult,
    aggregated_decrypted_part: &mut UnlistedBallotDecryptedResult,
) -> Result<bool, WedprError> {
    // counting for the unlisted candidate
    let current_aggregated_unlisted_candidate =
        aggregated_decrypted_part.get_decrypted_unlisted_candidate();
    let decrypted_part_unlisted_candidate =
        decrypted_part.get_decrypted_unlisted_candidate();
    let aggregated_unlisted_candidate = bytes_to_point(
        current_aggregated_unlisted_candidate.get_blinding_c2(),
    )? + bytes_to_point(
        decrypted_part_unlisted_candidate.get_blinding_c2(),
    )?;
    // update the aggregated_decrypt_result for ulisted candidate
    aggregated_decrypted_part
        .mut_decrypted_unlisted_candidate()
        .set_blinding_c2(point_to_bytes(&aggregated_unlisted_candidate));

    // push the cipher unlisted candidate ballot into aggregated_decrypted_part
    let unlisted_candidate_ballot =
        decrypted_part.get_decrypted_unlisted_candidate_ballot();
    // invalid decrypted_part
    if unlisted_candidate_ballot.len() < 1 {
        return Ok(false);
    }
    aggregated_decrypted_part
        .mut_decrypted_unlisted_candidate_ballot()
        .push((unlisted_candidate_ballot[0]).clone());
    Ok(true)
}

pub fn aggregate_decrypted_part_sum_unlisted(
    poll_parameters: &PollParametersStorage,
    partially_decrypted_result: &DecryptedResultPartStorage,
    aggregated_decrypted_result: &mut DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    aggregate_decrypted_part_sum(
        poll_parameters,
        partially_decrypted_result,
        aggregated_decrypted_result,
    )?;
    // aggregate unlisted candidate
    for unlisted_candidate_decrypt_part in
        partially_decrypted_result.get_unlisted_candidate_part()
    {
        let mut match_candidate = false;
        // find the aggregated_decrypted_part for the partially_decrypted_result
        for mut aggregated_decrypted_part in
            aggregated_decrypted_result.mut_unlisted_candidate_part()
        {
            if aggregated_decrypted_part.get_candidate_cipher()
                == unlisted_candidate_decrypt_part.get_candidate_cipher()
            {
                match_candidate =
                    aggregate_decrypted_part_for_specify_unlisted_candidate(
                        unlisted_candidate_decrypt_part,
                        &mut aggregated_decrypted_part,
                    )?;
                break;
            }
        }
        // insert a new item
        if !match_candidate {
            aggregated_decrypted_result
                .mut_unlisted_candidate_part()
                .push(unlisted_candidate_decrypt_part.clone());
        }
    }
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

pub fn decrypt_unlisted_candidate_ballot(
    decrypted_unlisted_candidate_ballot_result: &mut BTreeMap<u64, u64>,
    unlisted_candidate_part: &mut UnlistedBallotDecryptedResult,
    vote_sum: &VoteStorage,
    max_vote_limit: i64,
    max_candidate_number: i64,
) -> Result<bool, WedprError> {
    let candidate_cipher = unlisted_candidate_part.get_candidate_cipher();
    let aggregated_candidate_blinding_c2 = bytes_to_point(
        unlisted_candidate_part
            .get_decrypted_unlisted_candidate()
            .get_blinding_c2(),
    )?;
    // find the candidate id according to the candidate_cipher
    let target_total = bytes_to_point(candidate_cipher.get_ciphertext1())?
        - aggregated_candidate_blinding_c2;
    let mut decrypt_candidate_success = false;
    for i in 0..=max_candidate_number {
        let try_num = Scalar::from(i as u64);
        if target_total.eq(&((*BASEPOINT_G1) * (try_num))) {
            // find the candidate, update the candidate field of
            // unlisted_candidate_part
            unlisted_candidate_part.set_candidate(i);
            decrypt_candidate_success = true;
            break;
        }
    }
    if !decrypt_candidate_success {
        return Ok(false);
    }
    // decrypt the unlisted candidate ballot value when decrypt candidate
    // success
    for unlisted_vote_ballot in vote_sum.get_voted_ballot_unlisted() {
        if unlisted_candidate_part.get_candidate_cipher()
            != unlisted_vote_ballot.get_key()
        {
            continue;
        }
        // find out the unlisted vote ballot for the candidate
        // aggregate blinding_c2 decrypted cipher ballot unlisted
        let mut blinding_c2_sum = RistrettoPoint::default();
        for decrypted_unlisted_candidate_blinding_c2 in
            unlisted_candidate_part.get_decrypted_unlisted_candidate_ballot()
        {
            blinding_c2_sum += bytes_to_point(
                decrypted_unlisted_candidate_blinding_c2.get_blinding_c2(),
            )?;
        }
        // try to find out
        let c1 = bytes_to_point(
            unlisted_vote_ballot.get_ballot().get_ciphertext1(),
        )?;
        let target_total = c1 - blinding_c2_sum;
        // decrypt the ballot value
        for i in 0..max_vote_limit {
            let try_num = Scalar::from(i as u64);
            if !target_total.eq(&(*BASEPOINT_G1 * try_num)) {
                continue;
            }
            // merge the  candidate unlisted value
            let candidate = unlisted_candidate_part.get_candidate() as u64;
            if decrypted_unlisted_candidate_ballot_result
                .contains_key(&candidate)
            {
                let result_sum = decrypted_unlisted_candidate_ballot_result
                    .get(&candidate)
                    .unwrap()
                    + (i as u64);
                decrypted_unlisted_candidate_ballot_result
                    .insert(candidate, result_sum);
            } else {
                decrypted_unlisted_candidate_ballot_result
                    .insert(candidate, i as u64);
            }
        }
    }
    Ok(true)
}

pub fn finalize_vote_result_unlisted(
    poll_parameters: &PollParametersStorage,
    vote_sum: &VoteStorage,
    aggregated_decrypted_result: &mut DecryptedResultPartStorage,
    max_vote_limit: i64,
    max_candidate_number: i64,
) -> Result<VoteResultStorage, WedprError> {
    let mut vote_result = finalize_vote_result(
        poll_parameters,
        vote_sum,
        aggregated_decrypted_result,
        max_vote_limit,
    )?;
    // finalize the vote result for the unlisted-candidates
    let mut aggregated_unlisted_candidate_ballot_result = BTreeMap::new();
    for mut unlisted_candidate in
        aggregated_decrypted_result.mut_unlisted_candidate_part()
    {
        decrypt_unlisted_candidate_ballot(
            &mut aggregated_unlisted_candidate_ballot_result,
            &mut unlisted_candidate,
            &vote_sum,
            max_vote_limit,
            max_candidate_number,
        )?;
    }
    // push the aggregated_unlisted_candidate_ballot_result into
    // aggregated_decrypted_result
    for (key, value) in aggregated_unlisted_candidate_ballot_result {
        let mut unlisted_candidate_ballot_result = UnlistedVoteChoice::new();
        unlisted_candidate_ballot_result.set_candidate_id(key as u32);
        unlisted_candidate_ballot_result.set_value(value as u32);
        vote_result
            .mut_unlisted_result()
            .push(unlisted_candidate_ballot_result);
    }
    Ok(vote_result)
}
