// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a poll coordinator.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_crypto_zkp_discrete_logarithm_proof::verify_equality_relationship_proof;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, point_to_bytes, Deserialize, BASEPOINT_G1, BASEPOINT_G2,
};
use wedpr_l_utils::error::WedprError;

use wedpr_l_utils::traits::Hash;
use wedpr_s_protos::{
    config::HASH,
    generate_ballot_signature, generate_ballots_signature,
    generated::acv::{
        Ballot, CandidateBallot, CandidateList, CounterParametersStorage,
        CountingPart, DecryptedResultPartStorage, PollParametersStorage,
        RegistrationBlindingPoint, RegistrationRequest, RegistrationResponse,
        StringToCountingPartPair, StringToInt64Pair,
        UnlistedBallotDecryptedResult, UnlistedVoteChoice, VoteResultStorage,
        VoteStorage,
    },
};

use crate::{
    config::POLL_RESULT_KEY_TOTAL_BALLOTS,
    utils::{
        decode_vote_value, get_ballot_by_candidate,
        get_counting_part_by_candidate, validate_vote_candidates,
    },
};

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
};

/// Makes system parameters for a new poll.
pub fn make_poll_parameters(
    candidate_list: &CandidateList,
    counter_parameters: &CounterParametersStorage,
) -> Result<PollParametersStorage, WedprError> {
    let candidates = candidate_list.get_candidate();
    if candidates
        .iter()
        .any(|candidate| candidate == POLL_RESULT_KEY_TOTAL_BALLOTS)
        || candidates.iter().collect::<BTreeSet<_>>().len() != candidates.len()
    {
        return Err(WedprError::ArgumentError);
    }
    let shares = counter_parameters.get_counter_parameters_share();
    if shares.is_empty()
        || shares
            .iter()
            .map(|share| share.get_counter_id())
            .collect::<BTreeSet<_>>()
            .len()
            != shares.len()
    {
        return Err(WedprError::ArgumentError);
    }
    let mut poll_point = RistrettoPoint::default();
    for share in counter_parameters.get_counter_parameters_share() {
        poll_point += bytes_to_point(share.get_poll_point_share())?;
    }
    if poll_point == RistrettoPoint::default() {
        return Err(WedprError::ArgumentError);
    }

    let mut storage = PollParametersStorage::default();
    storage.set_candidates(candidate_list.clone());
    storage.set_poll_point(point_to_bytes(&poll_point));
    Ok(storage)
}

/// Certifies a voter's registration. It confirm its weight which indicates the
/// maximum votes that the voter can vote for all candidates in a poll.
/// `poll_parameters` must be the coordinator's trusted parameters for this
/// poll.
pub fn certify_voter(
    secret_key: &[u8],
    registration_request: &RegistrationRequest,
    voter_weight: u32,
    poll_parameters: &PollParametersStorage,
) -> Result<RegistrationResponse, WedprError> {
    verify_registration_blinding_point(
        registration_request.get_weight_point(),
        poll_parameters,
    )?;
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

/// Certifies the weight and zero ballots after verifying both registration
/// proofs. `poll_parameters` must come from the coordinator's trusted poll
/// state.
pub fn certify_unbounded_voter(
    secret_key: &[u8],
    registration_request: &RegistrationRequest,
    value: u32,
    poll_parameters: &PollParametersStorage,
) -> Result<RegistrationResponse, WedprError> {
    verify_registration_blinding_point(
        registration_request.get_weight_point(),
        poll_parameters,
    )?;
    verify_registration_blinding_point(
        registration_request.get_zero_point(),
        poll_parameters,
    )?;
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

fn verify_registration_blinding_point(
    registration: &RegistrationBlindingPoint,
    poll_parameters: &PollParametersStorage,
) -> Result<(), WedprError> {
    let poll_point = bytes_to_point(poll_parameters.get_poll_point())?;
    if poll_point == RistrettoPoint::default() {
        return Err(WedprError::ArgumentError);
    }
    let proof = Deserialize::deserialize(registration.get_equality_proof())?;
    if !verify_equality_relationship_proof(
        &bytes_to_point(registration.get_blinding_poll_point())?,
        &bytes_to_point(registration.get_blinding_basepoint_g2())?,
        &proof,
        &poll_point,
        &BASEPOINT_G2,
    )? {
        return Err(WedprError::VerificationError);
    }
    Ok(())
}

/// Aggregates all ciphertext ballots from a voter.
/// First verify the complete VoteRequest. Persist the resulting VoteStorage
/// atomically, including accepted_ballot_id, to reject reused credentials.
pub fn aggregate_vote_sum_response(
    poll_parameters: &PollParametersStorage,
    vote_part: &VoteStorage,
    vote_sum: &mut VoteStorage,
) -> Result<bool, WedprError> {
    validate_vote_candidates(poll_parameters, vote_part)?;
    if !vote_part.get_accepted_ballot_id().is_empty() {
        return Err(WedprError::ArgumentError);
    }
    if vote_sum.has_blank_ballot()
        && vote_sum.get_accepted_ballot_id().is_empty()
    {
        // Legacy aggregates lack the credential history required to reject
        // replays.
        return Err(WedprError::ArgumentError);
    }
    let blank = vote_part.get_blank_ballot();
    let mut credential =
        point_to_bytes(&bytes_to_point(blank.get_ciphertext1())?);
    credential
        .extend(point_to_bytes(&bytes_to_point(blank.get_ciphertext2())?));
    let ballot_id = HASH.hash(&credential);
    if vote_sum
        .get_accepted_ballot_id()
        .iter()
        .any(|accepted| accepted == &ballot_id)
    {
        return Err(WedprError::VerificationError);
    }
    let initializing = !vote_sum.has_blank_ballot();
    if !initializing {
        validate_vote_candidates(poll_parameters, vote_sum)?;
    } else if !vote_sum.get_voted_ballot().is_empty()
        || !vote_sum.get_accepted_ballot_id().is_empty()
    {
        return Err(WedprError::ArgumentError);
    }

    let c1_point =
        bytes_to_point(&vote_part.get_blank_ballot().get_ciphertext1())?;
    let blank_c1_sum = if initializing {
        c1_point
    } else {
        bytes_to_point(vote_sum.get_blank_ballot().get_ciphertext1())?
            + c1_point
    };
    let c2_point =
        bytes_to_point(&vote_part.get_blank_ballot().get_ciphertext2())?;
    let blank_c2_sum = if initializing {
        c2_point
    } else {
        bytes_to_point(vote_sum.get_blank_ballot().get_ciphertext2())?
            + c2_point
    };

    let mut updated_vote_sum_list = Vec::new();
    for candidate in poll_parameters.get_candidates().get_candidate() {
        let new_ballot = get_ballot_by_candidate(&vote_part, candidate)?;
        let mut candidate_voted_c1_sum =
            bytes_to_point(new_ballot.get_ciphertext1())?;
        let mut candidate_voted_c2_sum =
            bytes_to_point(new_ballot.get_ciphertext2())?;
        if !initializing {
            let sum_ballot = get_ballot_by_candidate(vote_sum, candidate)?;
            candidate_voted_c1_sum +=
                bytes_to_point(sum_ballot.get_ciphertext1())?;
            candidate_voted_c2_sum +=
                bytes_to_point(sum_ballot.get_ciphertext2())?;
        }

        // Write back.
        let mut new_sum_ballot = Ballot::new();
        new_sum_ballot.set_ciphertext1(point_to_bytes(&candidate_voted_c1_sum));
        new_sum_ballot.set_ciphertext2(point_to_bytes(&candidate_voted_c2_sum));
        let mut new_pair = CandidateBallot::new();
        new_pair.set_candidate(candidate.to_string());
        new_pair.set_ballot(new_sum_ballot);
        updated_vote_sum_list.push(new_pair);
    }
    // update the voted_ballot for vote sum
    vote_sum.clear_voted_ballot();
    for voted_ballot in updated_vote_sum_list {
        vote_sum.mut_voted_ballot().push(voted_ballot);
    }
    vote_sum
        .mut_blank_ballot()
        .set_ciphertext1(point_to_bytes(&blank_c1_sum));
    vote_sum
        .mut_blank_ballot()
        .set_ciphertext2(point_to_bytes(&blank_c2_sum));
    vote_sum.mut_accepted_ballot_id().push(ballot_id);
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

    let mut updated_candidate_part_list = Vec::new();
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
        updated_candidate_part_list.push(new_pair);
    }
    aggregated_decrypted_result.clear_candidate_part();
    for updated_candidate_part in updated_candidate_part_list {
        aggregated_decrypted_result
            .mut_candidate_part()
            .push(updated_candidate_part);
    }
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
    validate_vote_candidates(poll_parameters, vote_sum)?;
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
    let mut total = StringToInt64Pair::new();
    total.set_key(POLL_RESULT_KEY_TOTAL_BALLOTS.to_string());
    total.set_value(decode_vote_value(&target_total, max_vote_limit)? as i64);
    result.mut_result().push(total);

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

        let mut new_pair = StringToInt64Pair::new();
        new_pair.set_key(candidate.to_string());
        new_pair.set_value(
            decode_vote_value(&target_candidate, max_vote_limit)? as i64,
        );
        result.mut_result().push(new_pair);
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
    let candidate_id = decode_vote_value(&target_total, max_candidate_number)?;
    u32::try_from(candidate_id).map_err(|_| WedprError::ArgumentError)?;
    unlisted_candidate_part.set_candidate(candidate_id as i64);
    // decrypt the unlisted candidate ballot value when decrypt candidate
    // success
    let mut found_ballot = false;
    for unlisted_vote_ballot in vote_sum.get_voted_ballot_unlisted() {
        if unlisted_candidate_part.get_candidate_cipher()
            != unlisted_vote_ballot.get_key()
        {
            continue;
        }
        if found_ballot
            || unlisted_candidate_part
                .get_decrypted_unlisted_candidate_ballot()
                .is_empty()
        {
            return Err(WedprError::VerificationError);
        }
        found_ballot = true;
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
        let value = decode_vote_value(&target_total, max_vote_limit)?;
        let sum = decrypted_unlisted_candidate_ballot_result
            .entry(candidate_id)
            .or_insert(0);
        *sum = sum.checked_add(value).ok_or(WedprError::ArgumentError)?;
    }
    if !found_ballot {
        return Err(WedprError::VerificationError);
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
        if !decrypt_unlisted_candidate_ballot(
            &mut aggregated_unlisted_candidate_ballot_result,
            &mut unlisted_candidate,
            &vote_sum,
            max_vote_limit,
            max_candidate_number,
        )? {
            return Err(WedprError::VerificationError);
        }
    }
    // push the aggregated_unlisted_candidate_ballot_result into
    // aggregated_decrypted_result
    for (key, value) in aggregated_unlisted_candidate_ballot_result {
        let mut unlisted_candidate_ballot_result = UnlistedVoteChoice::new();
        unlisted_candidate_ballot_result.set_candidate_id(
            u32::try_from(key).map_err(|_| WedprError::ArgumentError)?,
        );
        unlisted_candidate_ballot_result.set_value(
            u32::try_from(value).map_err(|_| WedprError::ArgumentError)?,
        );
        vote_result
            .mut_unlisted_result()
            .push(unlisted_candidate_ballot_result);
    }
    if !crate::verifier::verify_vote_result(
        poll_parameters,
        vote_sum,
        aggregated_decrypted_result,
        &vote_result,
    )? {
        return Err(WedprError::VerificationError);
    }
    Ok(vote_result)
}
