// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a poll verifier.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use std::collections::{BTreeMap, BTreeSet};
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{
    verify_either_equality_relationship_proof,
    verify_equality_relationship_proof, verify_format_proof,
    verify_sum_relationship,
};
use wedpr_l_crypto_zkp_range_proof::verify_value_range_in_batch;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, Deserialize, BASEPOINT_G1, BASEPOINT_G2,
};
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::{
    generated::acv::BallotProof, verify_ballot_signature,
    verify_ballots_signature,
};

use wedpr_s_protos::generated::acv::{
    Ballot, CipherPointsToBallotPair, CipherPointsToBallotProofPair,
    DecryptedResultPartStorage, PollParametersStorage, StringToBallotProofPair,
    UnlistedBallotDecryptedResult, VoteRequest, VoteResultStorage, VoteStorage,
};

use crate::{
    config::POLL_RESULT_KEY_TOTAL_BALLOTS,
    utils::{
        align_commitment_list_if_needed, counter_part, get_ballot_by_candidate,
        get_counting_part_by_candidate, get_int64_by_candidate,
        validate_vote_candidates,
    },
};
/// Verifies whether ciphertext ballots from a certified voter are valid.
pub fn verify_vote_request(
    poll_parameters: &PollParametersStorage,
    vote_request: &VoteRequest,
    public_key: &[u8],
) -> Result<bool, WedprError> {
    validate_vote_request_structure(poll_parameters, vote_request, false)?;
    let poll_point = bytes_to_point(poll_parameters.get_poll_point())?;
    let signature = vote_request.get_vote().get_signature();

    let blank_ballot = vote_request.get_vote().get_blank_ballot();
    let verify_result = verify_ballot_signature(
        public_key,
        blank_ballot,
        &signature.to_vec(),
        poll_parameters,
    )?;
    if !verify_result {
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
            Deserialize::deserialize(&ballot_proof.get_format_proof())?;
        if !verify_format_proof(
            &ciphertext1,
            &ciphertext2,
            &format_proof,
            &*BASEPOINT_G1,
            &*BASEPOINT_G2,
            &poll_point,
        )? {
            return Err(WedprError::VerificationError);
        }
    }
    let balance_proof =
        Deserialize::deserialize(vote_request.get_sum_balance_proof())?;
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

fn validate_vote_request_structure(
    poll_parameters: &PollParametersStorage,
    vote_request: &VoteRequest,
    allow_unlisted: bool,
) -> Result<(), WedprError> {
    let vote = vote_request.get_vote();
    if poll_parameters.get_poll_id().len() != 32
        || vote.get_poll_id() != poll_parameters.get_poll_id()
    {
        return Err(WedprError::VerificationError);
    }
    if !vote.get_accepted_ballot_id().is_empty() {
        return Err(WedprError::VerificationError);
    }
    validate_vote_candidates(poll_parameters, vote)?;
    let ballot_candidates: BTreeSet<_> = vote
        .get_voted_ballot()
        .iter()
        .map(|pair| pair.get_candidate())
        .collect();
    let proof_candidates: BTreeSet<_> = vote_request
        .get_ballot_proof()
        .iter()
        .map(|pair| pair.get_key())
        .collect();
    if proof_candidates.len() != vote_request.get_ballot_proof().len()
        || proof_candidates != ballot_candidates
    {
        return Err(WedprError::VerificationError);
    }
    let ballots = vote.get_voted_ballot_unlisted();
    let proofs = vote_request.get_unlisted_ballot_proof();
    if !allow_unlisted && (!ballots.is_empty() || !proofs.is_empty()) {
        return Err(WedprError::VerificationError);
    }
    if !allow_unlisted
        && !vote_request.get_unlisted_candidate_range_proof().is_empty()
    {
        return Err(WedprError::VerificationError);
    }
    let ballot_keys: BTreeSet<_> = ballots
        .iter()
        .map(|pair| {
            (
                pair.get_key().get_ciphertext1(),
                pair.get_key().get_ciphertext2(),
            )
        })
        .collect();
    let proof_keys: BTreeSet<_> = proofs
        .iter()
        .map(|pair| {
            (
                pair.get_key().get_ciphertext1(),
                pair.get_key().get_ciphertext2(),
            )
        })
        .collect();
    if ballot_keys.len() != ballots.len()
        || proof_keys.len() != proofs.len()
        || ballot_keys != proof_keys
    {
        return Err(WedprError::VerificationError);
    }
    for ballot in ballots {
        bytes_to_point(ballot.get_key().get_ciphertext1())?;
        bytes_to_point(ballot.get_key().get_ciphertext2())?;
    }
    Ok(())
}

/// Verifies whether a partially decrypted result from a counter is valid.
pub fn verify_count_request(
    poll_parameters: &PollParametersStorage,
    encrypted_vote_sum: &VoteStorage,
    counter_share: &RistrettoPoint,
    partially_decrypted_result: &DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    validate_vote_candidates(poll_parameters, encrypted_vote_sum)?;
    if !has_expected_counting_parts(poll_parameters, partially_decrypted_result)
        || !partially_decrypted_result
            .get_unlisted_candidate_part()
            .is_empty()
        || !encrypted_vote_sum.get_voted_ballot_unlisted().is_empty()
    {
        return Ok(false);
    }
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
        Deserialize::deserialize(&blank_equality_proof_bytes)?;
    if !verify_equality_relationship_proof(
        &counter_share,
        &blank_c2_r,
        &&blank_equality_proof,
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
        let candidate_equality_proof =
            Deserialize::deserialize(counting_part.get_equality_proof())?;
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
/// Each counter's partial decryption must first be checked against its trusted
/// public share before aggregating it. This checks both listed and unlisted
/// totals.
pub fn verify_vote_result(
    poll_parameters: &PollParametersStorage,
    vote_sum: &VoteStorage,
    aggregated_decrypted_result: &DecryptedResultPartStorage,
    vote_result: &VoteResultStorage,
) -> Result<bool, WedprError> {
    validate_vote_candidates(poll_parameters, vote_sum)?;
    if !verify_aggregated_decryption(
        poll_parameters,
        vote_sum,
        aggregated_decrypted_result,
    )? {
        return Ok(false);
    }
    let mut expected_keys: BTreeSet<_> = poll_parameters
        .get_candidates()
        .get_candidate()
        .iter()
        .map(String::as_str)
        .collect();
    expected_keys.insert(POLL_RESULT_KEY_TOTAL_BALLOTS);
    let actual_keys: BTreeSet<_> = vote_result
        .get_result()
        .iter()
        .map(|pair| pair.get_key())
        .collect();
    if actual_keys.len() != vote_result.get_result().len()
        || actual_keys != expected_keys
        || vote_result
            .get_result()
            .iter()
            .any(|pair| pair.get_value() < 0)
    {
        return Ok(false);
    }
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
    verify_unlisted_vote_result(
        vote_sum,
        aggregated_decrypted_result,
        vote_result,
    )
}

pub(crate) fn verify_aggregated_decryption(
    poll: &PollParametersStorage,
    votes: &VoteStorage,
    aggregate: &DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    let records = aggregate.get_verified_counter_part();
    if records.is_empty()
        || records.len()
            != poll.get_counters().get_counter_parameters_share().len()
    {
        return Ok(false);
    }
    let mut rebuilt = DecryptedResultPartStorage::new();
    for record in records {
        let part = counter_part(record);
        let result = if votes.get_voted_ballot_unlisted().is_empty() {
            crate::coordinator::aggregate_decrypted_part_sum(
                poll,
                &part,
                &mut rebuilt,
                votes,
            )
        } else {
            crate::coordinator::aggregate_decrypted_part_sum_unlisted(
                poll,
                &part,
                &mut rebuilt,
                votes,
            )
        };
        if result.is_err() {
            return Ok(false);
        }
    }
    // Candidate IDs are recovered only during finalization; their correctness
    // is checked separately against the verified candidate decryption points.
    let mut normalized = aggregate.clone();
    for part in normalized.mut_unlisted_candidate_part() {
        part.set_candidate(0);
    }
    Ok(rebuilt == normalized)
}

fn verify_unlisted_vote_result(
    vote_sum: &VoteStorage,
    decrypted: &DecryptedResultPartStorage,
    result: &VoteResultStorage,
) -> Result<bool, WedprError> {
    let mut parts = BTreeMap::new();
    for part in decrypted.get_unlisted_candidate_part() {
        let cipher = part.get_candidate_cipher();
        let key = (cipher.get_ciphertext1(), cipher.get_ciphertext2());
        if parts.insert(key, part).is_some() {
            return Ok(false);
        }
    }
    if parts.len() != vote_sum.get_voted_ballot_unlisted().len() {
        return Ok(false);
    }
    let mut totals = BTreeMap::new();
    for ballot in vote_sum.get_voted_ballot_unlisted() {
        let cipher = ballot.get_key();
        let key = (cipher.get_ciphertext1(), cipher.get_ciphertext2());
        let part = match parts.remove(&key) {
            Some(part) => part,
            None => return Ok(false),
        };
        let candidate_id = part.get_candidate();
        if candidate_id < 0 || candidate_id > u32::max_value() as i64 {
            return Ok(false);
        }
        let candidate_point = bytes_to_point(cipher.get_ciphertext1())?
            - bytes_to_point(
                part.get_decrypted_unlisted_candidate().get_blinding_c2(),
            )?;
        if candidate_point != *BASEPOINT_G1 * Scalar::from(candidate_id as u64)
        {
            return Ok(false);
        }
        let shares = part.get_decrypted_unlisted_candidate_ballot();
        if shares.is_empty() {
            return Ok(false);
        }
        let mut plaintext =
            bytes_to_point(ballot.get_ballot().get_ciphertext1())?;
        for share in shares {
            plaintext -= bytes_to_point(share.get_blinding_c2())?;
        }
        *totals
            .entry(candidate_id as u32)
            .or_insert_with(RistrettoPoint::default) += plaintext;
    }
    if totals.len() != result.get_unlisted_result().len() {
        return Ok(false);
    }
    for entry in result.get_unlisted_result() {
        match totals.remove(&entry.get_candidate_id()) {
            Some(point)
                if point
                    == *BASEPOINT_G1
                        * Scalar::from(entry.get_value() as u64) => {},
            _ => return Ok(false),
        }
    }
    Ok(totals.is_empty())
}

fn verify_count_request_for_unlisted_candidate(
    counter_share: &RistrettoPoint,
    candidate_vote_sum: &CipherPointsToBallotPair,
    candidate_aggregated_unlisted_decrypted_result: &UnlistedBallotDecryptedResult,
) -> Result<bool, WedprError> {
    let unlisted_candidate_cipher = candidate_vote_sum.get_key();
    let unlisted_candidate_basepoint2 =
        bytes_to_point(unlisted_candidate_cipher.get_ciphertext2())?;
    let decrypted_unlisted_candidate =
        candidate_aggregated_unlisted_decrypted_result
            .get_decrypted_unlisted_candidate();
    let equality_proof = Deserialize::deserialize(
        &decrypted_unlisted_candidate.get_equality_proof(),
    )?;
    // verify the equality proof for unlisted candidate
    if !verify_equality_relationship_proof(
        &counter_share,
        &bytes_to_point(decrypted_unlisted_candidate.get_blinding_c2())?,
        &equality_proof,
        &BASEPOINT_G2,
        &unlisted_candidate_basepoint2,
    )? {
        return Ok(false);
    }
    // verify the equality proof for unlisted candidate ballot
    let unlisted_candidate_ballot = candidate_vote_sum.get_ballot();
    let decrypted_unlisted_candidate_ballot_list =
        candidate_aggregated_unlisted_decrypted_result
            .get_decrypted_unlisted_candidate_ballot();
    // without candidate ballot
    if decrypted_unlisted_candidate_ballot_list.len() != 1 {
        return Ok(false);
    }
    // verify equality proof for the candidate ballot
    let unlisted_candidate_ballot_basepoint2 =
        bytes_to_point(unlisted_candidate_ballot.get_ciphertext2())?;
    let equality_proof = Deserialize::deserialize(
        decrypted_unlisted_candidate_ballot_list[0].get_equality_proof(),
    )?;
    let c2_point = bytes_to_point(
        decrypted_unlisted_candidate_ballot_list[0].get_blinding_c2(),
    )?;
    if !verify_equality_relationship_proof(
        &counter_share,
        &c2_point,
        &equality_proof,
        &BASEPOINT_G2,
        &unlisted_candidate_ballot_basepoint2,
    )? {
        return Ok(false);
    }
    Ok(true)
}

fn verify_count_request_for_candidate(
    counter_share: &RistrettoPoint,
    candidate_id: &str,
    vote_sum: &VoteStorage,
    aggregated_decrypted_result: &DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    let candidate_ballot = get_ballot_by_candidate(vote_sum, candidate_id)?;
    let decrypted_candidate_part = get_counting_part_by_candidate(
        aggregated_decrypted_result,
        candidate_id,
    )?;
    let proof = Deserialize::deserialize(
        &decrypted_candidate_part.get_equality_proof(),
    )?;
    // verify equality from vote_sum to counting_sum
    if !verify_equality_relationship_proof(
        &counter_share,
        &(bytes_to_point(decrypted_candidate_part.get_blinding_c2())?),
        &proof,
        &BASEPOINT_G2,
        &(bytes_to_point(candidate_ballot.get_ciphertext2())?),
    )? {
        return Ok(false);
    }
    Ok(true)
}

pub fn verify_count_request_unlisted(
    poll_parameters: &PollParametersStorage,
    counter_share: &RistrettoPoint,
    vote_sum: &VoteStorage,
    aggregated_decrypted_result: &DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    validate_vote_candidates(poll_parameters, vote_sum)?;
    if !has_expected_counting_parts(
        poll_parameters,
        aggregated_decrypted_result,
    ) {
        return Ok(false);
    }
    let ballot_keys: BTreeSet<_> = vote_sum
        .get_voted_ballot_unlisted()
        .iter()
        .map(|ballot| {
            (
                ballot.get_key().get_ciphertext1(),
                ballot.get_key().get_ciphertext2(),
            )
        })
        .collect();
    let parts = aggregated_decrypted_result.get_unlisted_candidate_part();
    let part_keys: BTreeSet<_> = parts
        .iter()
        .map(|part| {
            (
                part.get_candidate_cipher().get_ciphertext1(),
                part.get_candidate_cipher().get_ciphertext2(),
            )
        })
        .collect();
    if ballot_keys.len() != vote_sum.get_voted_ballot_unlisted().len()
        || part_keys.len() != parts.len()
        || ballot_keys != part_keys
    {
        return Ok(false);
    }
    // verify equality for blank_ballot
    let blank_blinding_c2_sum =
        bytes_to_point(vote_sum.get_blank_ballot().get_ciphertext2())?;
    let blank_blinding_c2 = bytes_to_point(
        &aggregated_decrypted_result
            .get_blank_part()
            .get_blinding_c2(),
    )?;
    let blank_equality_proof = Deserialize::deserialize(
        &aggregated_decrypted_result
            .get_blank_part()
            .get_equality_proof(),
    )?;
    if !verify_equality_relationship_proof(
        &counter_share,
        &blank_blinding_c2,
        &blank_equality_proof,
        &BASEPOINT_G2,
        &blank_blinding_c2_sum,
    )? {
        return Ok(false);
    }
    // verify the candidate list
    for candidate in poll_parameters.get_candidates().get_candidate() {
        // verify the counter request for given candidate failed
        if !verify_count_request_for_candidate(
            &counter_share,
            &candidate,
            &vote_sum,
            &aggregated_decrypted_result,
        )? {
            return Ok(false);
        }
    }
    // verify the unlisted-candidate and the unlisted-candidate-ballot
    for unlisted_candidate_ballot in vote_sum.get_voted_ballot_unlisted() {
        // try to find the corresponding decrypted unlisted-candidate-ballot
        // from aggregated_decrypted_result
        let mut find_out_decrypted_result = false;
        for unlisted_candidate_part in
            aggregated_decrypted_result.get_unlisted_candidate_part()
        {
            if unlisted_candidate_ballot.get_key()
                != unlisted_candidate_part.get_candidate_cipher()
            {
                continue;
            }
            find_out_decrypted_result = true;
            // verify the unlisted-candidate
            if !verify_count_request_for_unlisted_candidate(
                &counter_share,
                &unlisted_candidate_ballot,
                &unlisted_candidate_part,
            )? {
                return Ok(false);
            }
            break;
        }
        // some unlisted-candidate-ballot without decrypted result, verify
        // failed
        if !find_out_decrypted_result {
            return Ok(false);
        }
    }
    Ok(true)
}

fn has_expected_counting_parts(
    poll_parameters: &PollParametersStorage,
    decrypted: &DecryptedResultPartStorage,
) -> bool {
    let expected: BTreeSet<_> = poll_parameters
        .get_candidates()
        .get_candidate()
        .iter()
        .map(String::as_str)
        .collect();
    let actual: BTreeSet<_> = decrypted
        .get_candidate_part()
        .iter()
        .map(|part| part.get_key())
        .collect();
    actual.len() == decrypted.get_candidate_part().len() && actual == expected
}

fn verify_ballot_proof(
    poll_parameters: &PollParametersStorage,
    ballot_proof: &BallotProof,
    candiate_ballot: &Ballot,
    weight_ballot: &Ballot,
    zero_ballot: &Ballot,
) -> Result<bool, WedprError> {
    // verify the format proof
    let format_proof =
        Deserialize::deserialize(&ballot_proof.get_format_proof())?;
    let polling_point = bytes_to_point(&poll_parameters.get_poll_point())?;
    let ret = verify_format_proof(
        &bytes_to_point(candiate_ballot.get_ciphertext1())?,
        &bytes_to_point(candiate_ballot.get_ciphertext2())?,
        &format_proof,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
        &polling_point,
    )?;
    if !ret {
        return Err(WedprError::VerificationError);
    }
    // verify either_equality_proof
    let either_equality_proof =
        Deserialize::deserialize(&ballot_proof.get_either_equality_proof())?;
    let verify_ret = verify_either_equality_relationship_proof(
        &bytes_to_point(candiate_ballot.get_ciphertext1())?,
        &bytes_to_point(weight_ballot.get_ciphertext1())?,
        &bytes_to_point(zero_ballot.get_ciphertext1())?,
        &either_equality_proof,
        &BASEPOINT_G1,
        &polling_point,
    )?;
    if !verify_ret {
        return Err(WedprError::VerificationError);
    }
    Ok(verify_ret)
}

fn batch_verify_ballot_proof(
    poll_parameters: &PollParametersStorage,
    vote_request: &VoteRequest,
    ballot_proof_infos: &Vec<StringToBallotProofPair>,
) -> Result<bool, WedprError> {
    let weight_ballot = vote_request.get_vote().get_blank_ballot();
    let zero_ballot = vote_request.get_vote().get_zero_ballot();
    for ballot_proof_info in ballot_proof_infos {
        let candidate = ballot_proof_info.get_key();
        let ballot_proof = ballot_proof_info.get_value();
        // find the candiate ballot
        let candidate_ballot =
            get_ballot_by_candidate(&vote_request.get_vote(), candidate)?;
        // verify the ballot proof
        let verify_result = verify_ballot_proof(
            &poll_parameters,
            &ballot_proof,
            &candidate_ballot,
            &weight_ballot,
            &zero_ballot,
        )?;
        if !verify_result {
            return Err(WedprError::VerificationError);
        }
    }
    Ok(true)
}

fn batch_verify_unlisted_candidate_ballot_proof(
    poll_parameters: &PollParametersStorage,
    vote_request: &VoteRequest,
    unlisted_ballot_proof_infos: &Vec<CipherPointsToBallotProofPair>,
) -> Result<bool, WedprError> {
    let weight_ballot = vote_request.get_vote().get_blank_ballot();
    let zero_ballot = vote_request.get_vote().get_zero_ballot();
    for unlisted_ballot_proof_info in unlisted_ballot_proof_infos {
        let candidate = unlisted_ballot_proof_info.get_key();
        let ballot_proof = unlisted_ballot_proof_info.get_value();
        let mut find_unlisted_candidate = false;
        // find the unlisted candiate ballot
        for unlisted_vote_ballot in
            vote_request.get_vote().get_voted_ballot_unlisted()
        {
            if unlisted_vote_ballot.get_key() != candidate {
                continue;
            }
            find_unlisted_candidate = true;
            // verify the found unlisted candidate ballot
            let verify_result = verify_ballot_proof(
                &poll_parameters,
                &ballot_proof,
                &unlisted_vote_ballot.get_ballot(),
                &weight_ballot,
                &zero_ballot,
            )?;
            if !verify_result {
                return Err(WedprError::VerificationError);
            }
        }
        if !find_unlisted_candidate {
            return Err(WedprError::VerificationError);
        }
    }
    Ok(true)
}

pub fn verify_unbounded_vote_request(
    poll_parameters: &PollParametersStorage,
    vote_request: &VoteRequest,
    public_key: &[u8],
) -> Result<bool, WedprError> {
    validate_vote_request_structure(poll_parameters, vote_request, false)?;
    verify_unbounded_vote_request_proofs(
        poll_parameters,
        vote_request,
        public_key,
    )
}

fn verify_unbounded_vote_request_proofs(
    poll_parameters: &PollParametersStorage,
    vote_request: &VoteRequest,
    public_key: &[u8],
) -> Result<bool, WedprError> {
    // check signature for the ballot with public key
    let signature = vote_request.get_vote().get_signature();
    let weight_ballot = vote_request.get_vote().get_blank_ballot();
    let zero_ballot = vote_request.get_vote().get_zero_ballot();
    let verify_result = verify_ballots_signature(
        public_key,
        weight_ballot,
        zero_ballot,
        &signature.to_vec(),
        poll_parameters,
    )?;
    if !verify_result {
        return Err(WedprError::VerificationError);
    }
    // verify the ballot proof
    let result = batch_verify_ballot_proof(
        &poll_parameters,
        &vote_request,
        &(vote_request.get_ballot_proof()).to_vec(),
    )?;
    if !result {
        return Err(WedprError::VerificationError);
    }
    Ok(true)
}

pub fn verify_unbounded_vote_request_unlisted(
    poll_parameters: &PollParametersStorage,
    vote_request: &VoteRequest,
    public_key: &[u8],
) -> Result<bool, WedprError> {
    validate_vote_request_structure(poll_parameters, vote_request, true)?;
    // verify the listed unbounded vote request
    let verify_result = verify_unbounded_vote_request_proofs(
        &poll_parameters,
        &vote_request,
        public_key,
    )?;
    if !verify_result {
        return Err(WedprError::VerificationError);
    }
    verify_unlisted_candidate_ids(poll_parameters, vote_request)?;
    // verify the unlisted unbouded vote request
    let result = batch_verify_unlisted_candidate_ballot_proof(
        &poll_parameters,
        &vote_request,
        &(vote_request.get_unlisted_ballot_proof()).to_vec(),
    )?;
    if !result {
        return Err(WedprError::VerificationError);
    }
    Ok(true)
}

fn verify_unlisted_candidate_ids(
    poll: &PollParametersStorage,
    request: &VoteRequest,
) -> Result<(), WedprError> {
    let ballots = request.get_vote().get_voted_ballot_unlisted();
    if ballots.is_empty() {
        return if request.get_unlisted_candidate_range_proof().is_empty() {
            Ok(())
        } else {
            Err(WedprError::VerificationError)
        };
    }
    let poll_point = bytes_to_point(poll.get_poll_point())?;
    for proof_pair in request.get_unlisted_ballot_proof() {
        let key = proof_pair.get_key();
        let proof =
            Deserialize::deserialize(proof_pair.get_candidate_format_proof())?;
        if !verify_format_proof(
            &bytes_to_point(key.get_ciphertext1())?,
            &bytes_to_point(key.get_ciphertext2())?,
            &proof,
            &BASEPOINT_G1,
            &BASEPOINT_G2,
            &poll_point,
        )? {
            return Err(WedprError::VerificationError);
        }
    }
    let mut commitments = vec![bytes_to_point(
        request.get_vote().get_blank_ballot().get_ciphertext1(),
    )?];
    let mut previous = None;
    for ballot in ballots {
        let point = bytes_to_point(ballot.get_key().get_ciphertext1())?;
        commitments.push(point);
        if let Some(previous_point) = previous {
            commitments.push(point - previous_point - *BASEPOINT_G1);
        }
        previous = Some(point);
    }
    align_commitment_list_if_needed(&mut commitments);
    if !verify_value_range_in_batch(
        &commitments,
        request.get_unlisted_candidate_range_proof(),
        &poll_point,
    ) {
        return Err(WedprError::VerificationError);
    }
    Ok(())
}
