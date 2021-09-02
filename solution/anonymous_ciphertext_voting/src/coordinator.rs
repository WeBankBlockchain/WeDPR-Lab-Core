// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous ciphertext voting (ACV) solution.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_crypto_zkp_utils::{BASEPOINT_G1, bytes_to_point, point_to_bytes};
use wedpr_l_utils::{
    error::WedprError,
    traits::{Hash, Signature},
};

use wedpr_s_protos::generated::acv::{Ballot, CandidateBallot, CandidateList, CounterSystemParametersStorage, CountingPart, DecryptedResultPartStorage, RegistrationRequest, RegistrationResponse, StringToCountingPartPair, StringToInt64Pair, SystemParametersStorage, VoteResultStorage, VoteStorage};

use crate::config::{HASH_KECCAK256, SIGNATURE_SECP256K1};

/// Makes system parameters containing public key and candidates list using counter storage messages.
pub fn make_system_parameters(
    candidates: &CandidateList,
    counter_storage: &CounterSystemParametersStorage,
) -> Result<SystemParametersStorage, WedprError> {
    let mut poll_point = RistrettoPoint::default();
    for counter_request in counter_storage.get_counter_parameters_request() {
        poll_point += bytes_to_point(counter_request.get_poll_point_share())?;
    }
    let mut storage = SystemParametersStorage::default();
    storage.set_candidates(candidates.clone());
    storage.set_poll_point(point_to_bytes(&poll_point));
    Ok(storage)
}

/// Certifies voter's weight which indicates the maximum value that the voter can vote totally.
pub fn certify_bounded_voter(
    secret_key: &[u8],
    value: u32,
    registration_request: &RegistrationRequest,
) -> Result<RegistrationResponse, WedprError> {

    let blinding_poll_point = bytes_to_point(
        registration_request
            .get_weight_point()
            .get_blinding_poll_point(),
    )?;
    let ciphertext1 =
        blinding_poll_point + (*BASEPOINT_G1 * Scalar::from(value));
    let mut ballot = Ballot::new();
    ballot.set_ciphertext1(point_to_bytes(&ciphertext1));
    ballot.set_ciphertext2(
        registration_request
            .get_weight_point()
            .get_blinding_basepoint_g2()
            .to_vec(),
    );
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut ballot.get_ciphertext1().to_vec());
    hash_vec.append(&mut ballot.get_ciphertext2().to_vec());
    let message_hash = HASH_KECCAK256.hash(&hash_vec);
    let signature = SIGNATURE_SECP256K1.sign(secret_key, &message_hash)?;
    let mut response = RegistrationResponse::new();
    response.set_signature(signature);
    response.set_ballot(ballot);
    response.set_voter_weight(value);
    Ok(response)
}

/// Aggregates the decrypted results of all counters, ?
pub fn aggregate_decrypted_part_sum(
    param: &SystemParametersStorage,
    decrypted_result_part_storage: &DecryptedResultPartStorage,
    counting_result_sum: &mut DecryptedResultPartStorage,
) -> Result<bool, WedprError> {
    if !counting_result_sum.has_blank_part() {
        counting_result_sum
            .mut_blank_part()
            .set_counter_id("default".to_string());
        counting_result_sum
            .mut_blank_part()
            .set_blinding_c2(point_to_bytes(&RistrettoPoint::default()));
        for candidate in param.get_candidates().get_candidate() {
            let mut counting_part = CountingPart::new();
            counting_part.set_blinding_c2(point_to_bytes(&RistrettoPoint::default()));
            let mut tmp_pair = StringToCountingPartPair::new();
            tmp_pair.set_key(candidate.to_string());
            tmp_pair.set_value(counting_part);
            counting_result_sum.mut_candidate_part().push(tmp_pair);
        }
    }
    let mut blank_c2_r_sum =
        bytes_to_point(&counting_result_sum.get_blank_part().get_blinding_c2())?;
    let blank_part_share = bytes_to_point(
        &decrypted_result_part_storage.get_blank_part().get_blinding_c2(),
    )?;

    blank_c2_r_sum += blank_part_share;
    counting_result_sum
        .mut_blank_part()
        .set_blinding_c2(point_to_bytes(&blank_c2_r_sum));
    for candidate in param.get_candidates().get_candidate() {
        let mut candidate_counting_part = CountingPart::new();
        for tmp_pair in counting_result_sum.get_candidate_part() {
            if candidate == tmp_pair.get_key() {
                candidate_counting_part = tmp_pair.get_value().clone();
            }
        }

        let mut candidate_c2_r_sum =
            bytes_to_point(&candidate_counting_part.get_blinding_c2())?;

        let mut counting_part = CountingPart::new();
        for tmp_pair in decrypted_result_part_storage.get_candidate_part() {
            if candidate == tmp_pair.get_key() {
                counting_part = tmp_pair.get_value().clone();
            }
        }

        let candidate_c2_r = bytes_to_point(&counting_part.get_blinding_c2())?;
        candidate_c2_r_sum += candidate_c2_r;
        let mut candidate_part = CountingPart::new();
        candidate_part.set_blinding_c2(point_to_bytes(&candidate_c2_r_sum));
        let mut tmp_pair = StringToCountingPartPair::new();
        tmp_pair.set_key(candidate.to_string());
        tmp_pair.set_value(candidate_part);
        counting_result_sum.mut_candidate_part().push(tmp_pair);
    }
    Ok(true)
}

/// ?
pub fn aggregate_vote_sum_response(
    param: &SystemParametersStorage,
    vote_storage_part: &VoteStorage,
    vote_sum: &mut VoteStorage,
) -> Result<bool, WedprError> {
    if !vote_sum.has_blank_ballot() {
        vote_sum
            .mut_blank_ballot()
            .set_ciphertext1(point_to_bytes(&RistrettoPoint::default()));
        vote_sum
            .mut_blank_ballot()
            .set_ciphertext2(point_to_bytes(&RistrettoPoint::default()));
        for candidate in param.get_candidates().get_candidate() {
            let mut ballot = Ballot::new();
            ballot.set_ciphertext1(point_to_bytes(&RistrettoPoint::default()));
            ballot.set_ciphertext2(point_to_bytes(&RistrettoPoint::default()));
            let mut ballot_pair = CandidateBallot::new();
            ballot_pair.set_candidate(candidate.to_string());
            ballot_pair.set_ballot(ballot);
            vote_sum.mut_voted_ballot().push(ballot_pair);
        }
    }

    let mut tmp_vote_storage_sum = VoteStorage::new();
    let mut blank_c1_sum =
        bytes_to_point(&vote_sum.get_blank_ballot().get_ciphertext1())?;
    let mut blank_c2_sum =
        bytes_to_point(&vote_sum.get_blank_ballot().get_ciphertext2())?;
    let c1_tmp_point = bytes_to_point(
        &vote_storage_part
            .get_blank_ballot()
            .get_ciphertext1()
            .clone(),
    )?;
    let c2_tmp_point = bytes_to_point(
        &vote_storage_part
            .get_blank_ballot()
            .get_ciphertext2()
            .clone(),
    )?;
    blank_c1_sum += c1_tmp_point;
    blank_c2_sum += c2_tmp_point;

    for candidate in param.get_candidates().get_candidate() {
        let mut candidate_ballot = Ballot::new();
        for tmp_pair in vote_sum.get_voted_ballot() {
            if tmp_pair.get_candidate() == candidate {
                candidate_ballot = tmp_pair.get_ballot().clone();
            }
        }
        let mut candidate_voted_c1_sum =
            bytes_to_point(&candidate_ballot.get_ciphertext1())?;
        let mut candidate_voted_c2_sum =
            bytes_to_point(&candidate_ballot.get_ciphertext2())?;
        let mut candidates_ballot = Ballot::new();
        for ballot_pair in vote_storage_part.get_voted_ballot() {
            if candidate == ballot_pair.get_candidate() {
                candidates_ballot = ballot_pair.get_ballot().clone();
            }
        }
        candidate_voted_c1_sum +=
            bytes_to_point(&candidates_ballot.get_ciphertext1())?;
        candidate_voted_c2_sum +=
            bytes_to_point(&candidates_ballot.get_ciphertext2())?;
        let mut vote_ballot = Ballot::new();
        vote_ballot.set_ciphertext1(point_to_bytes(&candidate_voted_c1_sum));
        vote_ballot.set_ciphertext2(point_to_bytes(&candidate_voted_c2_sum));
        let mut tmp_pair = CandidateBallot::new();
        tmp_pair.set_candidate(candidate.to_string());
        tmp_pair.set_ballot(vote_ballot);
        tmp_vote_storage_sum.mut_voted_ballot().push(tmp_pair);
    }
    tmp_vote_storage_sum
        .mut_blank_ballot()
        .set_ciphertext1(point_to_bytes(&blank_c1_sum));
    tmp_vote_storage_sum
        .mut_blank_ballot()
        .set_ciphertext2(point_to_bytes(&blank_c2_sum));
    *vote_sum = tmp_vote_storage_sum.clone();
    Ok(true)
}

/// Count the value of ballots received by each candidate.
pub fn finalize_vote_result(
    param: &SystemParametersStorage,
    vote_sum: &VoteStorage,
    counting_result_sum: &DecryptedResultPartStorage,
    max_number: i64,
) -> Result<VoteResultStorage, WedprError> {
    let mut request = VoteResultStorage::new();
    let blank_c1_sum =
        bytes_to_point(vote_sum.get_blank_ballot().get_ciphertext1())?;
    let blank_c2_r_sum =
        bytes_to_point(counting_result_sum.get_blank_part().get_blinding_c2())?;
    let tmp = blank_c1_sum - (blank_c2_r_sum);
    for i in 1..=max_number {
        let try_num = Scalar::from(i as u64);
        if tmp.eq(&(*BASEPOINT_G1 * try_num)) {
            let mut tmp_pair = StringToInt64Pair::new();
            tmp_pair.set_key("Wedpr_voting_total_ballots".to_string());
            tmp_pair.set_value(i);
            request.mut_result().push(tmp_pair);
            break;
        }
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
            bytes_to_point(candidate_counting_part.get_blinding_c2())?;
        let tmp =
            bytes_to_point(ballot.get_ciphertext1())? - (candidate_c2_r_sum);

        for i in 0..=max_number {
            let try_num = Scalar::from(i as u64);

            if tmp.eq(&(*BASEPOINT_G1 * try_num)) {
                let mut tmp_pair = StringToInt64Pair::new();
                tmp_pair.set_key(candidate.to_string());
                tmp_pair.set_value(i);
                request.mut_result().push(tmp_pair);
                break;
            }
        }
    }
    Ok(request)
}
