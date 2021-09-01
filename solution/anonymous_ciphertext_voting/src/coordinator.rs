// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous ciphertext voting (ACV) solution.

use crate::config::{HASH_KECCAK256, SIGNATURE_SECP256K1};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_crypto_zkp_utils::{bytes_to_point, point_to_bytes, BASEPOINT_G1};
use wedpr_l_utils::{
    error::WedprError,
    traits::{Hash, Signature},
};
use wedpr_s_protos::generated::acv::{
    Ballot, CandidateList, CounterSystemParametersStorage, CountingPart,
    DecryptedResultPartStorage, RegistrationRequest, RegistrationResponse,
    StringToCountingPartPair, SystemParametersStorage,
};

/// Makes system parameters by candidate list and counter storage messages.
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

/// Certifies ballot value which voter can vote to all candidates.
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

/// Decrypts counters' .
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
