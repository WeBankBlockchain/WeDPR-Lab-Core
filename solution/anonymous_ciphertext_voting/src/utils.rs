// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of ACV utility functions.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use std::collections::BTreeSet;
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::acv::{
    Ballot, CounterDecryptionRecord, CountingPart, DecryptedResultPartStorage,
    PollParametersStorage, VoteResultStorage, VoteStorage,
};

pub fn counter_record(
    part: &DecryptedResultPartStorage,
) -> CounterDecryptionRecord {
    let mut record = CounterDecryptionRecord::new();
    record.set_blank_part(part.get_blank_part().clone());
    record.set_candidate_part(part.get_candidate_part().to_vec().into());
    record.set_unlisted_candidate_part(
        part.get_unlisted_candidate_part().to_vec().into(),
    );
    record
}

pub fn counter_part(
    record: &CounterDecryptionRecord,
) -> DecryptedResultPartStorage {
    let mut part = DecryptedResultPartStorage::new();
    part.set_blank_part(record.get_blank_part().clone());
    part.set_candidate_part(record.get_candidate_part().to_vec().into());
    part.set_unlisted_candidate_part(
        record.get_unlisted_candidate_part().to_vec().into(),
    );
    part
}

pub fn counter_binding_scalar(counter_id: &str) -> Scalar {
    let mut context = b"WeDPR/ACV/counter-key/v2".to_vec();
    context.extend_from_slice(&(counter_id.len() as u64).to_be_bytes());
    context.extend_from_slice(counter_id.as_bytes());
    wedpr_l_crypto_zkp_utils::hash_to_scalar(&context)
}

pub fn validate_vote_candidates(
    poll_parameters: &PollParametersStorage,
    vote: &VoteStorage,
) -> Result<(), WedprError> {
    if poll_parameters.get_poll_id().len() != 32
        || vote.get_poll_id() != poll_parameters.get_poll_id()
    {
        return Err(WedprError::VerificationError);
    }
    let expected: BTreeSet<_> = poll_parameters
        .get_candidates()
        .get_candidate()
        .iter()
        .map(String::as_str)
        .collect();
    let actual: BTreeSet<_> = vote
        .get_voted_ballot()
        .iter()
        .map(|pair| pair.get_candidate())
        .collect();
    if expected.len() != poll_parameters.get_candidates().get_candidate().len()
        || actual.len() != vote.get_voted_ballot().len()
        || actual != expected
    {
        return Err(WedprError::VerificationError);
    }
    Ok(())
}

/// Recovers a small nonnegative plaintext, failing if the configured bound is
/// insufficient.
pub fn decode_vote_value(
    target: &RistrettoPoint,
    max_value: i64,
) -> Result<u64, WedprError> {
    if max_value < 0 {
        return Err(WedprError::ArgumentError);
    }
    let mut point = RistrettoPoint::default();
    for value in 0..=max_value {
        if point == *target {
            return Ok(value as u64);
        }
        point += *wedpr_l_crypto_zkp_utils::BASEPOINT_G1;
    }
    Err(WedprError::VerificationError)
}

pub fn get_counting_part_by_candidate(
    decrypted_result: &DecryptedResultPartStorage,
    candidate: &str,
) -> Result<CountingPart, WedprError> {
    for pair in decrypted_result.get_candidate_part() {
        if pair.get_key() == candidate {
            return Ok(pair.get_value().clone());
        }
    }
    Err(WedprError::ArgumentError)
}

pub fn get_ballot_by_candidate(
    vote_storage: &VoteStorage,
    candidate: &str,
) -> Result<Ballot, WedprError> {
    for pair in vote_storage.get_voted_ballot() {
        if pair.get_candidate() == candidate {
            return Ok(pair.get_ballot().clone());
        }
    }
    Err(WedprError::ArgumentError)
}

pub fn get_int64_by_candidate(
    vote_result: &VoteResultStorage,
    candidate: &str,
) -> Result<i64, WedprError> {
    for pair in vote_result.get_result() {
        if pair.get_key() == candidate {
            return Ok(pair.get_value());
        }
    }
    Err(WedprError::ArgumentError)
}

pub fn align_commitment_list_if_needed(list: &mut Vec<RistrettoPoint>) {
    let pending_length = compute_pending_size(list.len());
    for _ in 0..pending_length {
        list.push(RistrettoPoint::default());
    }
}

pub fn align_u64_list_if_needed(list: &mut Vec<u64>) {
    let pending_length = compute_pending_size(list.len());
    for _ in 0..pending_length {
        list.push(0u64);
    }
}

pub fn align_scalar_list_if_needed(list: &mut Vec<Scalar>) {
    let pending_length = compute_pending_size(list.len());
    for _ in 0..pending_length {
        list.push(Scalar::default());
    }
}

fn compute_pending_size(length: usize) -> usize {
    let log_length = (length as f64).log2().ceil() as u32;
    let aligned_length = 2_i32.pow(log_length) as usize;
    aligned_length - length
}
