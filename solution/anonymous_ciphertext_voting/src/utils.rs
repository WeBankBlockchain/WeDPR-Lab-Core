// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of ACV utility functions.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::acv::{
    Ballot, CountingPart, DecryptedResultPartStorage, VoteResultStorage,
    VoteStorage,
};

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
