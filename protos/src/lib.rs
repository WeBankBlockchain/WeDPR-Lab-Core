// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of protobuf definitions and their generated code.
#[macro_use]
extern crate lazy_static;
use crate::{
    config::{HASH, SIGNATURE},
    generated::{
        acv::{Ballot, PollParametersStorage},
        zkp::PBBalanceProof,
    },
};
use wedpr_l_utils::{
    error::WedprError,
    traits::{Hash, Signature},
};
pub mod config;
pub mod generated;

use protobuf::Message;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, point_to_bytes, scalar_to_bytes,
    ArithmeticProof,
};

pub fn proto_to_bytes<T: Message>(proto: &T) -> Result<Vec<u8>, WedprError> {
    return match proto.write_to_bytes() {
        Ok(v) => Ok(v),
        Err(_) => Err(WedprError::DecodeError),
    };
}

pub fn bytes_to_proto<T: Message>(proto_bytes: &[u8]) -> Result<T, WedprError> {
    return match T::parse_from_bytes(proto_bytes) {
        Ok(v) => Ok(v),
        Err(_) => Err(WedprError::DecodeError),
    };
}

// from struct ArithmeticProof to PBBalanceProof
pub fn arithmetric_proof_to_pb(
    arithmetric_proof: &ArithmeticProof,
) -> PBBalanceProof {
    let mut pb_proof = PBBalanceProof::new();
    pb_proof.set_t1(point_to_bytes(&arithmetric_proof.t1));
    pb_proof.set_t2(point_to_bytes(&arithmetric_proof.t2));
    pb_proof.set_t3(point_to_bytes(&arithmetric_proof.t3));
    pb_proof.set_m1(scalar_to_bytes(&arithmetric_proof.m1));
    pb_proof.set_m2(scalar_to_bytes(&arithmetric_proof.m2));
    pb_proof.set_m3(scalar_to_bytes(&arithmetric_proof.m3));
    pb_proof.set_m4(scalar_to_bytes(&arithmetric_proof.m4));
    pb_proof.set_m5(scalar_to_bytes(&arithmetric_proof.m5));
    pb_proof
}

// from PBBalanceProof to struct ArithmeticProof
pub fn pb_to_arithmetric_proof(
    arithmetric_proof: &PBBalanceProof,
) -> Result<ArithmeticProof, WedprError> {
    Ok(ArithmeticProof {
        t1: bytes_to_point(&arithmetric_proof.get_t1())?,
        t2: bytes_to_point(&arithmetric_proof.get_t2())?,
        t3: bytes_to_point(&arithmetric_proof.get_t3())?,
        m1: bytes_to_scalar(&arithmetric_proof.get_m1())?,
        m2: bytes_to_scalar(&arithmetric_proof.get_m2())?,
        m3: bytes_to_scalar(&arithmetric_proof.get_m3())?,
        m4: bytes_to_scalar(&arithmetric_proof.get_m4())?,
        m5: bytes_to_scalar(&arithmetric_proof.get_m5())?,
    })
}

// generate signature for the ballot
pub fn generate_ballot_signature(
    secret_key: &[u8],
    ballot: &Ballot,
    poll_parameters: &PollParametersStorage,
) -> Result<Vec<u8>, WedprError> {
    let message_hash = credential_hash(poll_parameters, &[ballot])?;
    SIGNATURE.sign(secret_key, &message_hash)
}

pub fn generate_ballots_signature(
    secret_key: &[u8],
    weight_ballot: &Ballot,
    zero_ballot: &Ballot,
    poll_parameters: &PollParametersStorage,
) -> Result<Vec<u8>, WedprError> {
    let message_hash =
        credential_hash(poll_parameters, &[weight_ballot, zero_ballot])?;
    SIGNATURE.sign(secret_key, &message_hash)
}

pub fn verify_ballot_signature(
    public_key: &[u8],
    ballot: &Ballot,
    signature: &Vec<u8>,
    poll_parameters: &PollParametersStorage,
) -> Result<bool, WedprError> {
    let message_hash = credential_hash(poll_parameters, &[ballot])?;
    Ok(SIGNATURE.verify(
        &public_key,
        &message_hash.as_ref(),
        &signature.as_slice(),
    ))
}

pub fn verify_ballots_signature(
    public_key: &[u8],
    weight_ballot: &Ballot,
    zero_ballot: &Ballot,
    signature: &Vec<u8>,
    poll_parameters: &PollParametersStorage,
) -> Result<bool, WedprError> {
    let message_hash =
        credential_hash(poll_parameters, &[weight_ballot, zero_ballot])?;
    Ok(SIGNATURE.verify(
        &public_key,
        &message_hash.as_ref(),
        &signature.as_slice(),
    ))
}

// Length-prefix variable fields and distinguish the two credential types.
// Ignore protobuf unknown fields: the signed context is defined by these
// fields.
fn credential_hash(
    poll: &PollParametersStorage,
    ballots: &[&Ballot],
) -> Result<Vec<u8>, WedprError> {
    if poll.get_poll_id().len() != 32 || poll.get_poll_point().len() != 32 {
        return Err(WedprError::ArgumentError);
    }
    let mut message = b"WeDPR/ACV/credential/v2".to_vec();
    message.push(ballots.len() as u8);
    message.extend_from_slice(poll.get_poll_id());
    message.extend_from_slice(poll.get_poll_point());
    let candidates = poll.get_candidates().get_candidate();
    message.extend_from_slice(&(candidates.len() as u64).to_be_bytes());
    for candidate in candidates {
        message.extend_from_slice(&(candidate.len() as u64).to_be_bytes());
        message.extend_from_slice(candidate.as_bytes());
    }
    let counters = poll.get_counters().get_counter_parameters_share();
    message.extend_from_slice(&(counters.len() as u64).to_be_bytes());
    for counter in counters {
        message.extend_from_slice(
            &(counter.get_counter_id().len() as u64).to_be_bytes(),
        );
        message.extend_from_slice(counter.get_counter_id().as_bytes());
        if counter.get_poll_point_share().len() != 32 {
            return Err(WedprError::FormatError);
        }
        message.extend_from_slice(counter.get_poll_point_share());
    }
    for ballot in ballots {
        for ciphertext in
            [ballot.get_ciphertext1(), ballot.get_ciphertext2()].iter()
        {
            if ciphertext.len() != 32 {
                return Err(WedprError::FormatError);
            }
            bytes_to_point(ciphertext)?;
            message.extend_from_slice(ciphertext);
        }
    }
    Ok(HASH.hash(&message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use generated::zkp::PBBalanceProof;

    #[test]
    fn test_parser() {
        let mut proof = PBBalanceProof::new();
        proof.set_check1("test1".as_bytes().to_vec());
        proof.set_check2("test2".as_bytes().to_vec());
        let bytes = proto_to_bytes(&proof).unwrap();
        let proof_parser = bytes_to_proto::<PBBalanceProof>(&bytes).unwrap();
        assert_eq!(proof_parser, proof);
    }
}
