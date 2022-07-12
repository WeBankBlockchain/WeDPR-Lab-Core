// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a poll voter.

use crate::utils::{align_scalar_list_if_needed, align_u64_list_if_needed};
use wedpr_s_protos::{arithmetric_proof_to_pb, format_proof_to_pb};

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{
    prove_format_proof, prove_sum_relationship,
};
use wedpr_l_crypto_zkp_range_proof::prove_value_range_in_batch;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, get_random_scalar, point_to_bytes,
    scalar_to_bytes, BASEPOINT_G1, BASEPOINT_G2,
};
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::{
    generated::acv::{
        Ballot, BallotProof, CandidateBallot, CandidateList,
        PollParametersStorage, RegistrationRequest, RegistrationResponse,
        StringToBallotProofPair, VoteChoice, VoteChoices, VoteRequest,
        VoterSecret,
    },
    proto_to_bytes,
};

/// Makes secrets used by a voter.
pub fn make_voter_secret() -> VoterSecret {
    let vote_secret = get_random_scalar();
    VoterSecret {
        voter_secret: scalar_to_bytes(&vote_secret),
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    }
}

/// Makes a request for voter registration.
pub fn make_registration_request(
    secret: &VoterSecret,
    poll_parameters: &PollParametersStorage,
) -> Result<RegistrationRequest, WedprError> {
    let voter_secret = bytes_to_scalar(secret.get_voter_secret())?;
    let blinding_basepoint_g2 = voter_secret * *BASEPOINT_G2;
    let poll_point = bytes_to_point(poll_parameters.get_poll_point())?;
    let blinding_poll_point = voter_secret * poll_point;
    let mut request = RegistrationRequest::new();
    let weight_point = request.mut_weight_point();
    weight_point
        .set_blinding_basepoint_g2(point_to_bytes(&blinding_basepoint_g2));
    weight_point.set_blinding_poll_point(point_to_bytes(&blinding_poll_point));
    Ok(request)
}

/// Verifies whether the blank ballot contained in a registration response is
/// valid.
pub fn verify_blank_ballot(
    request: &RegistrationRequest,
    response: &RegistrationResponse,
) -> Result<bool, WedprError> {
    let blinding_poll_point =
        bytes_to_point(request.get_weight_point().get_blinding_poll_point())?;
    let voter_weight = response.get_voter_weight();
    let computed_ciphertext1 = point_to_bytes(
        &(blinding_poll_point + *BASEPOINT_G1 * Scalar::from(voter_weight)),
    );
    let response_ciphertext1 = response.get_ballot().get_ciphertext1();

    let request_ciphertext2 =
        request.get_weight_point().get_blinding_basepoint_g2();
    let response_ciphertext2 = response.get_ballot().get_ciphertext2();

    Ok(response_ciphertext1 == computed_ciphertext1
        && response_ciphertext2 == request_ciphertext2)
}

/// Makes choices for all candidates.
pub fn make_vote_choices(
    choice_list: &Vec<u32>,
    candidate_list: &CandidateList,
) -> VoteChoices {
    let mut choices = VoteChoices::new();
    for i in 0..candidate_list.get_candidate().len() {
        let mut pair = VoteChoice::new();
        pair.set_candidate(candidate_list.get_candidate()[i].clone());
        pair.set_value(choice_list[i]);
        choices.mut_choice().push(pair);
    }
    choices
}

/// Votes the ciphertext ballots and generates associated ZKP proofs.
pub fn vote(
    voter_secret: &VoterSecret,
    vote_choices: &VoteChoices,
    registration_response: &RegistrationResponse,
    poll_parameters: &PollParametersStorage,
) -> Result<VoteRequest, WedprError> {
    let mut vote_request = VoteRequest::new();

    // Compute for each choice.
    let mut blinding_sum = Scalar::zero();
    let mut blinding_list: Vec<Scalar> = Vec::new();
    let mut choice_list: Vec<u64> = Vec::new();
    let mut unused_vote_weight =
        registration_response.get_voter_weight() as i64;
    let poll_point = bytes_to_point(poll_parameters.get_poll_point())?;
    for choice_keypair in vote_choices.get_choice() {
        let candidate_address = choice_keypair.get_candidate();
        let value = choice_keypair.get_value();
        unused_vote_weight -= value as i64;
        // Max voter weight has been used up.
        if unused_vote_weight < 0 {
            return Err(WedprError::ArgumentError);
        }

        // Make a ciphertext ballot.
        let mut vote_ballot = Ballot::new();
        let blinding = get_random_scalar();
        let ciphertext1 = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(value as u64), blinding],
            &[*BASEPOINT_G1, poll_point],
        );
        blinding_sum += blinding;
        let ciphertext2 = *BASEPOINT_G2 * blinding;
        vote_ballot.set_ciphertext1(point_to_bytes(&ciphertext1));
        vote_ballot.set_ciphertext2(point_to_bytes(&ciphertext2));

        // Prove ballot format.
        let format_proof = prove_format_proof(
            value as u64,
            &blinding,
            &*BASEPOINT_G1,
            &*BASEPOINT_G2,
            &poll_point,
        );
        let mut ballot_proof = BallotProof::new();
        ballot_proof.set_format_proof(proto_to_bytes(&format_proof_to_pb(
            &format_proof,
        ))?);

        // Write back.
        let mut proof_pair = StringToBallotProofPair::new();
        proof_pair.set_key(candidate_address.to_string());
        proof_pair.set_value(ballot_proof);
        vote_request.mut_ballot_proof().push(proof_pair);

        blinding_list.push(blinding);
        choice_list.push(value as u64);

        let mut ballot_pair = CandidateBallot::new();
        ballot_pair.set_candidate(candidate_address.to_string());
        ballot_pair.set_ballot(vote_ballot);
        vote_request.mut_vote().mut_voted_ballot().push(ballot_pair);
    }

    // Compute for the rest unused ballots.
    let blinding_rest = get_random_scalar();
    let rest_ballot = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(unused_vote_weight as u64), blinding_rest],
        &[*BASEPOINT_G1, poll_point],
    );

    // Prove the balance.
    let used_vote_weight_sum = (registration_response.get_voter_weight()
        - unused_vote_weight as u32) as u64;
    let vote_secret = bytes_to_scalar(voter_secret.get_voter_secret())?;
    let balance_proof = prove_sum_relationship(
        used_vote_weight_sum,
        unused_vote_weight as u64,
        &blinding_sum,
        &blinding_rest,
        &vote_secret,
        &BASEPOINT_G1,
        &poll_point,
    );

    // Prove the range.
    choice_list.push(unused_vote_weight as u64);
    blinding_list.push(blinding_rest);
    align_u64_list_if_needed(&mut choice_list);
    align_scalar_list_if_needed(&mut blinding_list);
    let (range_proof, _) =
        prove_value_range_in_batch(&choice_list, &blinding_list, &poll_point)?;

    // Write back.
    vote_request.set_sum_balance_proof(proto_to_bytes(
        &arithmetric_proof_to_pb(&balance_proof),
    )?);
    vote_request.set_range_proof(range_proof);
    let vote = vote_request.mut_vote();
    vote.set_signature(registration_response.get_signature().to_vec());
    vote.mut_rest_ballot()
        .set_ciphertext1(point_to_bytes(&rest_ballot));
    vote.set_blank_ballot(registration_response.get_ballot().clone());
    Ok(vote_request)
}
