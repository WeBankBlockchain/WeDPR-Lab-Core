// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a poll voter.

use crate::utils::{align_scalar_list_if_needed, align_u64_list_if_needed};
use wedpr_s_protos::generated::acv::CipherPoints;

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{
    prove_either_equality_relationship_proof, prove_format_proof,
    prove_sum_relationship,
};
use wedpr_l_crypto_zkp_range_proof::prove_value_range_in_batch;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, get_random_scalar, point_to_bytes,
    scalar_to_bytes, Serialize, BASEPOINT_G1, BASEPOINT_G2,
};
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::acv::{
    Ballot, BallotProof, CandidateBallot, CandidateList,
    CipherPointsToBallotPair, CipherPointsToBallotProofPair,
    PollParametersStorage, RegistrationBlindingPoint, RegistrationRequest,
    RegistrationResponse, StringToBallotProofPair, VoteChoice, VoteChoices,
    VoteRequest, VoterSecret,
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

pub fn generate_registration_blinding_point(
    secret: &VoterSecret,
    poll_parameters: &PollParametersStorage,
) -> Result<RegistrationBlindingPoint, WedprError> {
    let voter_secret = bytes_to_scalar(secret.get_voter_secret())?;
    let blinding_basepoint_g2 = voter_secret * *BASEPOINT_G2;
    let poll_point = bytes_to_point(poll_parameters.get_poll_point())?;
    let blinding_poll_point = voter_secret * poll_point;
    let mut registration_blinding_point = RegistrationBlindingPoint::new();
    registration_blinding_point
        .set_blinding_basepoint_g2(point_to_bytes(&blinding_basepoint_g2));
    registration_blinding_point
        .set_blinding_poll_point(point_to_bytes(&blinding_poll_point));
    Ok(registration_blinding_point)
}

/// Makes a request for voter registration.
pub fn make_registration_request(
    secret: &VoterSecret,
    poll_parameters: &PollParametersStorage,
) -> Result<RegistrationRequest, WedprError> {
    let mut request = RegistrationRequest::new();
    request.set_weight_point(generate_registration_blinding_point(
        secret,
        poll_parameters,
    )?);
    Ok(request)
}

pub fn make_unbounded_registration_request(
    zero_secret: &VoterSecret,
    weight_secret: &VoterSecret,
    poll_parameters: &PollParametersStorage,
) -> Result<RegistrationRequest, WedprError> {
    let mut request = RegistrationRequest::new();
    request.set_weight_point(generate_registration_blinding_point(
        weight_secret,
        poll_parameters,
    )?);
    request.set_zero_point(generate_registration_blinding_point(
        zero_secret,
        poll_parameters,
    )?);
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
        ballot_proof.set_format_proof(format_proof.serialize());

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
    vote_request.set_sum_balance_proof(balance_proof.serialize());
    vote_request.set_range_proof(range_proof);
    let vote = vote_request.mut_vote();
    vote.set_signature(registration_response.get_signature().to_vec());
    vote.mut_rest_ballot()
        .set_ciphertext1(point_to_bytes(&rest_ballot));
    vote.set_blank_ballot(registration_response.get_ballot().clone());
    Ok(vote_request)
}

pub fn generate_ballot_proof(
    vote_value: u64,
    registration_response: &RegistrationResponse,
    poll_point: &RistrettoPoint,
    voter_secret: &VoterSecret,
    zero_secret: &VoterSecret,
    ballot_proof: &mut BallotProof,
    vote_ballot: &mut Ballot,
) -> Result<bool, WedprError> {
    let blinding = get_random_scalar();
    let c1_blinding = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(vote_value), blinding],
        &[*BASEPOINT_G1, *poll_point],
    );
    // generate either-equality proof
    let either_equality_proof = prove_either_equality_relationship_proof(
        vote_value,
        registration_response.get_voter_weight() as u64,
        &blinding,
        &bytes_to_scalar(voter_secret.get_voter_secret())?,
        &bytes_to_scalar(zero_secret.get_voter_secret())?,
        &BASEPOINT_G1,
        &poll_point,
    );

    // generate format proof
    let format_proof = prove_format_proof(
        vote_value,
        &blinding,
        &BASEPOINT_G1,
        &BASEPOINT_G2,
        &poll_point,
    );
    let ciphertext2 = *BASEPOINT_G2 * blinding;
    vote_ballot.set_ciphertext1(point_to_bytes(&c1_blinding));
    vote_ballot.set_ciphertext2(point_to_bytes(&ciphertext2));
    // set proofs

    ballot_proof.set_either_equality_proof(either_equality_proof.serialize());
    ballot_proof.set_format_proof(format_proof.serialize());
    Ok(true)
}

pub fn vote_unbounded(
    voter_secret: &VoterSecret,
    zero_secret: &VoterSecret,
    vote_choices: &VoteChoices,
    registration_response: &RegistrationResponse,
    poll_parameters: &PollParametersStorage,
) -> Result<VoteRequest, WedprError> {
    let mut vote_request = VoteRequest::new();
    let poll_point = bytes_to_point(poll_parameters.get_poll_point())?;
    // generate ballot for every vote choice
    for vote_choice in vote_choices.get_choice() {
        let mut ballot_proof = BallotProof::new();
        let mut vote_ballot = Ballot::new();
        generate_ballot_proof(
            vote_choice.get_value() as u64,
            registration_response,
            &poll_point,
            voter_secret,
            zero_secret,
            &mut ballot_proof,
            &mut vote_ballot,
        )?;
        // push ballot_proof
        let mut proof_pair = StringToBallotProofPair::new();
        proof_pair.set_key(vote_choice.get_candidate().to_owned());
        proof_pair.set_value(ballot_proof);
        vote_request.mut_ballot_proof().push(proof_pair);
        // set ballot info
        let mut ballot_pair = CandidateBallot::new();
        ballot_pair.set_candidate(vote_choice.get_candidate().to_owned());
        ballot_pair.set_ballot(vote_ballot);
        vote_request.mut_vote().mut_voted_ballot().push(ballot_pair);
    }
    vote_request
        .mut_vote()
        .set_blank_ballot(registration_response.get_ballot().clone());
    vote_request
        .mut_vote()
        .set_zero_ballot(registration_response.get_zero_ballot().clone());
    vote_request
        .mut_vote()
        .set_signature(registration_response.get_signature().to_vec());
    Ok(vote_request)
}

pub fn generate_candidate_cipher(
    value: u64,
    poll_point: &RistrettoPoint,
) -> Result<CipherPoints, WedprError> {
    let mut cipher_point = CipherPoints::new();
    let blinding = get_random_scalar();
    let ciphertext1 = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(value as u64), blinding],
        &[*BASEPOINT_G1, *poll_point],
    );
    let ciphertext2 = *BASEPOINT_G2 * blinding;
    cipher_point.set_ciphertext1(point_to_bytes(&ciphertext1));
    cipher_point.set_ciphertext2(point_to_bytes(&ciphertext2));
    Ok(cipher_point)
}

pub fn vote_unbounded_unlisted(
    voter_secret: &VoterSecret,
    zero_secret: &VoterSecret,
    vote_choices: &VoteChoices,
    registration_response: &RegistrationResponse,
    poll_parameters: &PollParametersStorage,
) -> Result<VoteRequest, WedprError> {
    let mut vote_request = vote_unbounded(
        voter_secret,
        zero_secret,
        vote_choices,
        registration_response,
        poll_parameters,
    )?;
    let poll_point = bytes_to_point(poll_parameters.get_poll_point())?;
    for unlisted_vote_choice in vote_choices.get_unlisted_choice() {
        let mut ballot_proof = BallotProof::new();
        let mut vote_ballot = Ballot::new();
        generate_ballot_proof(
            unlisted_vote_choice.get_value() as u64,
            registration_response,
            &poll_point,
            voter_secret,
            zero_secret,
            &mut ballot_proof,
            &mut vote_ballot,
        )?;
        // update the vote_request
        // push ballot_proof
        let mut proof_pair = CipherPointsToBallotProofPair::new();
        let candidate_cipher = generate_candidate_cipher(
            unlisted_vote_choice.get_candidate_id() as u64,
            &poll_point,
        )?;
        proof_pair.set_key(candidate_cipher.clone());
        proof_pair.set_value(ballot_proof);
        vote_request.mut_unlisted_ballot_proof().push(proof_pair);
        // set the unlisted ballot info
        let mut unlisted_ballot = CipherPointsToBallotPair::new();
        unlisted_ballot.set_key(candidate_cipher.clone());
        unlisted_ballot.set_ballot(vote_ballot);
        vote_request
            .mut_vote()
            .mut_voted_ballot_unlisted()
            .push(unlisted_ballot);
    }
    Ok(vote_request)
}
