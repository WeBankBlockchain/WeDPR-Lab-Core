// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a poll counter.

use wedpr_l_crypto_zkp_discrete_logarithm_proof::prove_equality_relationship_proof;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, get_random_scalar, point_to_bytes,
    scalar_to_bytes, BASEPOINT_G2,
};
use wedpr_l_utils::error::WedprError;

use wedpr_s_protos::{
    generated::acv::{
        CounterParametersShareRequest, CounterSecret, CountingPart,
        DecryptedResultPartStorage, StringToCountingPartPair, VoteStorage,
    },
    proto_to_bytes,
};

use wedpr_s_protos::equality_proof_to_pb;

/// Makes secrets used by a counter.
pub fn make_counter_secret() -> CounterSecret {
    let secret_share = get_random_scalar();
    CounterSecret {
        poll_secret_share: scalar_to_bytes(&secret_share),
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    }
}

/// Makes share of system parameters used by a group of counters.
pub fn make_parameters_share(
    counter_id: &str,
    counter_secret: &CounterSecret,
) -> Result<CounterParametersShareRequest, WedprError> {
    let secret_scalar =
        bytes_to_scalar(counter_secret.get_poll_secret_share())?;
    let poll_point_share = secret_scalar * *BASEPOINT_G2;
    Ok(CounterParametersShareRequest {
        counter_id: counter_id.to_string(),
        poll_point_share: point_to_bytes(&poll_point_share),
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    })
}

/// Counts the aggregated ciphertext ballots and generates associated ZKP
/// proofs.
pub fn count(
    counter_id: &str,
    counter_secret: &CounterSecret,
    encrypted_vote_sum: &VoteStorage,
) -> Result<DecryptedResultPartStorage, WedprError> {
    let secret_share =
        bytes_to_scalar(&counter_secret.get_poll_secret_share())?;
    let mut partially_decrypted_result = DecryptedResultPartStorage::new();
    for candidate_ballot_pair in encrypted_vote_sum.get_voted_ballot() {
        // Count by partially decrypting the aggregated ciphertext ballots.
        let ballot = candidate_ballot_pair.get_ballot();
        let candidate_part_share = bytes_to_point(ballot.get_ciphertext2())?;
        let mut counting_part = CountingPart::new();
        counting_part.set_blinding_c2(point_to_bytes(
            &(&candidate_part_share * (secret_share)),
        ));

        // Prove the equality for each candidate.
        let equality_proof = prove_equality_relationship_proof(
            &secret_share,
            &BASEPOINT_G2,
            &candidate_part_share,
        );
        counting_part.set_equality_proof(proto_to_bytes(
            &(equality_proof_to_pb(&equality_proof)),
        )?);
        // Write back.
        let candidate = candidate_ballot_pair.get_candidate();
        let mut candidate_counting_part_pair = StringToCountingPartPair::new();
        candidate_counting_part_pair.set_key(candidate.to_string());
        candidate_counting_part_pair.set_value(counting_part);
        partially_decrypted_result
            .mut_candidate_part()
            .push(candidate_counting_part_pair);
    }

    // Prove the equality for the blank ballot.
    let blank_ciphertext2_sum = bytes_to_point(
        encrypted_vote_sum.get_blank_ballot().get_ciphertext2(),
    )?;
    let blinding_c2 = blank_ciphertext2_sum * (secret_share);
    let equality_proof = prove_equality_relationship_proof(
        &secret_share,
        &BASEPOINT_G2,
        &blank_ciphertext2_sum,
    );

    // Write back.
    let blank_part = partially_decrypted_result.mut_blank_part();
    blank_part.set_equality_proof(proto_to_bytes(&equality_proof_to_pb(
        &equality_proof,
    ))?);
    blank_part.set_blinding_c2(point_to_bytes(&blinding_c2));
    blank_part.set_counter_id(counter_id.to_string());
    Ok(partially_decrypted_result)
}
