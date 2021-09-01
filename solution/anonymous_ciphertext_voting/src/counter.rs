// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous ciphertext voting (ACV) solution.

use curve25519_dalek::scalar::Scalar;
use wedpr_l_crypto_zkp_discrete_logarithm_proof::prove_equality_relationship_proof;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, get_random_scalar, point_to_bytes,
    scalar_to_bytes, BASEPOINT_G1, BASEPOINT_G2,
};
use wedpr_l_protos::proto_to_bytes;
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::acv::{
    Ballot, CounterSecret, CounterSystemParametersShareRequest, CountingPart,
    DecryptedResultPartStorage, StringToCountingPartPair, StringToInt64Pair,
    SystemParametersStorage, VoteResultStorage, VoteStorage,
};

pub fn make_counter_secret() -> CounterSecret {
    let secret_share = get_random_scalar();
    CounterSecret {
        poll_secret_share: scalar_to_bytes(&secret_share),
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    }
}

pub fn make_system_parameters_share(
    counter_id: &str,
    counter_secret: &CounterSecret,
) -> Result<CounterSystemParametersShareRequest, WedprError> {
    let secret_scalar =
        bytes_to_scalar(counter_secret.get_poll_secret_share())?;
    let poll_point_share = secret_scalar * *BASEPOINT_G2;
    Ok(CounterSystemParametersShareRequest {
        counter_id: counter_id.to_string(),
        poll_point_share: point_to_bytes(&poll_point_share),
        unknown_fields: Default::default(),
        cached_size: Default::default(),
    })
}

pub fn count(
    counter_id: &str,
    secret: &CounterSecret,
    storage: &VoteStorage,
) -> Result<DecryptedResultPartStorage, WedprError> {
    let secret_share = bytes_to_scalar(&secret.get_poll_secret_share())?;
    let mut request = DecryptedResultPartStorage::new();
    let blank_ciphertext2_sum =
        bytes_to_point(storage.get_blank_ballot().get_ciphertext2())?;
    for candidate_ballot_pair in storage.get_voted_ballot() {
        let candidate = candidate_ballot_pair.get_candidate();
        let ballot = candidate_ballot_pair.get_ballot();
        let candidate_part_share = bytes_to_point(ballot.get_ciphertext2())?;
        let equity_proof = prove_equality_relationship_proof(
            &secret_share,
            &BASEPOINT_G2,
            &candidate_part_share,
        );
        let mut counting_part = CountingPart::new();
        counting_part.set_blinding_c2(point_to_bytes(
            &(&candidate_part_share * (secret_share)),
        ));
        counting_part.set_equality_proof(proto_to_bytes(&equity_proof)?);
        let mut candidate_counting_part_pair = StringToCountingPartPair::new();
        candidate_counting_part_pair.set_key(candidate.to_string());
        candidate_counting_part_pair.set_value(counting_part);
        request
            .mut_candidate_part()
            .push(candidate_counting_part_pair);
    }
    let blank_part = blank_ciphertext2_sum * (secret_share);
    let equity_proof = prove_equality_relationship_proof(
        &secret_share,
        &BASEPOINT_G2,
        &blank_ciphertext2_sum,
    );
    request
        .mut_blank_part()
        .set_equality_proof(proto_to_bytes(&equity_proof)?);
    request
        .mut_blank_part()
        .set_blinding_c2(point_to_bytes(&blank_part));
    request
        .mut_blank_part()
        .set_counter_id(counter_id.to_string());
    Ok(request)
}

// In this function, everyone can check anonymousvoting result by c1 - c2r_sum,
// because we already know v and candidates, by using c1 - c2r_sum, we can check
// whether vG_1 =? c1 - c2r_sum. pub fn verify_counter(result_pb:
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
