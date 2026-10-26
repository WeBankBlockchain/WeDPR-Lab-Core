// Copyright 2026 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use crate::{coordinator, counter, verifier, voter};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_crypto_zkp_utils::{bytes_to_point, point_to_bytes, BASEPOINT_G1};
use wedpr_l_utils::traits::Signature;
use wedpr_s_protos::{
    bytes_to_proto, config::SIGNATURE, generated::acv::*, proto_to_bytes,
};

struct Fixture {
    poll: PollParametersStorage,
    counter: CounterSecret,
    share: RistrettoPoint,
    public_key: Vec<u8>,
    signing_key: Vec<u8>,
    secret: VoterSecret,
    zero_secret: VoterSecret,
    registration: RegistrationRequest,
    bounded: RegistrationResponse,
    unbounded_registration: RegistrationRequest,
    unbounded: RegistrationResponse,
}

#[test]
fn final_result_cannot_be_forged_by_replacing_aggregate_decryption() {
    let f = Fixture::new();
    let (sum, mut decrypted, mut result) = f.tally(&f.bounded_vote(), false);
    let ciphertext = bytes_to_point(
        sum.get_voted_ballot()[0].get_ballot().get_ciphertext1(),
    )
    .unwrap();
    decrypted.mut_candidate_part()[0]
        .mut_value()
        .set_blinding_c2(point_to_bytes(
            &(ciphertext - Scalar::from(99u64) * *BASEPOINT_G1),
        ));
    result.mut_result()[1].set_value(99);
    assert!(
        !verifier::verify_vote_result(&f.poll, &sum, &decrypted, &result)
            .unwrap()
    );
}

#[test]
fn decryption_aggregation_verifies_membership_proofs_and_replay_atomically() {
    let f = Fixture::new();
    let (sum, decrypted, result) = f.tally(&f.bounded_vote(), false);
    let restored: DecryptedResultPartStorage =
        bytes_to_proto(&proto_to_bytes(&decrypted).unwrap()).unwrap();
    assert!(
        verifier::verify_vote_result(&f.poll, &sum, &restored, &result)
            .unwrap()
    );
    let part = counter::count("counter", &f.counter, &sum).unwrap();
    let mut aggregate = DecryptedResultPartStorage::new();
    coordinator::aggregate_decrypted_part_sum(
        &f.poll,
        &part,
        &mut aggregate,
        &sum,
    )
    .unwrap();
    let original = aggregate.clone();
    assert!(coordinator::aggregate_decrypted_part_sum(
        &f.poll,
        &part,
        &mut aggregate,
        &sum
    )
    .is_err());
    assert_eq!(aggregate, original);
    for mutation in 0..2 {
        let mut invalid = part.clone();
        match mutation {
            0 => invalid
                .mut_blank_part()
                .set_counter_id("unregistered".to_owned()),
            _ => invalid.mut_candidate_part()[0]
                .mut_value()
                .set_blinding_c2(point_to_bytes(&RistrettoPoint::default())),
        }
        let mut empty = DecryptedResultPartStorage::new();
        let before = empty.clone();
        assert!(coordinator::aggregate_decrypted_part_sum(
            &f.poll, &invalid, &mut empty, &sum
        )
        .is_err());
        assert_eq!(empty, before);
    }
    for mutation in 0..3 {
        let mut forged = decrypted.clone();
        match mutation {
            0 => forged.clear_verified_counter_part(),
            1 => forged
                .mut_verified_counter_part()
                .push(decrypted.get_verified_counter_part()[0].clone()),
            _ => forged.mut_verified_counter_part()[0]
                .mut_blank_part()
                .clear_equality_proof(),
        }
        assert!(
            !verifier::verify_vote_result(&f.poll, &sum, &forged, &result)
                .unwrap()
        );
    }
}

#[test]
fn unlisted_duplicate_plaintext_candidate_cannot_multiply_voting_weight() {
    let f = Fixture::new();
    let mut first = f.unlisted_vote();
    let second = f.unlisted_vote();
    first
        .mut_vote()
        .mut_voted_ballot_unlisted()
        .push(second.get_vote().get_voted_ballot_unlisted()[0].clone());
    first
        .mut_unlisted_ballot_proof()
        .push(second.get_unlisted_ballot_proof()[0].clone());
    assert!(verifier::verify_unbounded_vote_request_unlisted(
        &f.poll,
        &first,
        &f.public_key
    )
    .is_err());
}

#[test]
fn credentials_are_bound_to_a_unique_poll() {
    let f = Fixture::new();
    let mut counters = CounterParametersStorage::new();
    counters
        .mut_counter_parameters_share()
        .push(counter::make_parameters_share("counter", &f.counter).unwrap());
    let another_poll =
        coordinator::make_poll_parameters(f.poll.get_candidates(), &counters)
            .unwrap();
    assert!(verifier::verify_vote_request(
        &another_poll,
        &f.bounded_vote(),
        &f.public_key
    )
    .is_err());
    assert!(verifier::verify_unbounded_vote_request(
        &another_poll,
        &f.unbounded_vote(),
        &f.public_key
    )
    .is_err());
    let mut retagged = f.bounded_vote();
    retagged
        .mut_vote()
        .set_poll_id(another_poll.get_poll_id().to_vec());
    assert!(verifier::verify_vote_request(
        &another_poll,
        &retagged,
        &f.public_key
    )
    .is_err());
    let mut retagged = f.unbounded_vote();
    retagged
        .mut_vote()
        .set_poll_id(another_poll.get_poll_id().to_vec());
    assert!(verifier::verify_unbounded_vote_request(
        &another_poll,
        &retagged,
        &f.public_key
    )
    .is_err());
}

#[test]
fn credential_signature_covers_candidate_labels_and_counter_roster() {
    let f = Fixture::new();
    let mut poll = f.poll.clone();
    poll.mut_candidates().mut_candidate()[0] = "C".to_owned();
    let mut request = f.bounded_vote();
    request.mut_vote().mut_voted_ballot()[0].set_candidate("C".to_owned());
    request.mut_ballot_proof()[0].set_key("C".to_owned());
    assert!(
        verifier::verify_vote_request(&poll, &request, &f.public_key).is_err()
    );
    let mut poll = f.poll.clone();
    poll.mut_counters().mut_counter_parameters_share()[0]
        .set_counter_id("another counter".to_owned());
    assert!(verifier::verify_vote_request(
        &poll,
        &f.bounded_vote(),
        &f.public_key
    )
    .is_err());
}

#[test]
fn counter_proof_cannot_be_relabelled_or_same_key_registered_twice() {
    let f = Fixture::new();
    let honest = counter::make_parameters_share("counter", &f.counter).unwrap();
    let mut relabelled = honest.clone();
    relabelled.set_counter_id("renamed".to_owned());
    let mut counters = CounterParametersStorage::new();
    counters.mut_counter_parameters_share().push(relabelled);
    assert!(coordinator::make_poll_parameters(
        f.poll.get_candidates(),
        &counters
    )
    .is_err());
    counters.clear_counter_parameters_share();
    counters.mut_counter_parameters_share().extend([
        honest,
        counter::make_parameters_share("renamed", &f.counter).unwrap(),
    ]);
    assert!(coordinator::make_poll_parameters(
        f.poll.get_candidates(),
        &counters
    )
    .is_err());
}

#[test]
fn unlisted_candidate_proofs_validate_ids_order_and_credential_binding() {
    let f = Fixture::new();
    let mut choices = f.choices(vec![10, 0]);
    for id in [9, 0, 7] {
        let mut choice = UnlistedVoteChoice::new();
        choice.set_candidate_id(id);
        choice.set_value(10);
        choices.mut_unlisted_choice().push(choice);
    }
    let valid = voter::vote_unbounded_unlisted(
        &f.secret,
        &f.zero_secret,
        &choices,
        &f.unbounded,
        &f.poll,
    )
    .unwrap();
    assert!(verifier::verify_unbounded_vote_request_unlisted(
        &f.poll,
        &valid,
        &f.public_key
    )
    .unwrap());
    for mutation in 0..4 {
        let mut changed = valid.clone();
        match mutation {
            0 => changed.clear_unlisted_candidate_range_proof(),
            1 => changed.mut_unlisted_ballot_proof()[0]
                .clear_candidate_format_proof(),
            2 => changed.mut_vote().mut_voted_ballot_unlisted().swap(0, 1),
            _ => changed.mut_vote().mut_voted_ballot_unlisted()[0]
                .mut_key()
                .set_ciphertext2(point_to_bytes(&RistrettoPoint::default())),
        }
        assert!(verifier::verify_unbounded_vote_request_unlisted(
            &f.poll,
            &changed,
            &f.public_key
        )
        .is_err());
    }
    let valid_choices = choices.clone();
    let duplicate = choices.get_unlisted_choice()[0].clone();
    choices.mut_unlisted_choice().push(duplicate);
    assert!(voter::vote_unbounded_unlisted(
        &f.secret,
        &f.zero_secret,
        &choices,
        &f.unbounded,
        &f.poll
    )
    .is_err());
    let secret = voter::make_voter_secret();
    let zero = voter::make_voter_secret();
    let registration =
        voter::make_unbounded_registration_request(&zero, &secret, &f.poll)
            .unwrap();
    let response = coordinator::certify_unbounded_voter(
        &f.signing_key,
        &registration,
        10,
        &f.poll,
    )
    .unwrap();
    let mut spliced = voter::vote_unbounded_unlisted(
        &secret,
        &zero,
        &valid_choices,
        &response,
        &f.poll,
    )
    .unwrap();
    // Keep this voter's valid weight proofs. Replace only candidate identities
    // and their proofs with another voter's public proof material.
    for i in 0..valid.get_vote().get_voted_ballot_unlisted().len() {
        let other = &valid.get_unlisted_ballot_proof()[i];
        spliced.mut_vote().mut_voted_ballot_unlisted()[i]
            .set_key(other.get_key().clone());
        spliced.mut_unlisted_ballot_proof()[i].set_key(other.get_key().clone());
        spliced.mut_unlisted_ballot_proof()[i].set_candidate_format_proof(
            other.get_candidate_format_proof().to_vec(),
        );
    }
    spliced.set_unlisted_candidate_range_proof(
        valid.get_unlisted_candidate_range_proof().to_vec(),
    );
    assert!(verifier::verify_unbounded_vote_request_unlisted(
        &f.poll,
        &spliced,
        &f.public_key
    )
    .is_err());
}

#[test]
fn poll_creation_rejects_rogue_counter_share_without_secret_knowledge() {
    let f = Fixture::new();
    let honest = counter::make_parameters_share("counter", &f.counter).unwrap();
    let mut rogue = CounterParametersShareRequest::new();
    rogue.set_counter_id("rogue".to_owned());
    let combined_secret = Scalar::from(42u64);
    let forged = combined_secret * *wedpr_l_crypto_zkp_utils::BASEPOINT_G2
        - bytes_to_point(honest.get_poll_point_share()).unwrap();
    rogue.set_poll_point_share(point_to_bytes(&forged));
    let mut counters = CounterParametersStorage::new();
    counters
        .mut_counter_parameters_share()
        .extend([honest, rogue]);
    assert!(coordinator::make_poll_parameters(
        f.poll.get_candidates(),
        &counters
    )
    .is_err());
}

impl Fixture {
    fn new() -> Self {
        let counter = counter::make_counter_secret();
        let share =
            counter::make_parameters_share("counter", &counter).unwrap();
        let mut counters = CounterParametersStorage::new();
        counters.mut_counter_parameters_share().push(share.clone());
        let mut candidates = CandidateList::new();
        candidates
            .mut_candidate()
            .extend(["A".to_owned(), "B".to_owned()]);
        let poll =
            coordinator::make_poll_parameters(&candidates, &counters).unwrap();
        let (public_key, signing_key) = SIGNATURE.generate_keypair();
        let secret = voter::make_voter_secret();
        let zero_secret = voter::make_voter_secret();
        let registration =
            voter::make_registration_request(&secret, &poll).unwrap();
        let bounded =
            coordinator::certify_voter(&signing_key, &registration, 10, &poll)
                .unwrap();
        let unbounded_registration =
            voter::make_unbounded_registration_request(
                &zero_secret,
                &secret,
                &poll,
            )
            .unwrap();
        let unbounded = coordinator::certify_unbounded_voter(
            &signing_key,
            &unbounded_registration,
            10,
            &poll,
        )
        .unwrap();
        Self {
            poll,
            counter,
            share: bytes_to_point(share.get_poll_point_share()).unwrap(),
            public_key,
            signing_key,
            secret,
            zero_secret,
            registration,
            bounded,
            unbounded_registration,
            unbounded,
        }
    }

    fn choices(&self, values: Vec<u32>) -> VoteChoices {
        voter::make_vote_choices(&values, self.poll.get_candidates())
    }

    fn bounded_vote(&self) -> VoteRequest {
        voter::vote(
            &self.secret,
            &self.choices(vec![4, 3]),
            &self.bounded,
            &self.poll,
        )
        .unwrap()
    }

    fn unbounded_vote(&self) -> VoteRequest {
        voter::vote_unbounded(
            &self.secret,
            &self.zero_secret,
            &self.choices(vec![10, 0]),
            &self.unbounded,
            &self.poll,
        )
        .unwrap()
    }

    fn unlisted_vote(&self) -> VoteRequest {
        let mut choices = self.choices(vec![10, 0]);
        let mut other = UnlistedVoteChoice::new();
        other.set_candidate_id(7);
        other.set_value(10);
        choices.mut_unlisted_choice().push(other);
        voter::vote_unbounded_unlisted(
            &self.secret,
            &self.zero_secret,
            &choices,
            &self.unbounded,
            &self.poll,
        )
        .unwrap()
    }

    fn tally(
        &self,
        request: &VoteRequest,
        unlisted: bool,
    ) -> (VoteStorage, DecryptedResultPartStorage, VoteResultStorage) {
        let mut sum = VoteStorage::new();
        let mut decrypted = DecryptedResultPartStorage::new();
        let result = if unlisted {
            assert!(verifier::verify_unbounded_vote_request_unlisted(
                &self.poll,
                request,
                &self.public_key
            )
            .unwrap());
            coordinator::aggregate_vote_sum_response_unlisted(
                &self.poll,
                request.get_vote(),
                &mut sum,
            )
            .unwrap();
            let part = counter::count_unlisted("counter", &self.counter, &sum)
                .unwrap();
            assert!(verifier::verify_count_request_unlisted(
                &self.poll,
                &self.share,
                &sum,
                &part
            )
            .unwrap());
            coordinator::aggregate_decrypted_part_sum_unlisted(
                &self.poll,
                &part,
                &mut decrypted,
                &sum,
            )
            .unwrap();
            coordinator::finalize_vote_result_unlisted(
                &self.poll,
                &sum,
                &mut decrypted,
                20,
                10,
            )
            .unwrap()
        } else {
            assert!(verifier::verify_vote_request(
                &self.poll,
                request,
                &self.public_key
            )
            .unwrap());
            coordinator::aggregate_vote_sum_response(
                &self.poll,
                request.get_vote(),
                &mut sum,
            )
            .unwrap();
            let part = counter::count("counter", &self.counter, &sum).unwrap();
            assert!(verifier::verify_count_request(
                &self.poll,
                &sum,
                &self.share,
                &part
            )
            .unwrap());
            coordinator::aggregate_decrypted_part_sum(
                &self.poll,
                &part,
                &mut decrypted,
                &sum,
            )
            .unwrap();
            coordinator::finalize_vote_result(&self.poll, &sum, &decrypted, 20)
                .unwrap()
        };
        assert!(verifier::verify_vote_result(
            &self.poll, &sum, &decrypted, &result
        )
        .unwrap());
        (sum, decrypted, result)
    }
}

#[test]
fn registration_rejects_weight_inflation_and_missing_proofs() {
    let f = Fixture::new();
    let mut inflated = f.registration.clone();
    let point =
        bytes_to_point(inflated.get_weight_point().get_blinding_poll_point())
            .unwrap();
    inflated
        .mut_weight_point()
        .set_blinding_poll_point(point_to_bytes(
            &(point + Scalar::from(90u64) * *BASEPOINT_G1),
        ));
    assert!(
        coordinator::certify_voter(&f.signing_key, &inflated, 10, &f.poll)
            .is_err()
    );
    let mut missing = f.registration.clone();
    missing.mut_weight_point().clear_equality_proof();
    assert!(
        coordinator::certify_voter(&f.signing_key, &missing, 10, &f.poll)
            .is_err()
    );
    let mut wrong_c2 = f.registration.clone();
    wrong_c2
        .mut_weight_point()
        .set_blinding_basepoint_g2(point_to_bytes(&RistrettoPoint::default()));
    assert!(
        coordinator::certify_voter(&f.signing_key, &wrong_c2, 10, &f.poll)
            .is_err()
    );
    let encoded = proto_to_bytes(&f.registration).unwrap();
    let decoded: RegistrationRequest = bytes_to_proto(&encoded).unwrap();
    assert!(
        coordinator::certify_voter(&f.signing_key, &decoded, 10, &f.poll)
            .is_ok()
    );
}

#[test]
fn unbounded_registration_checks_weight_zero_and_trusted_poll() {
    let f = Fixture::new();
    for zero in [false, true] {
        let mut request = f.unbounded_registration.clone();
        let point = if zero {
            request.mut_zero_point()
        } else {
            request.mut_weight_point()
        };
        let original = bytes_to_point(point.get_blinding_poll_point()).unwrap();
        point.set_blinding_poll_point(point_to_bytes(
            &(original + Scalar::from(90u64) * *BASEPOINT_G1),
        ));
        assert!(coordinator::certify_unbounded_voter(
            &f.signing_key,
            &request,
            10,
            &f.poll
        )
        .is_err());
    }
    let other = Fixture::new();
    assert!(coordinator::certify_voter(
        &f.signing_key,
        &f.registration,
        10,
        &other.poll
    )
    .is_err());
    assert!(coordinator::certify_unbounded_voter(
        &f.signing_key,
        &f.unbounded_registration,
        10,
        &other.poll
    )
    .is_err());
    let mut missing = f.unbounded_registration.clone();
    missing.mut_zero_point().clear_equality_proof();
    assert!(coordinator::certify_unbounded_voter(
        &f.signing_key,
        &missing,
        10,
        &f.poll
    )
    .is_err());
}

#[test]
fn bounded_vote_requires_exact_proof_coverage() {
    let f = Fixture::new();
    let valid = f.bounded_vote();
    assert!(
        verifier::verify_vote_request(&f.poll, &valid, &f.public_key).unwrap()
    );
    let mut missing = valid.clone();
    missing.clear_ballot_proof();
    missing.mut_vote().mut_voted_ballot()[0]
        .mut_ballot()
        .set_ciphertext2(point_to_bytes(&RistrettoPoint::default()));
    assert!(
        verifier::verify_vote_request(&f.poll, &missing, &f.public_key)
            .is_err()
    );
    let mut partial = valid.clone();
    partial.mut_ballot_proof().pop();
    assert!(
        verifier::verify_vote_request(&f.poll, &partial, &f.public_key)
            .is_err()
    );
    let mut duplicate = valid.clone();
    duplicate.mut_ballot_proof()[1] = valid.get_ballot_proof()[0].clone();
    assert!(
        verifier::verify_vote_request(&f.poll, &duplicate, &f.public_key)
            .is_err()
    );
    let mut unknown = valid.clone();
    unknown.mut_ballot_proof()[0].set_key("unknown".to_owned());
    assert!(
        verifier::verify_vote_request(&f.poll, &unknown, &f.public_key)
            .is_err()
    );
}

#[test]
fn unbounded_vote_rejects_overweight_ballot_without_proofs() {
    let f = Fixture::new();
    let valid = f.unbounded_vote();
    assert!(verifier::verify_unbounded_vote_request(
        &f.poll,
        &valid,
        &f.public_key
    )
    .unwrap());
    let mut forged = valid.clone();
    forged.clear_ballot_proof();
    let ballot = forged.mut_vote().mut_voted_ballot()[0].mut_ballot();
    ballot.set_ciphertext1(point_to_bytes(
        &(Scalar::from(99u64) * *BASEPOINT_G1),
    ));
    ballot.set_ciphertext2(point_to_bytes(&RistrettoPoint::default()));
    assert!(verifier::verify_unbounded_vote_request(
        &f.poll,
        &forged,
        &f.public_key
    )
    .is_err());
    assert!(verifier::verify_unbounded_vote_request_unlisted(
        &f.poll,
        &forged,
        &f.public_key
    )
    .is_err());
    let invalid_value = voter::vote_unbounded(
        &f.secret,
        &f.zero_secret,
        &f.choices(vec![11, 0]),
        &f.unbounded,
        &f.poll,
    )
    .unwrap();
    assert!(verifier::verify_unbounded_vote_request(
        &f.poll,
        &invalid_value,
        &f.public_key
    )
    .is_err());
}

#[test]
fn vote_modes_reject_unknown_duplicate_and_missing_candidates() {
    let f = Fixture::new();
    for bounded in [true, false] {
        let valid = if bounded {
            f.bounded_vote()
        } else {
            f.unbounded_vote()
        };
        for mutation in 0..3 {
            let mut request = valid.clone();
            match mutation {
                0 => request.mut_vote().mut_voted_ballot()[0]
                    .set_candidate("unknown".to_owned()),
                1 => {
                    request.mut_vote().mut_voted_ballot()[1] =
                        valid.get_vote().get_voted_ballot()[0].clone()
                },
                _ => {
                    request.mut_vote().mut_voted_ballot().pop();
                },
            }
            let result = if bounded {
                verifier::verify_vote_request(&f.poll, &request, &f.public_key)
            } else {
                verifier::verify_unbounded_vote_request(
                    &f.poll,
                    &request,
                    &f.public_key,
                )
            };
            assert!(result.is_err());
        }
    }
}

#[test]
fn unlisted_vote_requires_exact_proof_coverage_and_correct_mode() {
    let f = Fixture::new();
    let valid = f.unlisted_vote();
    assert!(verifier::verify_unbounded_vote_request_unlisted(
        &f.poll,
        &valid,
        &f.public_key
    )
    .unwrap());
    assert!(verifier::verify_unbounded_vote_request(
        &f.poll,
        &valid,
        &f.public_key
    )
    .is_err());
    for mutation in 0..4 {
        let mut request = valid.clone();
        match mutation {
            0 => request.clear_unlisted_ballot_proof(),
            1 => request
                .mut_unlisted_ballot_proof()
                .push(valid.get_unlisted_ballot_proof()[0].clone()),
            2 => request
                .mut_vote()
                .mut_voted_ballot_unlisted()
                .push(valid.get_vote().get_voted_ballot_unlisted()[0].clone()),
            _ => request.mut_unlisted_ballot_proof()[0]
                .mut_key()
                .set_ciphertext1(point_to_bytes(&RistrettoPoint::default())),
        }
        assert!(verifier::verify_unbounded_vote_request_unlisted(
            &f.poll,
            &request,
            &f.public_key
        )
        .is_err());
    }
}

#[test]
fn result_verification_checks_all_unlisted_totals_and_candidate_ids() {
    let f = Fixture::new();
    let (sum, decrypted, result) = f.tally(&f.unlisted_vote(), true);
    assert_eq!(result.get_unlisted_result()[0].get_candidate_id(), 7);
    assert_eq!(result.get_unlisted_result()[0].get_value(), 10);
    for mutation in 0..5 {
        let mut changed = result.clone();
        match mutation {
            0 => changed.clear_unlisted_result(),
            1 => changed.mut_unlisted_result()[0].set_value(999),
            2 => changed.mut_unlisted_result()[0].set_candidate_id(8),
            3 => changed
                .mut_unlisted_result()
                .push(result.get_unlisted_result()[0].clone()),
            _ => changed.mut_result().push(result.get_result()[0].clone()),
        }
        assert!(!verifier::verify_vote_result(
            &f.poll, &sum, &decrypted, &changed
        )
        .unwrap());
    }
    let mut wrong_id = decrypted.clone();
    wrong_id.mut_unlisted_candidate_part()[0].set_candidate(8);
    assert!(
        !verifier::verify_vote_result(&f.poll, &sum, &wrong_id, &result)
            .unwrap()
    );
    let mut part =
        counter::count_unlisted("counter", &f.counter, &sum).unwrap();
    let extra = part.get_unlisted_candidate_part()[0]
        .get_decrypted_unlisted_candidate_ballot()[0]
        .clone();
    part.mut_unlisted_candidate_part()[0]
        .mut_decrypted_unlisted_candidate_ballot()
        .push(extra);
    assert!(!verifier::verify_count_request_unlisted(
        &f.poll, &f.share, &sum, &part
    )
    .unwrap());
}

#[test]
fn used_credential_cannot_be_counted_again_after_serialization() {
    let f = Fixture::new();
    let request = f.bounded_vote();
    let mut sum = VoteStorage::new();
    coordinator::aggregate_vote_sum_response(
        &f.poll,
        request.get_vote(),
        &mut sum,
    )
    .unwrap();
    let mut restored: VoteStorage =
        bytes_to_proto(&proto_to_bytes(&sum).unwrap()).unwrap();
    assert_eq!(restored.get_accepted_ballot_id().len(), 1);
    let original = restored.clone();
    assert!(coordinator::aggregate_vote_sum_response(
        &f.poll,
        request.get_vote(),
        &mut restored
    )
    .is_err());
    assert_eq!(restored, original);
    let alternative = f.bounded_vote();
    assert!(verifier::verify_vote_request(
        &f.poll,
        &alternative,
        &f.public_key
    )
    .unwrap());
    assert!(coordinator::aggregate_vote_sum_response(
        &f.poll,
        alternative.get_vote(),
        &mut restored
    )
    .is_err());
    assert_eq!(restored, original);
    let mut legacy = original.clone();
    legacy.clear_accepted_ballot_id();
    assert!(coordinator::aggregate_vote_sum_response(
        &f.poll,
        request.get_vote(),
        &mut legacy
    )
    .is_err());
}

#[test]
fn aggregation_failure_does_not_change_state_or_block_valid_votes() {
    let f = Fixture::new();
    let valid = f.bounded_vote();
    let mut invalid = valid.get_vote().clone();
    invalid.mut_voted_ballot()[1]
        .mut_ballot()
        .set_ciphertext2(vec![0; 33]);
    let mut sum = VoteStorage::new();
    let empty = sum.clone();
    assert!(coordinator::aggregate_vote_sum_response(
        &f.poll, &invalid, &mut sum
    )
    .is_err());
    assert_eq!(sum, empty);
    coordinator::aggregate_vote_sum_response(
        &f.poll,
        valid.get_vote(),
        &mut sum,
    )
    .unwrap();
    let original = sum.clone();
    let secret = voter::make_voter_secret();
    let request = voter::make_registration_request(&secret, &f.poll).unwrap();
    let registration =
        coordinator::certify_voter(&f.signing_key, &request, 10, &f.poll)
            .unwrap();
    let valid =
        voter::vote(&secret, &f.choices(vec![4, 3]), &registration, &f.poll)
            .unwrap();
    let mut invalid = valid.get_vote().clone();
    invalid.mut_voted_ballot()[1]
        .mut_ballot()
        .set_ciphertext2(vec![0; 33]);
    assert!(coordinator::aggregate_vote_sum_response(
        &f.poll, &invalid, &mut sum
    )
    .is_err());
    assert_eq!(sum, original);
    coordinator::aggregate_vote_sum_response(
        &f.poll,
        valid.get_vote(),
        &mut sum,
    )
    .unwrap();
    assert_eq!(sum.get_accepted_ballot_id().len(), 2);
}

#[test]
fn counting_rejects_duplicate_and_extra_unlisted_decryption_parts() {
    let f = Fixture::new();
    let (sum, mut decrypted, _) = f.tally(&f.unlisted_vote(), true);
    let valid = counter::count_unlisted("counter", &f.counter, &sum).unwrap();
    for duplicate in [true, false] {
        let mut part = valid.clone();
        let mut extra = valid.get_unlisted_candidate_part()[0].clone();
        if !duplicate {
            extra
                .mut_candidate_cipher()
                .set_ciphertext1(point_to_bytes(&RistrettoPoint::default()));
        }
        part.mut_unlisted_candidate_part().push(extra);
        assert!(!verifier::verify_count_request_unlisted(
            &f.poll, &f.share, &sum, &part
        )
        .unwrap());
    }
    decrypted.clear_unlisted_candidate_part();
    assert!(coordinator::finalize_vote_result_unlisted(
        &f.poll,
        &sum,
        &mut decrypted,
        20,
        10
    )
    .is_err());
    let mut listed = valid.clone();
    listed
        .mut_candidate_part()
        .push(valid.get_candidate_part()[0].clone());
    assert!(!verifier::verify_count_request_unlisted(
        &f.poll, &f.share, &sum, &listed
    )
    .unwrap());
}

#[test]
fn poll_parameters_reject_ambiguous_candidates_and_degenerate_keys() {
    let f = Fixture::new();
    let mut counters = CounterParametersStorage::new();
    assert!(coordinator::make_poll_parameters(
        f.poll.get_candidates(),
        &counters
    )
    .is_err());
    let share = counter::make_parameters_share("counter", &f.counter).unwrap();
    counters.mut_counter_parameters_share().push(share.clone());
    let mut duplicates = f.poll.get_candidates().clone();
    duplicates.mut_candidate().push("A".to_owned());
    assert!(coordinator::make_poll_parameters(&duplicates, &counters).is_err());
    let mut reserved = f.poll.get_candidates().clone();
    reserved
        .mut_candidate()
        .push(crate::config::POLL_RESULT_KEY_TOTAL_BALLOTS.to_owned());
    assert!(coordinator::make_poll_parameters(&reserved, &counters).is_err());
    counters.mut_counter_parameters_share().push(share);
    assert!(coordinator::make_poll_parameters(
        f.poll.get_candidates(),
        &counters
    )
    .is_err());
    counters.mut_counter_parameters_share().pop();
    counters.mut_counter_parameters_share()[0]
        .set_poll_point_share(point_to_bytes(&RistrettoPoint::default()));
    assert!(coordinator::make_poll_parameters(
        f.poll.get_candidates(),
        &counters
    )
    .is_err());
}

#[test]
fn tally_reports_invalid_bounds_and_handles_zero_total() {
    let f = Fixture::new();
    let (sum, decrypted, _) = f.tally(&f.bounded_vote(), false);
    assert!(
        coordinator::finalize_vote_result(&f.poll, &sum, &decrypted, 1)
            .is_err()
    );
    assert!(
        coordinator::finalize_vote_result(&f.poll, &sum, &decrypted, -1)
            .is_err()
    );
    let zero_registration =
        coordinator::certify_voter(&f.signing_key, &f.registration, 0, &f.poll)
            .unwrap();
    let zero_vote = voter::vote(
        &f.secret,
        &f.choices(vec![0, 0]),
        &zero_registration,
        &f.poll,
    )
    .unwrap();
    let (sum, decrypted, result) = f.tally(&zero_vote, false);
    let zero = coordinator::finalize_vote_result(&f.poll, &sum, &decrypted, 0)
        .unwrap();
    assert_eq!(zero, result);
    assert!(zero.get_result().iter().all(|pair| pair.get_value() == 0));
    let (sum, mut decrypted, _) = f.tally(&f.unlisted_vote(), true);
    assert!(coordinator::finalize_vote_result_unlisted(
        &f.poll,
        &sum,
        &mut decrypted,
        20,
        6
    )
    .is_err());
}
