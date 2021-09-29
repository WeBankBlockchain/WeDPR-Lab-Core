// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous ciphertext voting (ACV) solution.

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate wedpr_l_macros;

pub mod config;
pub mod coordinator;
pub mod counter;
mod utils;
pub mod verifier;
pub mod voter;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::SIGNATURE, coordinator};
    use wedpr_l_crypto_zkp_utils::bytes_to_point;
    use wedpr_l_utils::traits::Signature;
    use wedpr_s_protos::generated::acv::{
        CandidateList, CounterParametersStorage, CounterSecret,
        DecryptedResultPartStorage, VoteStorage, VoterSecret,
    };

    #[test]
    fn test_anonymous_ciphertext_voting() {
        // Initialize a group of counters.
        let mut counter_secret_list: Vec<CounterSecret> = vec![];
        let mut counter_parameters = CounterParametersStorage::default();
        // You can use any strings for counter ids.
        let counter_id_list = ["1001", "1002", "1003"];
        for counter_id in counter_id_list {
            let counter_secret = counter::make_counter_secret();
            let counter_parameters_share =
                counter::make_parameters_share(counter_id, &counter_secret)
                    .unwrap();
            counter_parameters
                .mut_counter_parameters_share()
                .push(counter_parameters_share);
            counter_secret_list.push(counter_secret);
        }

        // Initialize the coordinator.
        let (public_key, secret_key) = SIGNATURE.generate_keypair();

        // Coordinator initializes a new poll.
        let mut candidate_list = CandidateList::new();
        for candidate in ["Kitten", "Doge", "Bunny"] {
            candidate_list.mut_candidate().push(candidate.to_string());
        }
        let poll_parameters = coordinator::make_poll_parameters(
            &candidate_list,
            &counter_parameters,
        )
        .unwrap();

        // Initialize all voters.
        let mut voter_secret_list: Vec<VoterSecret> = vec![];
        let mut voter_registration_list = vec![];
        // Voter weight is the max voting power of each voter assigned by
        // coordinator.
        let voter_weight_list = [10, 20, 50, 60];
        for voter_weight in voter_weight_list {
            let vote_secret = voter::make_voter_secret();
            // Register a voter with coordinator.
            let registration_request = voter::make_registration_request(
                &vote_secret,
                &poll_parameters,
            )
            .unwrap();
            let registration_response = coordinator::certify_voter(
                &secret_key,
                &registration_request,
                voter_weight,
            )
            .unwrap();
            // Verify the blank ballot contained in registration_response.
            assert!(voter::verify_blank_ballot(
                &registration_request,
                &registration_response
            )
            .unwrap());
            voter_registration_list.push(registration_response);
            voter_secret_list.push(vote_secret);
        }

        // All voters vote.
        //          Kitten  Doge   Bunny
        // voter1:     1      2      3
        // voter2:     2      4      6
        // voter3:    10     15     25
        // voter4:    20     10      5
        let voter_choice_list: Vec<Vec<u32>> =
            vec![vec![1, 2, 3], vec![2, 4, 6], vec![10, 15, 25], vec![
                20, 10, 5,
            ]];
        let mut vote_request_list = vec![];
        let mut encrypted_vote_sum = VoteStorage::new();
        for index in 0..voter_choice_list.len() {
            let vote_choices = voter::make_vote_choices(
                &voter_choice_list[index],
                &candidate_list,
            );
            let vote_request = voter::vote(
                &voter_secret_list[index],
                &vote_choices,
                &voter_registration_list[index],
                &poll_parameters,
            )
            .unwrap();
            assert!(verifier::verify_vote_request(
                &poll_parameters,
                &vote_request,
                &public_key
            )
            .unwrap());

            // Coordinator aggregates individual ciphertext ballots.
            assert!(coordinator::aggregate_vote_sum_response(
                &poll_parameters,
                &vote_request.get_vote(),
                &mut encrypted_vote_sum
            )
            .unwrap());
            vote_request_list.push(vote_request);
        }

        // All counters decrypt the poll result in a distributed manner.
        let mut aggregated_decrypted_result = DecryptedResultPartStorage::new();
        for index in 0..counter_secret_list.len() {
            let partially_decrypted_result = counter::count(
                &counter_id_list[index],
                &counter_secret_list[index],
                &encrypted_vote_sum,
            )
            .unwrap();
            let counter_share = bytes_to_point(
                counter_parameters.get_counter_parameters_share()[index]
                    .get_poll_point_share(),
            )
            .unwrap();
            assert!(verifier::verify_count_request(
                &poll_parameters,
                &encrypted_vote_sum,
                &counter_share,
                &partially_decrypted_result
            )
            .unwrap());

            // Coordinator aggregates parts of decrypted poll result.
            assert!(coordinator::aggregate_decrypted_part_sum(
                &poll_parameters,
                &partially_decrypted_result,
                &mut aggregated_decrypted_result
            )
            .unwrap());
        }

        // Coordinator decrypts the final poll result by enumerating all
        // possible value and checking ZKP data.
        // TODO: Design a better way to do the decryption.
        // Each candidate should not receive more than 20k votes.
        let max_vote_limit = 200;
        let vote_result = coordinator::finalize_vote_result(
            &poll_parameters,
            &encrypted_vote_sum,
            &aggregated_decrypted_result,
            max_vote_limit,
        )
        .unwrap();
        assert!(verifier::verify_vote_result(
            &poll_parameters,
            &encrypted_vote_sum,
            &aggregated_decrypted_result,
            &vote_result,
        )
        .unwrap());
    }
}
