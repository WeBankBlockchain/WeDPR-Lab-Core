// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of anonymous ciphertext voting (ACV) solution.

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate wedpr_l_macros;

pub mod config;
pub mod coordinator;
pub mod counter;
pub mod verifier;
pub mod voter;

#[cfg(test)]
mod tests {
    use wedpr_l_crypto_zkp_utils::bytes_to_point;
    use wedpr_l_utils::traits::Signature;

    use wedpr_s_protos::generated::acv::{
        CandidateList, CounterSecret, CounterSystemParametersStorage,
        DecryptedResultPartStorage, VoteChoice, VoteChoices, VoteStorage,
        VoterSecret,
    };

    use crate::{config::SIGNATURE_SECP256K1, coordinator};

    use super::*;

    #[test]
    fn test_anonymous_ciphertext_voting() {
        // Generate coordinator's key pair
        let max_vote_number = 20000;
        let (public_key, secret_key) = SIGNATURE_SECP256K1.generate_keypair();
        let mut candidate_list = CandidateList::new();
        // Init candidate list
        for candidate in vec!["Kitten", "Doge", "Bunny"] {
            candidate_list.mut_candidate().push(candidate.to_string());
        }
        let counter_id_list = vec!["1001", "1002", "1003"];
        let blank_ballot_count = vec![10, 100, 1000, 10000];

        let mut counter_secret_list: Vec<CounterSecret> = vec![];
        let mut counter_parameters_storage =
            CounterSystemParametersStorage::default();
        // Counter init
        for id in counter_id_list.clone() {
            let share_secret = counter::make_counter_secret();
            counter_secret_list.push(share_secret.clone());
            let counter_parameters_request =
                counter::make_system_parameters_share(id, &share_secret)
                    .unwrap();
            counter_parameters_storage
                .mut_counter_parameters_request()
                .push(counter_parameters_request.clone());
        }
        // coordinator make system parameters
        let system_parameters = coordinator::make_system_parameters(
            &candidate_list,
            &counter_parameters_storage,
        )
        .unwrap();

        // voter init
        let mut voter_secret_list: Vec<VoterSecret> = vec![];
        let mut response_list = vec![];

        for blank_ballot in blank_ballot_count {
            let vote_secret = voter::make_voter_secret();
            voter_secret_list.push(vote_secret.clone());

            // voter -> coordinator generate blank ballot
            let vote_request = voter::make_registration_request(
                &vote_secret,
                &system_parameters,
            )
            .unwrap();
            let response = coordinator::certify_voter(
                &secret_key,
                blank_ballot,
                &vote_request,
            )
            .unwrap();
            response_list.push(response.clone());
            // verify blank ballot
            let result =
                voter::verify_blank_ballot(&vote_request, &response).unwrap();
            assert_eq!(true, result);
        }

        // voter vote
        let make_choice = |x: &Vec<u32>| {
            let mut choices = VoteChoices::new();
            for i in 0..candidate_list.get_candidate().len() {
                let mut pair = VoteChoice::new();
                pair.set_candidate(candidate_list.get_candidate()[i].clone());
                pair.set_value(x[i]);
                choices.mut_choice().push(pair);
            }
            choices
        };

        let voting_ballot_count: Vec<Vec<u32>> =
            vec![vec![1, 2, 3], vec![10, 20, 30], vec![100, 200, 300], vec![
                1000, 2000, 3000,
            ]];
        let mut vote_request_list = vec![];
        let mut encrypted_vote_sum = VoteStorage::new();
        for index in 0..voting_ballot_count.len() {
            let ballot_choice = make_choice(&voting_ballot_count[index]);
            let vote_request = voter::vote(
                &voter_secret_list[index],
                &ballot_choice,
                &response_list[index],
                &system_parameters,
            )
            .unwrap();
            assert_eq!(
                true,
                verifier::verify_vote_request(
                    &system_parameters,
                    &vote_request,
                    &public_key
                )
                .unwrap()
            );
            assert_eq!(
                true,
                coordinator::aggregate_vote_sum_response(
                    &system_parameters,
                    &vote_request.get_vote(),
                    &mut encrypted_vote_sum
                )
                .unwrap()
            );
            vote_request_list.push(vote_request);
        }
        let mut vote_sum_total = DecryptedResultPartStorage::new();
        let length = counter_secret_list.len().clone();
        for index in 0..length {
            let decrypt_request = counter::count(
                &counter_id_list[index],
                &counter_secret_list[index],
                &encrypted_vote_sum,
            )
            .unwrap();
            let share = bytes_to_point(
                counter_parameters_storage.get_counter_parameters_request()
                    [index]
                    .get_poll_point_share(),
            )
            .unwrap();
            assert_eq!(
                true,
                verifier::verify_count_request(
                    &system_parameters,
                    &encrypted_vote_sum,
                    &share,
                    &decrypt_request
                )
                .unwrap()
            );
            assert_eq!(
                true,
                coordinator::aggregate_decrypted_part_sum(
                    &system_parameters,
                    &decrypt_request,
                    &mut vote_sum_total
                )
                .unwrap()
            );
        }
        let final_result_request = coordinator::finalize_vote_result(
            &system_parameters,
            &encrypted_vote_sum,
            &vote_sum_total,
            max_vote_number,
        )
        .unwrap();
        wedpr_println!("final result is : {:?}", final_result_request);
        let result = verifier::verify_vote_result(
            &system_parameters,
            &encrypted_vote_sum,
            &vote_sum_total,
            &final_result_request,
        )
        .unwrap();
        assert!(result);
    }
}
