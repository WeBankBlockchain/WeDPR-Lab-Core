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
    use wedpr_l_crypto_zkp_utils::{
        bytes_to_point, get_random_scalar, scalar_to_bytes,
    };
    use wedpr_l_utils::traits::Signature;
    use wedpr_s_protos::generated::acv::{
        CandidateList, CounterParametersStorage, CounterSecret,
        DecryptedResultPartStorage, UnlistedVoteChoice, VoteChoice,
        VoteChoices, VoteStorage, VoterSecret,
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

    #[test]
    fn test_unbounded_voting() {
        let candidate_list: Vec<String> = vec!["Alice", "Bob", "charlie"]
            .iter()
            .map(|i| i.to_string())
            .collect();
        let counter_id_list = vec!["10086", "10010", "10000"];
        let blank_ballot_count = vec![10, 20, 30];
        let voting_ballot_weight =
            vec![vec![10, 0, 10], vec![0, 20, 20], vec![30, 30, 30]];
        let max_vote_number = 60;
        let init_counter = || {
            let counter_secret = counter::make_counter_secret();
            counter_secret
        };

        let counter1 = init_counter();
        let counter2 = init_counter();
        let counter3 = init_counter();

        let counter_share1 =
            counter::make_parameters_share(&counter_id_list[0], &counter1)
                .unwrap();
        let counter_share2 =
            counter::make_parameters_share(&counter_id_list[1], &counter2)
                .unwrap();
        let counter_share3 =
            counter::make_parameters_share(&counter_id_list[2], &counter3)
                .unwrap();

        // generate the candidate list
        let mut pb_candidate_list = CandidateList::new();
        for i in candidate_list.iter() {
            pb_candidate_list.mut_candidate().push(i.to_string());
        }
        // generate the CounterParametersStorage
        let mut counter_parameters = CounterParametersStorage::new();
        counter_parameters
            .mut_counter_parameters_share()
            .push(counter_share1.clone());
        counter_parameters
            .mut_counter_parameters_share()
            .push(counter_share2.clone());
        counter_parameters
            .mut_counter_parameters_share()
            .push(counter_share3.clone());
        let poll_parameters = coordinator::make_poll_parameters(
            &pb_candidate_list,
            &counter_parameters,
        )
        .unwrap();
        pub struct VoterSecretPair {
            pub weight_secret: VoterSecret,
            pub zero_sercret: VoterSecret,
        }
        let init_voter = || {
            let mut pb_secret_r = VoterSecret::new();
            pb_secret_r.set_voter_secret(scalar_to_bytes(&get_random_scalar()));
            let mut pb_zero_secret_r = VoterSecret::new();
            pb_zero_secret_r
                .set_voter_secret(scalar_to_bytes(&get_random_scalar()));
            VoterSecretPair {
                weight_secret: pb_secret_r,
                zero_sercret: pb_zero_secret_r,
            }
        };

        let voter1_secret_pair = init_voter();
        let registration_request1 = voter::make_unbounded_registration_request(
            &voter1_secret_pair.zero_sercret,
            &voter1_secret_pair.weight_secret,
            &poll_parameters,
        )
        .unwrap();

        let voter2_secret_pair = init_voter();
        let registration_request2 = voter::make_unbounded_registration_request(
            &voter2_secret_pair.zero_sercret,
            &voter2_secret_pair.weight_secret,
            &poll_parameters,
        )
        .unwrap();

        let voter3_secret_pair = init_voter();
        let registration_request3 = voter::make_unbounded_registration_request(
            &voter3_secret_pair.zero_sercret,
            &voter3_secret_pair.weight_secret,
            &poll_parameters,
        )
        .unwrap();

        // certify_unbounded_voter
        let coordinator_key_pair = SIGNATURE.generate_keypair();
        let response1 = coordinator::certify_unbounded_voter(
            &coordinator_key_pair.1,
            &registration_request1,
            blank_ballot_count[0],
        )
        .unwrap();

        let response2 = coordinator::certify_unbounded_voter(
            &coordinator_key_pair.1,
            &registration_request2,
            blank_ballot_count[1],
        )
        .unwrap();

        let response3 = coordinator::certify_unbounded_voter(
            &coordinator_key_pair.1,
            &registration_request3,
            blank_ballot_count[2],
        )
        .unwrap();

        // verify blank ballot
        let result =
            voter::verify_blank_ballot(&registration_request1, &response1)
                .unwrap();
        assert_eq!(result, true);
        let result =
            voter::verify_blank_ballot(&registration_request2, &response2)
                .unwrap();
        assert_eq!(result, true);
        let result =
            voter::verify_blank_ballot(&registration_request3, &response3)
                .unwrap();
        assert_eq!(result, true);

        // begin vote
        let mut encrypted_vote_sum = VoteStorage::new();
        let make_choice = |x: &Vec<i32>| {
            let mut choices = VoteChoices::new();
            for i in 0..candidate_list.len() {
                let mut choice = VoteChoice::new();
                choice.set_candidate(candidate_list[i].clone());
                choice.set_value(x[i] as u32);
                choices.mut_choice().push(choice);
            }
            choices
        };
        // voter1 vote
        let choice1 = make_choice(&voting_ballot_weight[0]);
        let vote_request1 = voter::vote_unbounded(
            &voter1_secret_pair.weight_secret,
            &voter1_secret_pair.zero_sercret,
            &choice1,
            &response1,
            &poll_parameters,
        )
        .unwrap();
        // verify the vote
        assert_eq!(
            true,
            verifier::verify_unbounded_vote_request(
                &poll_parameters,
                &vote_request1,
                &coordinator_key_pair.0
            )
            .unwrap()
        );
        wedpr_println!("vote_request1 = {:?}", vote_request1);
        // aggregate the vote
        assert_eq!(
            true,
            coordinator::aggregate_vote_sum_response(
                &poll_parameters,
                &vote_request1.get_vote(),
                &mut encrypted_vote_sum
            )
            .unwrap()
        );

        // voter2 vote
        let choice2 = make_choice(&voting_ballot_weight[1]);
        let vote_request2 = voter::vote_unbounded(
            &voter2_secret_pair.weight_secret,
            &voter2_secret_pair.zero_sercret,
            &choice2,
            &response2,
            &poll_parameters,
        )
        .unwrap();
        // verify the vote request
        assert_eq!(
            true,
            verifier::verify_unbounded_vote_request(
                &poll_parameters,
                &vote_request2,
                &coordinator_key_pair.0
            )
            .unwrap()
        );
        // aggregate the vote
        assert_eq!(
            true,
            coordinator::aggregate_vote_sum_response(
                &poll_parameters,
                &vote_request2.get_vote(),
                &mut encrypted_vote_sum
            )
            .unwrap()
        );

        // voter3 vote
        let choice3 = make_choice(&voting_ballot_weight[2]);
        let vote_request3 = voter::vote_unbounded(
            &voter3_secret_pair.weight_secret,
            &voter3_secret_pair.zero_sercret,
            &choice3,
            &response3,
            &poll_parameters,
        )
        .unwrap();
        // verify the vote request
        assert_eq!(
            true,
            verifier::verify_unbounded_vote_request(
                &poll_parameters,
                &vote_request3,
                &coordinator_key_pair.0
            )
            .unwrap()
        );
        // aggregate the vote_request3
        // aggregate the vote
        assert_eq!(
            true,
            coordinator::aggregate_vote_sum_response(
                &poll_parameters,
                &vote_request3.get_vote(),
                &mut encrypted_vote_sum
            )
            .unwrap()
        );
        wedpr_println!("encrypted_vote_sum: {:?}", encrypted_vote_sum);

        // count the encrypted_vote_sum
        let mut vote_sum_total = DecryptedResultPartStorage::new();
        let decrypt_request1 =
            counter::count(counter_id_list[0], &counter1, &encrypted_vote_sum)
                .unwrap();
        // verify the count request
        assert_eq!(
            true,
            verifier::verify_count_request(
                &poll_parameters,
                &encrypted_vote_sum,
                &bytes_to_point(&counter_share1.get_poll_point_share())
                    .unwrap(),
                &decrypt_request1
            )
            .unwrap()
        );
        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum(
                &poll_parameters,
                &decrypt_request1,
                &mut vote_sum_total,
            )
            .unwrap()
        );

        let decrypt_request2 =
            counter::count(counter_id_list[1], &counter2, &encrypted_vote_sum)
                .unwrap();
        // verify the count request
        assert_eq!(
            true,
            verifier::verify_count_request(
                &poll_parameters,
                &encrypted_vote_sum,
                &bytes_to_point(&counter_share2.get_poll_point_share())
                    .unwrap(),
                &decrypt_request2
            )
            .unwrap()
        );
        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum(
                &poll_parameters,
                &decrypt_request2,
                &mut vote_sum_total,
            )
            .unwrap()
        );
        // count3
        let decrypt_request3 =
            counter::count(counter_id_list[2], &counter3, &encrypted_vote_sum)
                .unwrap();
        // verify the count request
        assert_eq!(
            true,
            verifier::verify_count_request(
                &poll_parameters,
                &encrypted_vote_sum,
                &bytes_to_point(&counter_share3.get_poll_point_share())
                    .unwrap(),
                &decrypt_request3
            )
            .unwrap()
        );
        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum(
                &poll_parameters,
                &decrypt_request3,
                &mut vote_sum_total,
            )
            .unwrap()
        );

        // finalize_vote_result
        let final_result_request = coordinator::finalize_vote_result(
            &poll_parameters,
            &encrypted_vote_sum,
            &vote_sum_total,
            max_vote_number,
        )
        .unwrap();
        wedpr_println!("final result is : {:?}", final_result_request);
        let result = verifier::verify_vote_result(
            &poll_parameters,
            &encrypted_vote_sum,
            &vote_sum_total,
            &final_result_request,
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_unbounded_voting_unlisted() {
        let candidate_list: Vec<String> = vec!["Alice", "Bob", "charlie"]
            .iter()
            .map(|i| i.to_string())
            .collect();
        let candidate_list_unlisted: Vec<i64> = vec![1, 2, 3, 4, 5];
        let counter_id_list = vec!["10086", "10010", "10000"];
        let blank_ballot_count = vec![10, 20, 30];
        let voting_ballot_weight =
            vec![vec![10, 0, 10], vec![0, 20, 20], vec![30, 30, 30]];
        let max_vote_number = 60;
        let max_candidate_number = 10;

        let init_counter = || {
            let counter_secret = counter::make_counter_secret();
            counter_secret
        };
        let counter1 = init_counter();
        let counter2 = init_counter();
        let counter3 = init_counter();
        let counter_share1 =
            counter::make_parameters_share(&counter_id_list[0], &counter1)
                .unwrap();
        let counter_share2 =
            counter::make_parameters_share(&counter_id_list[1], &counter2)
                .unwrap();
        let counter_share3 =
            counter::make_parameters_share(&counter_id_list[2], &counter3)
                .unwrap();

        // generate the candidate list
        let mut pb_candidate_list = CandidateList::new();
        for i in candidate_list.iter() {
            pb_candidate_list.mut_candidate().push(i.to_string());
        }
        // generate the CounterParametersStorage
        let mut counter_parameters = CounterParametersStorage::new();
        counter_parameters
            .mut_counter_parameters_share()
            .push(counter_share1.clone());
        counter_parameters
            .mut_counter_parameters_share()
            .push(counter_share2.clone());
        counter_parameters
            .mut_counter_parameters_share()
            .push(counter_share3.clone());
        let poll_parameters = coordinator::make_poll_parameters(
            &pb_candidate_list,
            &counter_parameters,
        )
        .unwrap();
        pub struct VoterSecretPair {
            pub weight_secret: VoterSecret,
            pub zero_sercret: VoterSecret,
        }
        let init_voter = || {
            let mut pb_secret_r = VoterSecret::new();
            pb_secret_r.set_voter_secret(scalar_to_bytes(&get_random_scalar()));
            let mut pb_zero_secret_r = VoterSecret::new();
            pb_zero_secret_r
                .set_voter_secret(scalar_to_bytes(&get_random_scalar()));
            VoterSecretPair {
                weight_secret: pb_secret_r,
                zero_sercret: pb_zero_secret_r,
            }
        };
        let voter1_secret_pair = init_voter();
        let registration_request1 = voter::make_unbounded_registration_request(
            &voter1_secret_pair.zero_sercret,
            &voter1_secret_pair.weight_secret,
            &poll_parameters,
        )
        .unwrap();

        let voter2_secret_pair = init_voter();
        let registration_request2 = voter::make_unbounded_registration_request(
            &voter2_secret_pair.zero_sercret,
            &voter2_secret_pair.weight_secret,
            &poll_parameters,
        )
        .unwrap();

        let voter3_secret_pair = init_voter();
        let registration_request3 = voter::make_unbounded_registration_request(
            &voter3_secret_pair.zero_sercret,
            &voter3_secret_pair.weight_secret,
            &poll_parameters,
        )
        .unwrap();

        let coordinator_key_pair = SIGNATURE.generate_keypair();
        let response1 = coordinator::certify_unbounded_voter(
            &coordinator_key_pair.1,
            &registration_request1,
            blank_ballot_count[0],
        )
        .unwrap();

        let response2 = coordinator::certify_unbounded_voter(
            &coordinator_key_pair.1,
            &registration_request2,
            blank_ballot_count[1],
        )
        .unwrap();

        let response3 = coordinator::certify_unbounded_voter(
            &coordinator_key_pair.1,
            &registration_request3,
            blank_ballot_count[2],
        )
        .unwrap();
        // verify blank ballot
        let result =
            voter::verify_blank_ballot(&registration_request1, &response1)
                .unwrap();
        assert_eq!(result, true);
        let result =
            voter::verify_blank_ballot(&registration_request2, &response2)
                .unwrap();
        assert_eq!(result, true);
        let result =
            voter::verify_blank_ballot(&registration_request3, &response3)
                .unwrap();
        assert_eq!(result, true);
        let mut encrypted_vote_sum = VoteStorage::new();

        let make_choice = |x: &Vec<i32>, y: &Vec<i64>| {
            let mut choices = VoteChoices::new();
            for i in 0..candidate_list.len() {
                let mut choice = VoteChoice::new();
                choice.set_candidate(candidate_list[i].clone());
                choice.set_value(x[i] as u32);
                choices.mut_choice().push(choice);
            }
            // unlisted
            for j in 0..y.len() {
                let mut pair_unlisted = UnlistedVoteChoice::new();
                pair_unlisted.set_candidate_id(y[j] as u32);
                pair_unlisted.set_value(x[j] as u32);
                choices.mut_unlisted_choice().push(pair_unlisted);
            }
            choices
        };

        // make unlisted choice
        let choice_candidate_unlisted1 =
            &candidate_list_unlisted[0..3].to_vec();
        let choice1 =
            make_choice(&voting_ballot_weight[0], choice_candidate_unlisted1);
        wedpr_println!("choice1:{:?}", choice1);

        let vote_request1 = voter::vote_unbounded_unlisted(
            &voter1_secret_pair.weight_secret,
            &voter1_secret_pair.zero_sercret,
            &choice1,
            &response1,
            &poll_parameters,
        )
        .unwrap();
        // verify
        assert_eq!(
            true,
            verifier::verify_unbounded_vote_request_unlisted(
                &poll_parameters,
                &vote_request1,
                &coordinator_key_pair.0
            )
            .unwrap()
        );
        // aggregate
        assert_eq!(
            true,
            coordinator::aggregate_vote_sum_response_unlisted(
                &poll_parameters,
                &vote_request1.get_vote(),
                &mut encrypted_vote_sum
            )
            .unwrap()
        );
        // vote2
        let choice_candidate_unlisted2 =
            &candidate_list_unlisted[1..3].to_vec();
        let choice2 =
            make_choice(&voting_ballot_weight[1], choice_candidate_unlisted2);
        wedpr_println!("choice2:{:?}", choice2);
        let vote_request2 = voter::vote_unbounded_unlisted(
            &voter2_secret_pair.weight_secret,
            &voter2_secret_pair.zero_sercret,
            &choice2,
            &response2,
            &poll_parameters,
        )
        .unwrap();
        assert_eq!(
            true,
            verifier::verify_unbounded_vote_request_unlisted(
                &poll_parameters,
                &vote_request2,
                &coordinator_key_pair.0
            )
            .unwrap()
        );
        assert_eq!(
            true,
            coordinator::aggregate_vote_sum_response_unlisted(
                &poll_parameters,
                &vote_request2.get_vote(),
                &mut encrypted_vote_sum
            )
            .unwrap()
        );
        // vote3
        let choice_candidate_unlisted3 =
            &candidate_list_unlisted[2..3].to_vec();
        let choice3 =
            make_choice(&voting_ballot_weight[2], choice_candidate_unlisted3);
        wedpr_println!("choice3:{:?}", choice3);
        let vote_request3 = voter::vote_unbounded_unlisted(
            &voter3_secret_pair.weight_secret,
            &voter3_secret_pair.zero_sercret,
            &choice3,
            &response3,
            &poll_parameters,
        )
        .unwrap();
        assert_eq!(
            true,
            verifier::verify_unbounded_vote_request_unlisted(
                &poll_parameters,
                &vote_request3,
                &coordinator_key_pair.0
            )
            .unwrap()
        );
        assert_eq!(
            true,
            coordinator::aggregate_vote_sum_response_unlisted(
                &poll_parameters,
                &vote_request3.get_vote(),
                &mut encrypted_vote_sum
            )
            .unwrap()
        );
        wedpr_println!("encrypted_vote_sum: {:?}", encrypted_vote_sum);

        let mut vote_sum_total = DecryptedResultPartStorage::new();

        let decrypt_request1 = counter::count_unlisted(
            counter_id_list[0],
            &counter1,
            &encrypted_vote_sum,
        )
        .unwrap();
        //        wedpr_println!("decrypt_request1=========================:{:?
        // }", decrypt_request1);
        assert_eq!(
            true,
            verifier::verify_count_request_unlisted(
                &poll_parameters,
                &bytes_to_point(&counter_share1.get_poll_point_share())
                    .unwrap(),
                &encrypted_vote_sum,
                &decrypt_request1
            )
            .unwrap()
        );

        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum_unlisted(
                &poll_parameters,
                &decrypt_request1,
                &mut vote_sum_total,
            )
            .unwrap()
        );
        let decrypt_request2 = counter::count_unlisted(
            counter_id_list[1],
            &counter2,
            &encrypted_vote_sum,
        )
        .unwrap();
        //        wedpr_println!("decrypt_request2=========================:{:?
        // }", decrypt_request2);
        assert_eq!(
            true,
            verifier::verify_count_request_unlisted(
                &poll_parameters,
                &bytes_to_point(&counter_share2.get_poll_point_share())
                    .unwrap(),
                &encrypted_vote_sum,
                &decrypt_request2
            )
            .unwrap()
        );

        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum_unlisted(
                &poll_parameters,
                &decrypt_request2,
                &mut vote_sum_total,
            )
            .unwrap()
        );

        let decrypt_request3 = counter::count_unlisted(
            counter_id_list[2],
            &counter3,
            &encrypted_vote_sum,
        )
        .unwrap();
        //        wedpr_println!("decrypt_request3=========================:{:?
        // }", decrypt_request3);
        assert_eq!(
            true,
            verifier::verify_count_request_unlisted(
                &poll_parameters,
                &bytes_to_point(&counter_share3.get_poll_point_share())
                    .unwrap(),
                &encrypted_vote_sum,
                &decrypt_request3
            )
            .unwrap()
        );

        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum_unlisted(
                &poll_parameters,
                &decrypt_request3,
                &mut vote_sum_total,
            )
            .unwrap()
        );
        //        wedpr_println!("vote_sum_total:{:?}", vote_sum_total);

        let final_result_request_unlisted =
            coordinator::finalize_vote_result_unlisted(
                &poll_parameters,
                &encrypted_vote_sum,
                &mut vote_sum_total,
                max_vote_number,
                max_candidate_number,
            )
            .unwrap();

        wedpr_println!(
            "final result unlisted is : {:?}",
            final_result_request_unlisted
        );

        let result = verifier::verify_vote_result(
            &poll_parameters,
            &encrypted_vote_sum,
            &vote_sum_total,
            &final_result_request_unlisted,
        )
        .unwrap();
        assert!(result);
    }
}
