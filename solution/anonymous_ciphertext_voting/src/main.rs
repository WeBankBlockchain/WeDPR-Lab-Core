// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Minimalist demo of anonymous ciphertext voting.

use wedpr_l_crypto_zkp_utils::bytes_to_point;
use wedpr_l_utils::traits::Signature;

use wedpr_s_protos::generated::acv::{
    CandidateList, CounterParametersStorage, CounterSecret,
    DecryptedResultPartStorage, VoteStorage, VoterSecret,
};

extern crate wedpr_s_anonymous_ciphertext_voting;
use colored::Colorize;
use wedpr_s_anonymous_ciphertext_voting::{
    config::{POLL_RESULT_KEY_TOTAL_BALLOTS, SIGNATURE},
    coordinator, counter, verifier, voter,
};

fn main() {
    print_highlight2(
        "#\n# Welcome to anonymous ciphertext voting (ACV) demo!",
        "# 欢迎来到多方密文决策demo演示!\n#",
    );
    println!();
    print_alert2(
        "Please select the display language used for this demonstration: ▼▼▼",
        "请选择演示所使用的显示语言：▼▼▼",
    );

    print_alert2(
        " ▶ Enter \"1\" to select English (default option)",
        " ▶ 输入 \"2\" 选择中文",
    );
    println!();
    let mut choice = wait_for_input();
    loop {
        // The default option.
        if choice == "1" || choice.is_empty() {
            flow_en();
            break;
        } else if choice == "2" {
            flow_cn();
            break;
        } else {
            print_alert2(
                "输入错误！请重新输入：",
                "Invalid input! Please try again:",
            );
            choice = wait_for_input();
        }
    }
}

fn flow_cn() {
    print_wide(
        "投票demo流程中，您将体验多方密文决策的全过程，具体包括：\n
        1. 投票者如何使用密文选票进行隐匿投票；\n
        2. 计票者如何联合解密得到计票结果；\n
        3. 任意验证者如何借助零知识证明来验证整个过程中投票者与计票者行为的正确性。",
    );
    print_wide("为了更容易理解其效果，我们设定了如下示例场景。");

    println!(
        "{}\n{}\n{}\n",
        "【场景介绍】".yellow(),
        "4个投票者为3个候选人进行投票，\
         每个投票者都可向其中任意一个或多个候选人投出包含一定数值的密文选票，",
        "3个计票者需合作才能统计出每个候选人的最终得票。",
    );
    println!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        "【流程介绍】".yellow(),
        "1. 投票者申请密文空白选票；",
        "2. 投票者决定为各候选人分别投出多少票数，\
         生成并投出对应的密文选票和零知识证明；",
        "3. 任意验证者验证投票者投出的密文选票是否正确有效；",
        "4. 计票者联合计算每个候选人的得票，公布统计结果和零知识证明；",
        "5. 任意验证者验证计票者的计票过程及计票结果是否正确有效。"
    );
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】",
        "<<申请密文空白选票>>".yellow(),
        "↦ 投出对各候选人的密文选票 ↦ 验证密文选票 ↦ 联合计票并公布计票信息↦ \
         验证计票过程 ↦ 公布计票结果 ↦ 验证计票结果",
    );

    print_alert(
        "现在请输入当前投票者的密文空白选票的权重：\
         ▼▼（密文空白选票的权重表示：该投票者可以投出的密文选票最大总票数）",
    );
    print_highlight(
        "这里，我们暂定密文空白选票权重上限为100（真实业务可按需扩展），\
         请输入0到100之间的整数",
    );
    let last_voter_weight = wait_for_number_cn();
    let mut voter_weight_list = vec![100, 100, 100];
    voter_weight_list.push(last_voter_weight as u32);
    let last_voter_id = voter_weight_list.len() - 1;

    // Initialize a group of counters.
    let counter_id_list = vec!["1001", "1002", "1003"];
    let mut counter_secret_list: Vec<CounterSecret> = vec![];
    let mut counter_parameters = CounterParametersStorage::default();
    for id in counter_id_list.clone() {
        let counter_secret = counter::make_counter_secret();
        let counter_parameters_share =
            counter::make_parameters_share(id, &counter_secret).unwrap();
        counter_parameters
            .mut_counter_parameters_share()
            .push(counter_parameters_share);
        counter_secret_list.push(counter_secret);
    }

    // Initialize the coordinator.
    let (public_key, secret_key) = SIGNATURE.generate_keypair();

    // Coordinator initializes a new poll.
    let mut candidate_list = CandidateList::new();
    for candidate in ["张三", "李四", "王五"] {
        candidate_list.mut_candidate().push(candidate.to_string());
    }
    let poll_parameters =
        coordinator::make_poll_parameters(&candidate_list, &counter_parameters)
            .unwrap();

    // Initialize all voters.
    let mut voter_secret_list: Vec<VoterSecret> = vec![];
    let mut voter_registration_list = vec![];
    // Voter weight is the max voting power of each voter assigned by
    // coordinator.
    for blank_ballot in voter_weight_list {
        let vote_secret = voter::make_voter_secret();
        // Register a voter with coordinator.
        let registration_request =
            voter::make_registration_request(&vote_secret, &poll_parameters)
                .unwrap();
        let registration_response = coordinator::certify_voter(
            &secret_key,
            &registration_request,
            blank_ballot,
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
    println!(
        "您的密文空白选票为：\n{:?}\n",
        voter_registration_list[last_voter_id].get_ballot()
    );
    print_alert("注：投票者申请的密文空白选票中不包含投票者的身份及其权重。");
    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 申请密文空白选票 ↦",
        "<<投出对各候选人的密文选票>>".yellow(),
        "↦ 验证密文选票 ↦ 联合计票并公布计票信息↦ 验证计票过程 ↦ 公布计票结果 \
         ↦ 验证计票结果",
    );

    print_alert("现在请输入您对 张三 投票的票数：▼▼");
    let candidate1_votes = wait_for_number_cn();
    print_alert("现在请输入您对 李四 投票的票数：▼▼");
    let candidate2_votes = wait_for_number_cn();
    print_alert("现在请输入您对 王五 投票的票数：▼▼");
    print_highlight(
        "注：当投出的总票数大于密文空白选票权重时，会导致投票失败。",
    );
    let candidate3_votes = wait_for_number_cn();

    // All voters vote.
    let candidate1_default = 10;
    let candidate2_default = 20;
    let candidate3_default = 30;
    let voting_ballot_count: Vec<Vec<u32>> = vec![
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![candidate1_votes, candidate2_votes, candidate3_votes],
    ];

    let mut vote_request_list = vec![];
    let mut encrypted_vote_sum = VoteStorage::new();
    for index in 0..voting_ballot_count.len() {
        let vote_choices = voter::make_vote_choices(
            &voting_ballot_count[index],
            &candidate_list,
        );
        let vote_request = match voter::vote(
            &voter_secret_list[index],
            &vote_choices,
            &voter_registration_list[index],
            &poll_parameters,
        ) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "\n投票失败：您投出的总票数超出您的权重限制：{} + {} + {} \
                     > {}\n",
                    candidate1_votes,
                    candidate2_votes,
                    candidate3_votes,
                    last_voter_weight
                );
                return;
            },
        };

        // Coordinator aggregates individual ciphertext ballots.
        coordinator::aggregate_vote_sum_response(
            &poll_parameters,
            &vote_request.get_vote(),
            &mut encrypted_vote_sum,
        )
        .unwrap();
        vote_request_list.push(vote_request);
    }
    println!(
        "\n您投出的密文选票为：\n{:?}\n",
        vote_request_list[last_voter_id].get_vote()
    );
    print_alert(
        "注：投票者投出的密文选票中不包含投票者身份、候选人获得票数等信息。",
    );
    println!("假定其他投票者对三位候选人的投票均为[10，20，30]。");
    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 申请密文空白选票 ↦ 投出对各候选人的密文选票 ↦",
        "<<验证密文选票>>".yellow(),
        "↦ 联合计票并公布计票信息↦ 验证计票过程 ↦ 公布计票结果 ↦ 验证计票结果",
    );

    println!(
        "验证内容包括：\n1. 投给每个候选人的密文选票票数非负；\n2. \
         每个密文选票格式正确（否则会导致后续计票失败）；\n3. \
         投票者投出的密文选票票数之和小于等于其密文空白选票权重。"
    );
    print_alert("\n注：只有通过验证的密文选票，才会进入后续计票流程。");
    pause_cn();

    // Verifier verifies all ciphertext ballots.
    for index in 0..vote_request_list.len() {
        println!(
            "对投票者{}的验证结果为：{}",
            index,
            if verifier::verify_vote_request(
                &poll_parameters,
                &vote_request_list[index],
                &public_key,
            )
            .unwrap()
            {
                "✓"
            } else {
                "✗"
            }
        );
    }
    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 申请密文空白选票 ↦ 投出对各候选人的密文选票 ↦ \
         验证密文选票 ↦",
        "<<联合计票并公布计票信息>>".yellow(),
        "↦ 验证计票过程 ↦ 公布计票结果 ↦ 验证计票结果",
    );

    // All counters decrypt the poll result in a distributed manner.
    let mut aggregated_decrypted_result = DecryptedResultPartStorage::new();
    let mut partially_decrypted_result_list = vec![];
    let mut counter_share_list = vec![];
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

        // Coordinator aggregates parts of decrypted poll result.
        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum(
                &poll_parameters,
                &partially_decrypted_result,
                &mut aggregated_decrypted_result
            )
            .unwrap()
        );
        partially_decrypted_result_list.push(partially_decrypted_result);
        counter_share_list.push(counter_share);
    }
    println!(
        "所有计票者联合计票的聚合计票信息为：\n{:?}",
        aggregated_decrypted_result
    );
    print_alert(
        "注：计票者公布的聚合计票信息中无法反推出个人投票数等隐私信息。",
    );
    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 申请密文空白选票 ↦ 投出对各候选人的密文选票 ↦ \
         验证密文选票 ↦ 联合计票并公布计票信息 ↦",
        "<<验证计票过程>>".yellow(),
        "↦ 公布计票结果 ↦ 验证计票结果",
    );

    println!(
        "验证内容包括：\n1. \
         验证计票者公布的计票信息是使用正确的计票者密钥计算而得，\
         而不是随意构造而得。\n"
    );
    for index in 0..counter_secret_list.len() {
        println!(
            "对计票者{}的验证结果为：{}",
            index,
            if verifier::verify_count_request(
                &poll_parameters,
                &encrypted_vote_sum,
                &counter_share_list[index],
                &partially_decrypted_result_list[index],
            )
            .unwrap()
            {
                "✓"
            } else {
                "✗"
            }
        );
    }

    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 申请密文空白选票 ↦ 投出对各候选人的密文选票 ↦ \
         验证密文选票 ↦ 联合计票并公布计票信息 ↦ 验证计票过程 ↦",
        "<<公布计票结果>>".yellow(),
        "↦ 验证计票结果",
    );

    let max_vote_limit = 20000;
    let vote_result = coordinator::finalize_vote_result(
        &poll_parameters,
        &encrypted_vote_sum,
        &aggregated_decrypted_result,
        max_vote_limit,
    )
    .unwrap();
    for result in vote_result.get_result() {
        if result.get_key() == POLL_RESULT_KEY_TOTAL_BALLOTS {
            continue;
        }
        println!("{} 最终得票为 {}", result.get_key(), result.get_value());
    }

    // TODO: Refactor to use a more elegant way for the following code.
    print_alert("\n对比传统明文计票结果：");
    let plaintext_result1 = (candidate1_default
        + candidate1_default
        + candidate1_default
        + candidate1_votes) as i64;
    let plaintext_result2 = (candidate2_default
        + candidate2_default
        + candidate2_default
        + candidate2_votes) as i64;
    let plaintext_result3 = (candidate3_default
        + candidate3_default
        + candidate3_default
        + candidate3_votes) as i64;
    println!(
        "张三得票：{} + {} + {} + {} = {}",
        candidate1_default,
        candidate1_default,
        candidate1_default,
        candidate1_votes,
        plaintext_result1
    );
    println!(
        "李四得票：{} + {} + {} + {} = {}",
        candidate2_default,
        candidate2_default,
        candidate2_default,
        candidate2_votes,
        plaintext_result2
    );
    println!(
        "王五得票：{} + {} + {} + {} = {}",
        candidate3_default,
        candidate3_default,
        candidate3_default,
        candidate3_votes,
        plaintext_result3
    );
    assert!(
        vote_result.get_result()[1].get_value() == plaintext_result1
            && vote_result.get_result()[2].get_value() == plaintext_result2
            && vote_result.get_result()[3].get_value() == plaintext_result3
    );
    print_alert("\n注：密文选票的计票结果与传统明文计票结果一致。");
    pause_cn();

    println!(
        "{} {} \n",
        "【演示进度】 申请密文空白选票 ↦ 投出对各候选人的密文选票 ↦ \
         验证密文选票 ↦ 联合计票并公布计票信息 ↦ 验证计票过程 ↦ 公布计票结果 ↦",
        "<<验证计票结果>>".yellow(),
    );
    println!(
        "\n最终计票结果的有效性：{}",
        if verifier::verify_vote_result(
            &poll_parameters,
            &encrypted_vote_sum,
            &aggregated_decrypted_result,
            &vote_result,
        )
        .unwrap()
        {
            "✓"
        } else {
            "✗"
        }
    );
    pause_cn();

    print_alert("十分感谢您的试用！");
    println!(
        "\n{}\n\n{}\n{}\n",
        "关于WeDPR，如需了解更多，欢迎通过以下方式联系我们",
        "1. 微信公众号【微众银行区块链】",
        "2. 官方邮箱【wedpr@webank.com】"
    );
    println!();
}

fn flow_en() {
    print_wide(
        "In this demo, you will experience how to use anonymous ciphertext \
         voting, including: \n
        1. A certified voter generates ciphertext ballots to protect real \
         opinion. \n
        2. A group of counters jointly decrypt and count the voting results. \n
        3. A public verifier verifies the validity of the whole voting process \
         via advance zero-knowledge proof (ZKP).",
    );
    print_wide(
        "We use the following application scenario for easy demonstration of \
         this new capability.",
    );

    println!(
        "{}\n{}\n",
        "[Background]".yellow(),
        "4 voters vote for 3 candidates, where each voter can vote for \
         multiple candidates as long as the total number of voted ballots are \
         no more than its preassigned weight.",
    );
    println!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        "[Story]".yellow(),
        "1. A voter apply for certified blank ciphertext ballots.",
        "2. A voter votes for chosen candidates and generates ZKP proofs.",
        "3. A public verifier verifies the validity of voting via ZKP.",
        "4. A group of counters jointly decrypt and count the voting results \
         and generates ZKP proofs.",
        "5. A public verifier verifies the validity of counting via ZKP."
    );
    pause_en();

    println!(
        "{} {} {}\n",
        "[Demo progress]",
        "<<Apply for certified blank ballots>>".yellow(),
        "↦ Vote ↦ Verify voting ↦ Count jointly ↦ Verify counting ↦ Publish \
         result ↦ Verify result",
    );

    print_alert(
        "Please enter your voter weight: ▼▼ The voter weight specifies the \
         max votes you can vote.",
    );
    print_highlight(
        "In this demo, we use 100 as the weight limit, which could be \
         extended for a higher limit in real applications. Please enter a \
         integer number between 0 and 100.",
    );
    let last_voter_weight = wait_for_number_en();
    let mut voter_weight_list = vec![100, 100, 100];
    voter_weight_list.push(last_voter_weight as u32);
    let last_voter_id = voter_weight_list.len() - 1;

    // Initialize a group of counters.
    let counter_id_list = vec!["1001", "1002", "1003"];
    let mut counter_secret_list: Vec<CounterSecret> = vec![];
    let mut counter_parameters = CounterParametersStorage::default();
    for id in counter_id_list.clone() {
        let counter_secret = counter::make_counter_secret();
        let counter_parameters_share =
            counter::make_parameters_share(id, &counter_secret).unwrap();
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
    let poll_parameters =
        coordinator::make_poll_parameters(&candidate_list, &counter_parameters)
            .unwrap();

    // Initialize all voters.
    let mut voter_secret_list: Vec<VoterSecret> = vec![];
    let mut voter_registration_list = vec![];
    // Voter weight is the max voting power of each voter assigned by
    // coordinator.
    for blank_ballot in voter_weight_list {
        let vote_secret = voter::make_voter_secret();
        // Register a voter with coordinator.
        let registration_request =
            voter::make_registration_request(&vote_secret, &poll_parameters)
                .unwrap();
        let registration_response = coordinator::certify_voter(
            &secret_key,
            &registration_request,
            blank_ballot,
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
    println!(
        "You will receive the following certified blank ballots: \n{:?}\n",
        voter_registration_list[last_voter_id].get_ballot()
    );
    print_alert(
        "Notice: No voter id or weight in certified blank ciphertext ballots.",
    );
    pause_en();

    println!(
        "{} {} {} \n",
        "[Demo progress] Apply for certified blank ballots ↦",
        "<<Vote>>".yellow(),
        "↦ Verify voting ↦ Count jointly ↦ Verify counting ↦ Publish result ↦ \
         Verify result",
    );

    print_alert("Please enter your votes for Kitten ▼▼");
    let candidate1_votes = wait_for_number_en();
    print_alert("Please enter your votes for Doge ▼▼");
    let candidate2_votes = wait_for_number_en();
    print_alert("Please enter your votes for Bunny ▼▼");
    print_highlight(
        "Notice: Your total votes cannot exceed your voter weight.",
    );
    let candidate3_votes = wait_for_number_en();

    // All voters vote.
    let candidate1_default = 10;
    let candidate2_default = 20;
    let candidate3_default = 30;
    let voting_ballot_count: Vec<Vec<u32>> = vec![
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![candidate1_votes, candidate2_votes, candidate3_votes],
    ];

    let mut vote_request_list = vec![];
    let mut encrypted_vote_sum = VoteStorage::new();
    for index in 0..voting_ballot_count.len() {
        let vote_choices = voter::make_vote_choices(
            &voting_ballot_count[index],
            &candidate_list,
        );
        let vote_request = match voter::vote(
            &voter_secret_list[index],
            &vote_choices,
            &voter_registration_list[index],
            &poll_parameters,
        ) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "\nVote Failed: Your total votes has exceeded your voter \
                     weight: {} + {} + {} > {}\n",
                    candidate1_votes,
                    candidate2_votes,
                    candidate3_votes,
                    last_voter_weight
                );
                return;
            },
        };

        // Coordinator aggregates individual ciphertext ballots.
        coordinator::aggregate_vote_sum_response(
            &poll_parameters,
            &vote_request.get_vote(),
            &mut encrypted_vote_sum,
        )
        .unwrap();
        vote_request_list.push(vote_request);
    }
    println!(
        "\nYour voted ciphertext ballots are: \n{:?}\n",
        vote_request_list[last_voter_id].get_vote()
    );
    print_alert(
        "Notice: No voter id or candidate votes in ciphertext ballots.",
    );
    println!(
        "For simplicity, we assume the other three voters voted [10, 20, 30] \
         for our candidates."
    );
    pause_en();

    println!(
        "{} {} {} \n",
        "[Demo progress] Apply for certified blank ballots ↦ Vote ↦",
        "<<Verify voting>>".yellow(),
        "↦ Count jointly ↦ Verify counting ↦ Publish result ↦ Verify result",
    );

    println!(
        "Now verifying: \n1. All votes in ciphertext ballots is not negative \
         numbers.\n2. All ciphertext ballots are in a valid format.\n3. The \
         vote sum in ciphertext ballots from the same voter is no larger than \
         its weight."
    );
    print_alert(
        "\nNotice: Only verified ciphertext ballots will be later counted.",
    );
    pause_en();

    // Verifier verifies all ciphertext ballots.
    for index in 0..vote_request_list.len() {
        println!(
            "Voter {}'s voted ciphertext ballots: {}",
            index,
            if verifier::verify_vote_request(
                &poll_parameters,
                &vote_request_list[index],
                &public_key,
            )
            .unwrap()
            {
                "✓"
            } else {
                "✗"
            }
        );
    }
    pause_en();

    println!(
        "{} {} {} \n",
        "[Demo progress] Apply for certified blank ballots ↦ Vote ↦ Verify \
         voting ↦",
        "<<Count jointly>>".yellow(),
        "↦ Verify counting ↦ Publish result ↦ Verify result",
    );

    // All counters decrypt the poll result in a distributed manner.
    let mut aggregated_decrypted_result = DecryptedResultPartStorage::new();
    let mut partially_decrypted_result_list = vec![];
    let mut counter_share_list = vec![];
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

        // Coordinator aggregates parts of decrypted poll result.
        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum(
                &poll_parameters,
                &partially_decrypted_result,
                &mut aggregated_decrypted_result
            )
            .unwrap()
        );
        partially_decrypted_result_list.push(partially_decrypted_result);
        counter_share_list.push(counter_share);
    }
    println!(
        "Aggregated decrypted voting result is: \n{:?}",
        aggregated_decrypted_result
    );
    print_alert(
        "Notice: Individual votes cannot be recovered from aggregated \
         decrypted voting result.",
    );
    pause_en();

    println!(
        "{} {} {} \n",
        "[Demo progress] Apply for certified blank ballots ↦ Vote ↦ Verify \
         voting ↦ Count jointly ↦",
        "<<Verify counting>>".yellow(),
        "↦ Publish result ↦ Verify result",
    );

    println!(
        "Now verifying:\n1. All counters use the correct secret share to \
         count partially decrypted voting result.\n"
    );
    for index in 0..counter_secret_list.len() {
        println!(
            "Counter {}'s partially decrypted voting result: {}",
            index,
            if verifier::verify_count_request(
                &poll_parameters,
                &encrypted_vote_sum,
                &counter_share_list[index],
                &partially_decrypted_result_list[index],
            )
            .unwrap()
            {
                "✓"
            } else {
                "✗"
            }
        );
    }

    pause_en();

    println!(
        "{} {} {} \n",
        "[Demo progress] Apply for certified blank ballots ↦ Vote ↦ Verify \
         voting ↦ Count jointly ↦ Verify counting ↦",
        "<<Publish result>>".yellow(),
        "↦ Verify result",
    );

    let max_vote_limit = 20000;
    let vote_result = coordinator::finalize_vote_result(
        &poll_parameters,
        &encrypted_vote_sum,
        &aggregated_decrypted_result,
        max_vote_limit,
    )
    .unwrap();
    for result in vote_result.get_result() {
        if result.get_key() == POLL_RESULT_KEY_TOTAL_BALLOTS {
            continue;
        }
        println!("{}: total votes = {}", result.get_key(), result.get_value());
    }

    // TODO: Refactor to use a more elegant way for the following code.
    print_alert("\nCompare with traditional plaintext counting:");
    let plaintext_result1 = (candidate1_default
        + candidate1_default
        + candidate1_default
        + candidate1_votes) as i64;
    let plaintext_result2 = (candidate2_default
        + candidate2_default
        + candidate2_default
        + candidate2_votes) as i64;
    let plaintext_result3 = (candidate3_default
        + candidate3_default
        + candidate3_default
        + candidate3_votes) as i64;
    println!(
        "Kitten: {} + {} + {} + {} = {}",
        candidate1_default,
        candidate1_default,
        candidate1_default,
        candidate1_votes,
        plaintext_result1
    );
    println!(
        "Doge: {} + {} + {} + {} = {}",
        candidate2_default,
        candidate2_default,
        candidate2_default,
        candidate2_votes,
        plaintext_result2
    );
    println!(
        "Bunny: {} + {} + {} + {} = {}",
        candidate3_default,
        candidate3_default,
        candidate3_default,
        candidate3_votes,
        plaintext_result3
    );
    assert!(
        vote_result.get_result()[1].get_value() == plaintext_result1
            && vote_result.get_result()[2].get_value() == plaintext_result2
            && vote_result.get_result()[3].get_value() == plaintext_result3
    );
    print_alert(
        "\nNotice: ciphertext ballot counting yield the same result as \
         traditional plaintext counting.",
    );
    pause_en();

    println!(
        "{} {} \n",
        "[Demo progress] Apply for certified blank ballots ↦ Vote ↦ Verify \
         voting ↦ Count jointly ↦ Verify counting ↦ Publish result ↦",
        "<<Verify result>>".yellow(),
    );
    println!(
        "\nFinal voting result's validity: {}",
        if verifier::verify_vote_result(
            &poll_parameters,
            &encrypted_vote_sum,
            &aggregated_decrypted_result,
            &vote_result,
        )
        .unwrap()
        {
            "✓"
        } else {
            "✗"
        }
    );
    pause_en();

    print_alert("Thank you for your time!");
    println!(
        "\n{}\n\n{}\n",
        "Welcome to contact us for more information about WeDPR by the \
         following Email:",
        "wedpr@webank.com"
    );
    println!();
}

// Utility functions
// TODO: Extract those common functions to solution utility.
fn print_highlight(message: &str) {
    println!("{}", message.green());
}

fn print_highlight2(message1: &str, message2: &str) {
    println!("{}\n{}", message1.green(), message2.green());
}

fn print_alert(message: &str) {
    println!("{}", message.yellow());
}

fn print_alert2(message1: &str, message2: &str) {
    println!("{}\n{}", message1.yellow(), message2.yellow());
}

fn print_wide(message: &str) {
    println!("\n{}\n", message);
}

fn wait_for_input() -> String {
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line.");
    input.trim().to_string()
}

// In this demo, we set the upper limit of input value to 100.
const MAX_INPUT_VALUE: i32 = 100;

fn wait_for_number(error_message: &str) -> u32 {
    let mut input = wait_for_input();
    let mut input_num = input.parse::<i32>();
    loop {
        match input_num {
            // TODO: Enable negative input in the demo.
            Ok(v) if (v >= 0) && (v <= MAX_INPUT_VALUE) => return v as u32,
            _ => {
                print_alert(error_message);
                input = wait_for_input();
                input_num = input.parse::<i32>();
            },
        }
    }
}

fn wait_for_number_cn() -> u32 {
    wait_for_number("请输入有效数字：")
}

fn wait_for_number_en() -> u32 {
    wait_for_number("Please input a valid number:")
}

fn pause(info_message: &str) {
    let mut enter_continue = String::new();
    print_wide(info_message);
    std::io::stdin()
        .read_line(&mut enter_continue)
        .expect("read_line should not fail");
    println!("... {}\n", enter_continue.trim());
}

fn pause_cn() {
    pause("按任意键继续...");
}

fn pause_en() {
    pause("Press any key to continue...");
}
