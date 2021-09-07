// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Minimalist demo of anonymous ciphertext voting.

use wedpr_l_crypto_zkp_utils::bytes_to_point;
use wedpr_l_utils::traits::Signature;

use wedpr_s_protos::generated::acv::{
    CandidateList, CounterSecret, CounterSystemParametersStorage,
    DecryptedResultPartStorage, VoteChoice, VoteChoices, VoteStorage,
    VoterSecret,
};

extern crate wedpr_s_anonymous_ciphertext_voting;
use colored::Colorize;
use wedpr_s_anonymous_ciphertext_voting::{
    config::SIGNATURE_SECP256K1, coordinator, counter, verifier, voter,
};

fn main() {
    print_highlight2(
        "#\n# Welcome to anonymous ciphertext voting (ACV) demo!",
        "# 欢迎来到匿名密文投票demo演示!\n#",
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
        "投票demo流程中，你将体验隐匿密文投票的全过程，具体包括：\n
        1. 投票者如何使用密文选票进行匿名投票；\n
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
        "1. 投票者获得初始选票；",
        "2. 投票者决定为各候选人分别投出多少数额，\
         生成并公布对应的密文选票和零知识证明；",
        "3. 任意验证者验证投票者公布的密文选票是否正确有效；",
        "4. 计票者联合计算每个候选人的得票，公布统计结果和零知识证明；",
        "5. 任意验证者验证计票者的计票过程及计票结果是否正确有效。"
    );
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】",
        "<<生成并公布初始密文选票>>".yellow(),
        "↦ 生成并公布对各候选人的密文选票 ↦ 验证密文选票 ↦ \
         联合计票并公布计票信息↦ 验证计票过程 ↦ 公布计票结果 ↦ 验证计票结果",
    );

    print_alert(
        "现在请输入初始选票的数额：▼▼（初始选票的数额表示：\
         该投票者可以投出的密文选票总额上限）",
    );
    print_highlight(
        "在这个demo中，我们暂定初始选票数额上限为100（真实业务可按需扩展），\
         请输入0到100之间的整数",
    );
    let value1 = wait_for_number_cn();

    let max_vote_number = 20000;
    let (public_key, secret_key) = SIGNATURE_SECP256K1.generate_keypair();
    let mut candidate_list = CandidateList::new();
    // Init candidate list
    for candidate in vec!["候选人1", "候选人2", "候选人3"] {
        candidate_list.mut_candidate().push(candidate.to_string());
    }
    let counter_id_list = vec!["1001", "1002", "1003"];
    let mut blank_ballot_count = vec![100, 100, 100];
    blank_ballot_count.push(value1 as u32);

    let mut counter_secret_list: Vec<CounterSecret> = vec![];
    let mut counter_parameters_storage =
        CounterSystemParametersStorage::default();
    // Counter init
    for id in counter_id_list.clone() {
        let share_secret = counter::make_counter_secret();
        counter_secret_list.push(share_secret.clone());
        let counter_parameters_request =
            counter::make_system_parameters_share(id, &share_secret).unwrap();
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
        let vote_request =
            voter::make_registration_request(&vote_secret, &system_parameters)
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
    println!(
        "您的初始密文选票为：\n{:?}\n",
        response_list[3].get_ballot()
    );
    print_alert(
        "可以看到，投票者公布的初始密文选票中不包含投票者的身份及其初始数额。",
    );
    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】生成并公布初始密文选票 ↦",
        "<<生成并公布对各候选人的密文选票>>".yellow(),
        "↦ 验证密文选票 ↦ 联合计票并公布计票信息↦ 验证计票过程 ↦ 公布计票结果 \
         ↦ 验证计票结果",
    );

    print_alert("现在请输入您对候选人1的投票数额：▼▼");
    let value2 = wait_for_number_cn();
    print_alert("现在请输入您对候选人2的投票数额：▼▼");
    let value3 = wait_for_number_cn();
    print_alert("现在请输入您对候选人3的投票数额：▼▼");
    print_highlight(
        "（注：当投出的总数额大于初始选票数值时，会导致投票失败）。",
    );
    let value4 = wait_for_number_cn();

    // Voter votes.
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
    let candidate1_default = 10;
    let candidate2_default = 20;
    let candidate3_default = 30;
    let voting_ballot_count: Vec<Vec<u32>> = vec![
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![candidate1_default, candidate2_default, candidate3_default],
        vec![value2, value3, value4],
    ];

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
        coordinator::aggregate_vote_sum_response(
            &system_parameters,
            &vote_request.get_vote(),
            &mut encrypted_vote_sum,
        )
        .unwrap();
        vote_request_list.push(vote_request);
    }
    println!(
        "\n您公布的密文选票为：\n{:?}\n",
        vote_request_list[3].get_vote()
    );
    print_alert(
        "可以看到：投票者公布的密文选票中不包含投票者身份、候选人身份、\
         投票数额等信息。",
    );
    println!("假定其他投票者对三位候选人的投票均为[10，20，30]。");
    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 生成并公布初始密文选票 ↦ 生成并公布对各候选人的密文选票 \
         ↦",
        "验证密文选票".yellow(),
        "↦ 联合计票并公布计票信息↦ 验证计票过程 ↦ 公布计票结果 ↦ 验证计票结果",
    );

    println!(
        "验证内容包括：\n1. 投给每个候选人的密文选票数额非负；\n2. \
         每个密文选票格式正确（否则会导致后续计票失败）；\n3. \
         投票者投出的密文选票数额之和小于等于其初始选票数额。"
    );

    print_alert("\n只有通过验证的密文选票，才会进入后续计票流程。");
    pause_cn();

    // Verifier verifies voters.
    let length = vote_request_list.len().clone();
    for index in 0..length {
        let verify_voter = verifier::verify_vote_request(
            &system_parameters,
            &vote_request_list[index],
            &public_key,
        )
        .unwrap();
        println!("\n对投票者{}的验证结果为：{:?}", index, verify_voter);
    }
    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 生成并公布初始密文选票 ↦ 生成并公布对各候选人的密文选票 \
         ↦ 验证密文选票 ↦",
        "联合计票并公布计票信息".yellow(),
        "↦ 验证计票过程 ↦ 公布计票结果 ↦ 验证计票结果",
    );

    // Counters count.
    let mut vote_sum_total = DecryptedResultPartStorage::new();
    let mut decrypt_request_list = vec![];
    let mut share_list = vec![];
    let length = counter_secret_list.len().clone();
    for index in 0..length {
        let decrypt_request = counter::count(
            &counter_id_list[index],
            &counter_secret_list[index],
            &encrypted_vote_sum,
        )
        .unwrap();
        let share = bytes_to_point(
            counter_parameters_storage.get_counter_parameters_request()[index]
                .get_poll_point_share(),
        )
        .unwrap();
        assert_eq!(
            true,
            coordinator::aggregate_decrypted_part_sum(
                &system_parameters,
                &decrypt_request,
                &mut vote_sum_total
            )
            .unwrap()
        );
        decrypt_request_list.push(decrypt_request);
        share_list.push(share);
    }
    println!("所有计票者联合计票的计票信息为：\n{:?}", vote_sum_total);
    print_alert(
        "可以看到：计票者公布的计票信息中不包含计票者身份等计票者隐私信息。",
    );
    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 生成并公布初始密文选票 ↦ 生成并公布对各候选人的密文选票 \
         ↦ 验证密文选票 ↦ 联合计票并公布计票信息 ↦",
        "验证计票过程".yellow(),
        "↦ 公布计票结果 ↦ 验证计票结果",
    );

    println!(
        "验证计票过程，是指：\n
         验证计票者公布的计票信息是使用正确的计票者密钥计算而得，\
         而不是随意构造而得。"
    );
    let length = counter_secret_list.len().clone();
    for index in 0..length {
        let verify_counter = verifier::verify_count_request(
            &system_parameters,
            &encrypted_vote_sum,
            &share_list[index],
            &decrypt_request_list[index],
        )
        .unwrap();
        println!("\n对计票者{}的验证结果为：{:?}", index, verify_counter);
    }

    pause_cn();

    println!(
        "{} {} {} \n",
        "【演示进度】 生成并公布初始密文选票 ↦ 生成并公布对各候选人的密文选票 \
         ↦ 验证密文选票 ↦ 联合计票并公布计票信息 ↦ 验证计票过程 ↦",
        "公布计票结果".yellow(),
        "↦ 验证计票结果",
    );

    let final_result_request = coordinator::finalize_vote_result(
        &system_parameters,
        &encrypted_vote_sum,
        &vote_sum_total,
        max_vote_number,
    )
    .unwrap();

    println!(
        "{}： 最终得票为{}。",
        final_result_request.get_result()[1].get_key(),
        final_result_request.get_result()[1].get_value()
    );
    println!(
        "{}： 最终得票为{}。",
        final_result_request.get_result()[2].get_key(),
        final_result_request.get_result()[2].get_value()
    );
    println!(
        "{}： 最终得票为{}。",
        final_result_request.get_result()[3].get_key(),
        final_result_request.get_result()[3].get_value()
    );

    print_alert("\n对比明文统计结果：");
    let plaintext_result1 =
        (candidate1_default + candidate1_default + candidate1_default + value2).into();
    let plaintext_result2 =
        (candidate2_default + candidate2_default + candidate2_default + value3).into();
    let plaintext_result3 =
        (candidate3_default + candidate3_default + candidate3_default + value4).into();
    println!(
        "候选人1得票：{} + {} + {} + {} = {}",
        candidate1_default,
        candidate1_default,
        candidate1_default,
        value2,
        plaintext_result1
    );
    println!(
        "候选人2得票：{} + {} + {} + {} = {}",
        candidate2_default,
        candidate2_default,
        candidate2_default,
        value3,
        plaintext_result2
    );
    println!(
        "候选人3得票：{} + {} + {} + {} = {}",
        candidate3_default,
        candidate3_default,
        candidate3_default,
        value4,
        plaintext_result3
    );
    if final_result_request.get_result()[1].get_value() == plaintext_result1
        && final_result_request.get_result()[2].get_value() == plaintext_result2
        && final_result_request.get_result()[3].get_value() == plaintext_result3
    {
        print_alert("\n可以看到，密文选票的计票结果与明文计算结果一致。");
    }

    pause_cn();

    println!(
        "{} {} \n",
        "【演示进度】 生成并公布初始密文选票 ↦ 生成并公布对各候选人的密文选票 \
         ↦ 验证密文选票 ↦ 联合计票并公布计票信息 ↦ 验证计票过程 ↦ \
         公布计票结果 ↦",
        "验证计票结果".yellow(),
    );

    let verify_result = verifier::verify_vote_result(
        &system_parameters,
        &encrypted_vote_sum,
        &vote_sum_total,
        &final_result_request,
    )
    .unwrap();

    println!("\n验证结果为：{:?}", verify_result);
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
    // TODO: en flow
}

// Utility functions
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

// In this demo, we set the upper limit of input value to 10000.
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
