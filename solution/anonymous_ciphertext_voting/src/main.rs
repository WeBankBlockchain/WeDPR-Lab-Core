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

fn flow_en() {
    // TODO: en flow
}

fn flow_cn() {
    print_wide(
        "投票demo流程中，你将体验如何通过明文数据生成投票密文， \
         并了解投票密文如何解密获取最终结果的过程",
    );

    print_wide("本示例中，您将与三个投票者，共同为三位候选人进行投票");

    println!(
        "{} {} {}\n",
        "【演示进度】",
        "<<申请空白选票>>".yellow(),
        "↦ 生成密文选票 ↦ 聚合密文选票 ↦ 联合解密选票 ↦ 公布计票结果",
    );

    print_alert(
        "现在请输入空白选票的投票数额：\
         ▼▼（空白选票为投票者可以为所有候选人分配的票数总和））",
    );
    print_highlight(
        "在这个demo中，我们暂定投票上限为100（真实业务可按需扩展），\
         请输入0到100之间的整数",
    );
    let value1 = wait_for_number_cn();

    let max_vote_number = 20000;
    let (public_key, secret_key) = SIGNATURE_SECP256K1.generate_keypair();
    let mut candidate_list = CandidateList::new();
    // Init candidate list
    for candidate in vec!["小明", "小王", "小张"] {
        candidate_list.mut_candidate().push(candidate.to_string());
    }
    let counter_id_list = vec!["1001", "1002", "1003"];
    let mut blank_ballot_count = vec![100, 100, 100];
    blank_ballot_count.push(value1 as u32);
    println!("候选人分别为：{:?}", vec!["小明", "小王", "小张"]);

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
    println!("您的空白选票为：{:?}", response_list[3].get_ballot());

    println!(
        "{} {} {}\n",
        "【演示进度】申请空白选票 ↦ ",
        "<<生成密文选票>> ".yellow(),
        "↦ 聚合密文选票 ↦ 联合解密选票 ↦ 公布计票结果",
    );
    print_alert("现在请输入您对候选人：【小明】的投票数额：▼▼");
    let value2 = wait_for_number_cn();
    print_alert("现在请输入您对候选人：【小王】的投票数额：▼▼");
    let value3 = wait_for_number_cn();
    print_alert("现在请输入您对候选人：【小张】的投票数额：▼▼");
    let value4 = wait_for_number_cn();
    print_alert("注：当总数额大于空白选票数额时将会导致投票失败");

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
        vec![vec![10, 20, 30], vec![10, 20, 30], vec![10, 20, 30], vec![
            value2, value3, value4,
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
    println!("您的密文选票为：{:?}", vote_request_list[3].get_vote());
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】申请空白选票 ↦ 生成密文选票 ↦ ",
        "<<聚合密文选票>> ".yellow(),
        "↦ 联合解密选票 ↦ 公布计票结果",
    );

    println!("所有投票者聚合后的密文选票为：{:?}", encrypted_vote_sum);
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】申请空白选票 ↦ 生成密文选票 ↦ 聚合密文选票 ↦ ",
        "<<联合解密选票>> ".yellow(),
        "↦ 公布计票结果",
    );

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
            counter_parameters_storage.get_counter_parameters_request()[index]
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
    println!("所有计票者联合解密投票结果为：{:?}", vote_sum_total);
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】申请空白选票 ↦ 生成密文选票 ↦ 聚合密文选票 ↦ \
         联合解密选票 ↦ ",
        "<<公布计票结果>> ".yellow(),
        "",
    );

    let final_result_request = coordinator::finalize_vote_result(
        &system_parameters,
        &encrypted_vote_sum,
        &vote_sum_total,
        max_vote_number,
    )
    .unwrap();
    println!("另外三位投票者对候选人的投票分别均为10，20，30");
    for f_result in final_result_request.get_result() {
        println!(
            "候选人：{}, 最终得票{}",
            f_result.get_key(),
            f_result.get_value()
        )
    }
    let result = verifier::verify_vote_result(
        &system_parameters,
        &encrypted_vote_sum,
        &vote_sum_total,
        &final_result_request,
    )
    .unwrap();
    assert!(result);

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
