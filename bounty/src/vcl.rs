// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Playground of VCL bounty targets.

use super::utils;
use verifiable_confidential_ledger::vcl;
extern crate wedpr_crypto;
use wedpr_crypto::zkp;

pub fn flow_vcl() {
    utils::print_highlight("## 欢迎来到VCL零知识证明靶场! ##");
    println!("{}\n", "在此，我们提供了3个待挑战零知识证明，分别为：");
    utils::print_alert("▶ 1. 加和证明的效果:");
    println!(
        "{}\n",
        "给定密文A, B, C，在不解密的前提下，验证密文A, B, \
         C对应的明文是否满足加和关系a + b =? c。"
    );
    utils::print_alert("▶ 2. 乘积证明的效果：");
    println!(
        "{}\n",
        "给定密文A, B, C，在不解密的前提下，验证密文A, B, \
         C对应的明文是否满足加和关系a * b =? c。"
    );
    utils::print_alert("▶ 3. 范围证明的效果：");
    println!(
        "{}\n",
        "给定密文A，在不解密A的前提下，验证密文A对应的明文是否满足a属于[0, \
         2^32)区间。"
    );
    println!();
    println!("现在请选择待挑战的零知识证明编号：▼▼▼");
    utils::print_alert3(
        "▶ 输入 \"1\" 选择加和证明（默认选项）",
        "▶ 输入 \"2\" 选择乘积证明",
        "▶ 输入 \"3\" 选择范围证明",
    );
    let mut choice = utils::wait_for_input();
    loop {
        if choice == "1" || choice.is_empty() {
            play_vcl_prove_sum_balance();
            break;
        } else if choice == "2" {
            play_vcl_prove_product_balance();
            break;
        } else if choice == "3" {
            play_zkp_verify_value_range();
            break;
        } else {
            utils::print_alert("输入错误！请重新输入：");
            choice = utils::wait_for_input();
        }
    }
}

pub fn play_vcl_prove_sum_balance() {
    utils::print_highlight("加和证明靶场 载入中 。。。");
    utils::print_wide(
        "漏洞目标：找到一组数值输入a，b，c，满足a + b != \
         c，但通过了加和证明；或者a + b == c，但未通过加和证明。",
    );

    utils::print_alert("现在请输入第一个明文数据a：▼▼▼");
    utils::print_highlight("加和证明的输入范围为：[0, 2^64)。");
    let value1 = utils::wait_for_number_cn();
    let (c1_credit, c1_secret) = vcl::make_credit(value1);

    utils::print_alert("现在请输入第二个明文数据b：▼▼▼");
    let value2 = utils::wait_for_number_cn();
    let (c2_credit, c2_secret) = vcl::make_credit(value2);

    utils::print_alert("现在请输入第三个明文数据c：▼▼▼");
    let value3 = utils::wait_for_number_cn();
    let (c3_credit, c3_secret) = vcl::make_credit(value3);

    println!("\n加和证明的验证结果为：");
    let sum_proof = vcl::prove_sum_balance(&c1_secret, &c2_secret, &c3_secret);
    let satisfy_sum_balance =
        vcl::verify_sum_balance(&c1_credit, &c2_credit, &c3_credit, &sum_proof);

    if satisfy_sum_balance {
        println!(
            "✓ 您的输入：{} + {} = {}，所以通过加和验证。",
            value1, value2, value3,
        );
        utils::print_wide("您的输入对应的验证结果符合预期。");
    } else {
        println!(
            "X 您的输入：{} + {} != {}，所以未通过加和验证。",
            value1, value2, value3,
        );
        utils::print_wide("您的输入对应的验证结果符合预期。");
    }
    println!();
    if (value1 as u128 + value2 as u128 == value3 as u128
        && satisfy_sum_balance)
        || (value1 as u128 + value2 as u128 != value3 as u128
            && !satisfy_sum_balance)
    {
        utils::print_alert("您未能找到漏洞输入，再试一次？");
    } else if (value1 as u128 + value2 as u128 != value3 as u128
        && satisfy_sum_balance)
        || (value1 as u128 + value2 as u128 == value3 as u128
            && !satisfy_sum_balance)
    {
        utils::print_alert("恭喜您，找到了加和零知识证明的漏洞输入！");
        println!(
            "您找到的漏洞输入为：\na = {}\nb = {}\nc = {}\n",
            value1, value2, value3,
        );
    }
}

pub fn play_vcl_prove_product_balance() {
    utils::print_highlight("乘积证明靶场 载入中 。。。");
    utils::print_wide(
        "漏洞目标：找到一组数值输入a，b，c，满足a * b != \
         c，但通过了乘积证明；或者a * b == c，但未通过乘积证明。",
    );

    utils::print_alert("现在请输入第一个明文数据a：▼▼▼");
    utils::print_highlight("乘积证明的输入范围为：[0, 2^64)。");
    let value1 = utils::wait_for_number_cn();
    let (c1_credit, c1_secret) = vcl::make_credit(value1);

    utils::print_alert("现在请输入第二个明文数据b：▼▼▼");
    let value2 = utils::wait_for_number_cn();
    let (c2_credit, c2_secret) = vcl::make_credit(value2);

    utils::print_alert("现在请输入第三个明文数据c：▼▼▼");
    let value3 = utils::wait_for_number_cn();
    let (c3_credit, c3_secret) = vcl::make_credit(value3);

    println!("\n乘积证明的验证结果为：");
    let product_proof =
        vcl::prove_product_balance(&c1_secret, &c2_secret, &c3_secret);
    let satisfy_product_balance = vcl::verify_product_balance(
        &c1_credit,
        &c2_credit,
        &c3_credit,
        &product_proof,
    );
    if satisfy_product_balance {
        println!(
            "✓ 您的输入：{} * {} = {}，所以通过乘积验证。",
            value1, value2, value3,
        );
        utils::print_wide("您的输入对应的验证结果符合预期。");
    } else {
        println!(
            "X 您的输入：{} * {} != {}，所以未通过乘积验证。",
            value1, value2, value3,
        );
        utils::print_wide("您的输入对应的验证结果符合预期。");
    }

    if (value1 as u128 * value2 as u128 == value3 as u128
        && satisfy_product_balance)
        || (value1 as u128 * value2 as u128 != value3 as u128
            && !satisfy_product_balance)
    {
        utils::print_alert("您未能找到漏洞输入，再试一次？");
    } else if (value1 as u128 * value2 as u128 != value3 as u128
        && satisfy_product_balance)
        || (value1 as u128 * value2 as u128 == value3 as u128
            && !satisfy_product_balance)
    {
        utils::print_alert("恭喜您，找到了乘积零知识证明的漏洞输入！");
        println!(
            "您找到的漏洞输入为：\na = {}\nb = {}\nc = {}\n",
            value1, value2, value3,
        );
    }
}

const RANGE_MAX: u64 = (u32::MAX) as u64;

pub fn play_zkp_verify_value_range() {
    utils::print_highlight("范围证明靶场 载入中 。。。");
    utils::print_wide(
        "漏洞目标：找到一个数值输入a，满足a不在[0, \
         2^32)，但通过了范围证明；或者a在[0, 2^32),但未通过范围证明。",
    );

    utils::print_alert("现在请输入明文数据a：▼▼▼");
    utils::print_highlight("明文数据输入范围为：[0, 2^64)。");
    let input = utils::wait_for_number_cn();
    let (proof_c1, c1_point, _) = zkp::prove_value_range(input);
    let within_range = zkp::verify_value_range(&c1_point, &proof_c1);

    println!("\n范围证明验证结果为：");
    if within_range && input <= RANGE_MAX {
        println!(
            "✓ 您的输入：{} 属于[0, 2^32)区间，所以通过范围验证。",
            input
        );
        utils::print_wide("您的输入对应的验证结果符合预期。");
        utils::print_alert("您未能找到漏洞输入，再试一次？");
    } else if !within_range && input > RANGE_MAX {
        println!(
            "X 您的输入：{} 不属于[0, 2^32)区间，所以未通过范围验证。",
            input
        );
        utils::print_wide("您的输入对应的验证结果符合预期。");
        utils::print_alert("您未能找到漏洞输入，再试一次？");
    } else {
        utils::print_alert("恭喜您，找到了乘积零知识证明的漏洞输入！");
        println!("您找到的漏洞输入为：\na = {}\n", input);
    }
}

#[cfg(test)]
mod tests {
    use super::{wedpr_crypto::utils::string_to_bytes, *};
    use crate::vcl_data::{
        TARGET_SIZE, VCL_C1_VEC, VCL_C2_VEC, VCL_C3_VEC, VCL_PROOF_VEC,
    };
    use wedpr_crypto::{
        constant::{BASEPOINT_G1, BASEPOINT_G2},
        utils::string_to_point,
    };
    use wedpr_protos::generated::zkp::BalanceProof;

    #[test]
    fn test_bounty_data_validity() {
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        for i in 0..TARGET_SIZE {
            let c1_point =
                string_to_point(VCL_C1_VEC[i]).expect("failed to decode point");
            let c2_point =
                string_to_point(VCL_C2_VEC[i]).expect("failed to decode point");
            let c3_point =
                string_to_point(VCL_C3_VEC[i]).expect("failed to decode point");
            let proof = protobuf::parse_from_bytes::<BalanceProof>(
                &string_to_bytes(VCL_PROOF_VEC[i])
                    .expect("failed to decode proof"),
            )
            .expect("failed to parse proof PB");

            assert!(zkp::verify_sum_relationship(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            ));
        }
    }
}
