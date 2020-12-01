// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.
#![allow(deprecated)]
use super::bounty_utils;
use verifiable_confidential_ledger::vcl;
extern crate wedpr_crypto;
use wedpr_crypto::zkp;

pub fn flow_vcl() {
    bounty_utils::print_highlight("## 欢迎来到VCL零知识证明靶场! ##");
    println!("{}\n", "在此，我们提供了3个待挑战零知识证明，分别为：");
    bounty_utils::print_alert("▶ 1. 加和证明:");
    println!(
        "{}\n",
        "给定密文A, B, C，在不解密的前提下，验证密文A, B, \
         C对应的明文是否满足加和关系a + b =? c。"
    );
    bounty_utils::print_alert("▶ 2. 乘积证明：");
    println!(
        "{}\n",
        "给定密文A, B, C，在不解密的前提下，验证密文A, B, \
         C对应的明文是否满足加和关系a * b =? c。"
    );
    bounty_utils::print_alert("▶ 3. 范围证明：");
    println!(
        "{}\n",
        "给定密文A，在不解密A的前提下，验证密文A对应的明文是否满足a属于[0, \
         2^32)区间。"
    );
    println!();
    println!("现在请选择待挑战的零知识证明编号：▼▼▼");
    bounty_utils::print_alert3(
        "▶ 输入 \"1\" 选择加和证明。",
        "▶ 输入 \"2\" 选择乘积证明。",
        "▶ 输入 \"3\" 选择范围证明。",
    );
    let mut choice = bounty_utils::wait_for_input();
    loop {
        if choice == "1" || choice.is_empty() {
            flow_sum();
            break;
        } else if choice == "2" {
            flow_product();
            break;
        } else if choice == "3" {
            flow_range();
            break;
        } else {
            bounty_utils::print_alert("输入错误！请重新输入：");
            choice = bounty_utils::wait_for_input();
        }
    }
}

pub fn flow_sum() {
    bounty_utils::print_alert("现在请输入第一个明文数据a：▼▼▼");
    bounty_utils::print_highlight("加和证明的输入范围为：[0, 2^64]。");
    let value1 = bounty_utils::wait_for_number_cn();
    let (c1_credit, c1_secret) = vcl::make_credit(value1);

    bounty_utils::print_alert("现在请输入第二个明文数据b：▼▼▼");
    let value2 = bounty_utils::wait_for_number_cn();
    let (c2_credit, c2_secret) = vcl::make_credit(value2);

    bounty_utils::print_alert("现在请输入第三个明文数据c：▼▼▼");
    let value3 = bounty_utils::wait_for_number_cn();
    let (c3_credit, c3_secret) = vcl::make_credit(value3);

    println!();
    bounty_utils::print_alert("加和证明的验证结果为：");
    let sum_proof = vcl::prove_sum_balance(&c1_secret, &c2_secret, &c3_secret);
    let meet_sum_balance =
        vcl::verify_sum_balance(&c1_credit, &c2_credit, &c3_credit, &sum_proof);

    if meet_sum_balance {
        println!(
            "✓ 您的输入：{} + {} = {}，所以通过加和验证。",
            value1, value2, value3,
        );
        bounty_utils::print_highlight("您的输入对应的验证结果符合预期。");
    } else {
        println!(
            "X 您的输入：{} + {} != {}，所以未通过加和验证。",
            value1, value2, value3,
        );
        bounty_utils::print_highlight("您的输入对应的验证结果符合预期。");
    }
    println!();
    if (value1 as u128 + value2 as u128 == value3 as u128
        && meet_sum_balance == true)
        || (value1 as u128 + value2 as u128 != value3 as u128
            && meet_sum_balance == false)
    {
        bounty_utils::print_highlight("别灰心，再试一次。");
    } else if (value1 as u128 + value2 as u128 != value3 as u128
        && meet_sum_balance == true)
        || (value1 as u128 + value2 as u128 == value3 as u128
            && meet_sum_balance == false)
    {
        bounty_utils::print_highlight(
            "恭喜您，找到了加和零知识证明的漏洞输入！",
        );
        println!(
            "您找到的漏洞输入为：\na = {}\nb = {}\nc = {}\n",
            value1, value2, value3,
        );
    }
}

pub fn flow_product() {
    bounty_utils::print_alert("现在请输入第一个明文数据a：▼▼▼");
    bounty_utils::print_highlight("乘积证明的输入范围为：[0, 2^64]。");
    let value1 = bounty_utils::wait_for_number_cn();
    let (c1_credit, c1_secret) = vcl::make_credit(value1);

    bounty_utils::print_alert("现在请输入第二个明文数据b：▼▼▼");
    let value2 = bounty_utils::wait_for_number_cn();
    let (c2_credit, c2_secret) = vcl::make_credit(value2);

    bounty_utils::print_alert("现在请输入第三个明文数据c：▼▼▼");
    let value3 = bounty_utils::wait_for_number_cn();
    let (c3_credit, c3_secret) = vcl::make_credit(value3);
    println!();
    bounty_utils::print_alert("乘积证明的验证结果为：");
    let product_proof =
        vcl::prove_product_balance(&c1_secret, &c2_secret, &c3_secret);
    let meet_product_balance = vcl::verify_product_balance(
        &c1_credit,
        &c2_credit,
        &c3_credit,
        &product_proof,
    );
    if meet_product_balance {
        println!(
            "✓ 您的输入：{} * {} = {}，所以通过乘积验证。",
            value1, value2, value3,
        );
        bounty_utils::print_highlight("您的输入对应的验证结果符合预期。");
    } else {
        println!(
            "X 您的输入：{} * {} != {}，所以未通过乘积验证。",
            value1, value2, value3,
        );
        bounty_utils::print_highlight("您的输入对应的验证结果符合预期。");
    }

    if (value1 as u128 * value2 as u128 == value3 as u128
        && meet_product_balance == true)
        || (value1 as u128 * value2 as u128 != value3 as u128
            && meet_product_balance == false)
    {
        bounty_utils::print_highlight("别灰心，再试一次。");
    } else if (value1 as u128 * value2 as u128 != value3 as u128
        && meet_product_balance == true)
        || (value1 as u128 * value2 as u128 == value3 as u128
            && meet_product_balance == false)
    {
        bounty_utils::print_highlight(
            "恭喜您，找到了乘积零知识证明的漏洞输入！",
        );
        println!(
            "您找到的漏洞输入为：\na = {}\nb = {}\nc = {}\n",
            value1, value2, value3,
        );
    }
}
const MAX_INPUT_VALUE: u64 = (u32::MAX) as u64;
pub fn flow_range() {
    bounty_utils::print_alert("现在请输入明文数据a：▼▼▼");
    bounty_utils::print_highlight("明文数据输入范围为：[0, 2^64]。");
    let value1 = bounty_utils::wait_for_number_cn();
    let (proof_c1, c1_point, _) = zkp::prove_value_range(value1);
    let meet_range = zkp::verify_value_range(&c1_point, &proof_c1);
    println!();
    bounty_utils::print_alert("范围证明验证结果为：");
    if meet_range {
        println!("✓ 您的输入：{}属于[0,2^32)区间，所以通过范围验证。", value1,);
        bounty_utils::print_highlight("您的输入对应的验证结果符合预期。");
        bounty_utils::print_highlight("别灰心，再试一次。");
    } else {
        println!(
            "X 您的输入：{}不属于[0,2^32)区间，所以未通过范围验证。",
            value1,
        );
        bounty_utils::print_highlight("您的输入对应的验证结果符合预期。");
        bounty_utils::print_highlight("别灰心，再试一次。");
    }

    if value1 > MAX_INPUT_VALUE && meet_range == true {
        bounty_utils::print_highlight(
            "恭喜您，找到了乘积零知识证明的漏洞输入！",
        );
        println!("您找到的漏洞输入为：\na = {}\n", value1);
    }
}

#[cfg(test)]
mod tests {
    use super::{wedpr_crypto::utils::string_to_bytes, *};
    use crate::vcl_data::{VCL_C1_VEC, VCL_C2_VEC, VCL_C3_VEC, VCL_PROOF_VEC};
    use wedpr_crypto::{
        constant::{BASEPOINT_G1, BASEPOINT_G2},
        utils::string_to_point,
    };
    use wedpr_protos::generated::zkp::BalanceProof;

    #[test]
    fn test_bounty() {
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        for i in 0..100 {
            let c1_point =
                string_to_point(VCL_C1_VEC[i]).expect("secret bounty point");
            let c2_point =
                string_to_point(VCL_C2_VEC[i]).expect("secret bounty point");
            let c3_point =
                string_to_point(VCL_C3_VEC[i]).expect("secret bounty point");
            let proof = protobuf::parse_from_bytes::<BalanceProof>(
                &string_to_bytes(VCL_PROOF_VEC[i]).expect("decode bytes"),
            )
            .expect("decode proto");
            assert_eq!(
                true,
                zkp::verify_sum_relationship(
                    &c1_point,
                    &c2_point,
                    &c3_point,
                    &proof,
                    &value_basepoint,
                    &blinding_basepoint
                )
            );
        }
    }
}
