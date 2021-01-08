// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Playground of VCL bounty targets.

use super::utils;
extern crate wedpr_s_verifiable_confidential_ledger;
use wedpr_s_verifiable_confidential_ledger::vcl;
extern crate wedpr_l_crypto_zkp_range_proof;

/// UI flow of VCL bounty playground.
pub fn flow_vcl() {
    utils::print_highlight(
        "\n##\n## Opening the gate of VCL bounty playground... ##\n##",
    );
    println!("{}\n", "List of available challenges:");
    utils::print_alert(
        "▶ Enter 1 to select proof of sum relationship: (default option)",
    );
    println!(
        "{}\n",
        "Given ciphertext A, B, C, without decrypting them, \nprove that \
         their corresponding plaintext values satisfying a + b = c or not."
    );
    utils::print_alert("▶ Enter 2 to select proof of product relationship:");
    println!(
        "{}\n",
        "Given ciphertext A, B, C, without decrypting them, \nprove that \
         their corresponding plaintext values satisfying a * b = c or not."
    );
    utils::print_alert("▶ Enter 3 to select proof of value range:");
    println!(
        "{}\n",
        "Given ciphertext A, without decrypting it, \nprove that its \
         corresponding plaintext values satisfying a in the range of [0, \
         2^32)."
    );
    println!();
    println!("Your choices: ▼▼▼");
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
            utils::print_alert("Invalid input! Please try again:");
            choice = utils::wait_for_input();
        }
    }
}

fn play_vcl_prove_sum_balance() {
    utils::print_highlight(
        "Loading the challenge for proof of sum relationship...",
    );
    utils::print_wide(
        "Challenge goals:\nFind malicious plaintext a, b, c, which lead \
         to:\n1) proof of sum relationship passed but a + b != c\n2) proof of \
         sum relationship failed but a + b == c",
    );

    utils::print_alert("Please enter a from [0, 2^64): ▼▼▼");
    let value1 = utils::wait_for_number_en();
    let (c1_credit, c1_secret) = vcl::make_credit(value1);

    utils::print_alert("Please enter b from [0, 2^64): ▼▼▼");
    let value2 = utils::wait_for_number_en();
    let (c2_credit, c2_secret) = vcl::make_credit(value2);

    utils::print_alert("Please enter c from [0, 2^64): ▼▼▼");
    let value3 = utils::wait_for_number_en();
    let (c3_credit, c3_secret) = vcl::make_credit(value3);

    println!("\nVerification result:");
    let sum_proof = vcl::prove_sum_balance(&c1_secret, &c2_secret, &c3_secret);
    let satisfy_sum_balance =
        vcl::verify_sum_balance(&c1_credit, &c2_credit, &c3_credit, &sum_proof)
            .unwrap();

    if satisfy_sum_balance {
        println!(
            "✓ Proof passed for your inputs: {} + {} == {}",
            value1, value2, value3,
        );
    } else {
        println!(
            "✗ Proof failed for your inputs: {} + {} != {}",
            value1, value2, value3,
        );
    }
    println!();
    if (value1 as u128 + value2 as u128 == value3 as u128
        && satisfy_sum_balance)
        || (value1 as u128 + value2 as u128 != value3 as u128
            && !satisfy_sum_balance)
    {
        utils::print_try_again();
    } else if (value1 as u128 + value2 as u128 != value3 as u128
        && satisfy_sum_balance)
        || (value1 as u128 + value2 as u128 == value3 as u128
            && !satisfy_sum_balance)
    {
        utils::print_alert(
            "Congratulation! You found malicious input breaking the algorithm.",
        );
        println!(
            "The found inputs: \na = {}\nb = {}\nc = {}\n",
            value1, value2, value3,
        );
    }
}

fn play_vcl_prove_product_balance() {
    utils::print_highlight(
        "Loading the challenge for proof of product relationship...",
    );
    utils::print_wide(
        "Challenge goals:\nFind malicious plaintext a, b, c, which lead \
         to:\n1) proof of product relationship passed but a * b != c\n2) \
         proof of product relationship failed but a * b == c",
    );

    utils::print_alert("Please enter a from [0, 2^64): ▼▼▼");
    let value1 = utils::wait_for_number_en();
    let (c1_credit, c1_secret) = vcl::make_credit(value1);

    utils::print_alert("Please enter b from [0, 2^64): ▼▼▼");
    let value2 = utils::wait_for_number_en();
    let (c2_credit, c2_secret) = vcl::make_credit(value2);

    utils::print_alert("Please enter c from [0, 2^64): ▼▼▼");
    let value3 = utils::wait_for_number_en();
    let (c3_credit, c3_secret) = vcl::make_credit(value3);

    println!("\nVerification result:");
    let product_proof =
        vcl::prove_product_balance(&c1_secret, &c2_secret, &c3_secret);
    let satisfy_product_balance = vcl::verify_product_balance(
        &c1_credit,
        &c2_credit,
        &c3_credit,
        &product_proof,
    )
    .unwrap();
    if satisfy_product_balance {
        println!(
            "✓ Proof passed for your inputs: {} * {} == {}",
            value1, value2, value3,
        );
    } else {
        println!(
            "✗ Proof failed for your inputs: {} * {} != {}",
            value1, value2, value3,
        );
    }

    if (value1 as u128 * value2 as u128 == value3 as u128
        && satisfy_product_balance)
        || (value1 as u128 * value2 as u128 != value3 as u128
            && !satisfy_product_balance)
    {
        utils::print_try_again();
    } else if (value1 as u128 * value2 as u128 != value3 as u128
        && satisfy_product_balance)
        || (value1 as u128 * value2 as u128 == value3 as u128
            && !satisfy_product_balance)
    {
        utils::print_alert(
            "Congratulation! You found malicious input breaking the algorithm.",
        );
        println!(
            "The found inputs: \na = {}\nb = {}\nc = {}\n",
            value1, value2, value3,
        );
    }
}

const RANGE_MAX: u64 = (u32::MAX) as u64;

fn play_zkp_verify_value_range() {
    utils::print_highlight("Loading the challenge for proof of value range...");
    utils::print_wide(
        "Challenge goals:\nFind malicious plaintext a, which leads to:\n1) \
         proof of value range passed but a is not in [0, 2^32)\n2) proof of \
         value range failed but a is in [0, 2^32)",
    );

    utils::print_alert("Please enter a from [0, 2^64): ▼▼▼");
    let input = utils::wait_for_number_en();
    let (proof_c1, c1_point, _) =
        wedpr_l_crypto_zkp_range_proof::prove_value_range(input);
    let within_range = wedpr_l_crypto_zkp_range_proof::verify_value_range(
        &c1_point, &proof_c1,
    );

    println!("\nVerification result:");
    if within_range && input <= RANGE_MAX {
        println!("✓ Proof passed for your inputs: {} in [0, 2^32)", input);
        utils::print_try_again();
    } else if !within_range && input > RANGE_MAX {
        println!("✗ Proof failed for your inputs: {} not in [0, 2^32)", input);
        utils::print_try_again();
    } else {
        utils::print_alert(
            "Congratulation! You found malicious input breaking the algorithm.",
        );
        println!("The found inputs: \na = {}\n", input);
    }
}

#[cfg(test)]
mod tests {
    extern crate wedpr_l_crypto_zkp_discrete_logarithm_proof;
    extern crate wedpr_l_crypto_zkp_utils;
    extern crate wedpr_l_utils;
    use wedpr_l_crypto_zkp_utils::{
        bytes_to_point, BASEPOINT_G1, BASEPOINT_G2,
    };
    extern crate wedpr_l_common_coder_base64;
    extern crate wedpr_l_crypto_zkp_range_proof;
    extern crate wedpr_l_protos;
    extern crate wedpr_s_verifiable_confidential_ledger;
    use crate::vcl_data::{
        TARGET_SIZE, VCL_C1_VEC, VCL_C2_VEC, VCL_C3_VEC, VCL_PROOF_VEC,
    };
    use protobuf::Message;
    use wedpr_l_common_coder_base64::WedprBase64;
    use wedpr_l_protos::generated::zkp::BalanceProof;
    use wedpr_l_utils::traits::Coder;

    #[test]
    fn test_vcl_bounty_data_validity() {
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;
        let base64 = WedprBase64::default();
        for i in 0..TARGET_SIZE {
            let c1_point =
                bytes_to_point(&base64.decode(&VCL_C1_VEC[i]).unwrap())
                    .expect("failed to decode point");
            let c2_point =
                bytes_to_point(&base64.decode(&VCL_C2_VEC[i]).unwrap())
                    .expect("failed to decode point");
            let c3_point =
                bytes_to_point(&base64.decode(&VCL_C3_VEC[i]).unwrap())
                    .expect("failed to decode point");

            let proof = <BalanceProof>::parse_from_bytes(
                &base64.decode(&VCL_PROOF_VEC[i]).unwrap(),
            )
            .expect("failed to parse proof PB");

            assert!(wedpr_l_crypto_zkp_discrete_logarithm_proof::verify_sum_relationship(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            ).unwrap());
        }
    }
}
