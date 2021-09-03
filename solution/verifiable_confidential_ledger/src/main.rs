// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Minimalist demo of verifiable confidential ledger.

use colored::*;
use protobuf::Message;
use std;
use wedpr_l_crypto_zkp_utils::point_to_bytes;
use wedpr_s_verifiable_confidential_ledger::vcl;

fn main() {
    print_highlight2(
        "#\n# Welcome to verifiable confidential ledger (VCL) demo!",
        "# 欢迎来到公开可验证密文账本demo演示!\n#",
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
    print_wide("账本demo流程中，你将体验如何通过账本金额的明文数据生成对应的密文凭证， \
        并了解密文凭证配套零知识证明的基础用法");

    println!(
        "{} {} {}\n",
        "【演示进度】",
        "<<开具密文凭证>>".yellow(),
        "↦ 生成凭证的约束关系证明 ↦ 验证凭证的约束关系证明",
    );

    print_alert("现在请输入第一个待转换成密文凭证c1的账本金额：▼▼▼");
    print_highlight(
        "在这个demo中，我们暂定金额上限为10000（真实业务可按需扩展），\
         请输入0到10000之间的整数",
    );

    let value1 = wait_for_number_cn();
    let (c1_credit, c1_secret) = vcl::make_credit(value1);
    println!("\n{}", "关于c1的完整密文凭证共包含以下两部分".green());
    println!(" ▶ 公开部分：可公开验证的密文凭证\n{}", &c1_credit);
    println!(
        " ▶ 私有部分：用于生成以上的密文凭证的秘密参数，\
         代表了对应账本金额的所有权\n{}",
        c1_secret
    );
    print_wide(
        "为了简化描述，我们使用“密文凭证”指代公开部分；对于私有部分，\
         用户应妥善保存，保护其对凭证的所有权",
    );

    print_alert("现在请输入第二个待转换成密文凭证c2的账本金额：▼▼▼");
    let value2 = wait_for_number_cn();
    let (c2_credit, c2_secret) = vcl::make_credit(value2);

    print_alert("请输入第三个待转换成密文凭证c3的账本金额：▼▼▼");
    let value3 = wait_for_number_cn();
    let (c3_credit, c3_secret) = vcl::make_credit(value3);

    print_wide("至此，我们一共生成了如下一系列公开可验证的密文凭证");
    println!("c1：{:?}", point_to_bytes(&c1_credit.get_point()));
    println!("c2：{:?}", point_to_bytes(&c2_credit.get_point()));
    println!("c3：{:?}", point_to_bytes(&c3_credit.get_point()));
    pause_cn();

    println!(
        "\n{} {} {}\n",
        "【演示进度】开具密文凭证 ↦ ",
        "<<生成凭证的约束关系证明>> ".yellow(),
        "↦ 验证凭证的约束关系证明",
    );

    print_highlight("以下将演示这些密文凭证的基础用法：");
    print_highlight(
        "证明和验证c1，c2，c3中隐匿的金额c1_value，c2_value，\
         c3_value是否满足如下约束关系：",
    );
    print_highlight("  c1_value + c2_value =? c3_value");
    print_highlight("  c1_value * c2_value =? c3_value");
    print_highlight("  c1_value >=? 0");
    print_highlight(
        "若不满足对应的约束关系，只能生成错误的证明，在验证环节将会验证失败。",
    );

    print_wide(" ▶ 是否存在加和关系？尝试证明c1_value + c2_value =? c3_value");
    let sum_proof = vcl::prove_sum_balance(&c1_secret, &c2_secret, &c3_secret);
    println!("加和关系的证明数据：\n{:?}", sum_proof);
    pause_cn();

    print_wide(" ▶ 是否存在乘积关系？尝试证明c1_value * c2_value =? c3_value");
    let product_proof =
        vcl::prove_product_balance(&c1_secret, &c2_secret, &c3_secret);
    println!("乘积关系的证明数据：\n{:?}", product_proof);
    pause_cn();

    print_wide(" ▶ 是否是非负数？尝试证明c1_value >=? 0");
    let range_proof_c1 = vcl::prove_range(&c1_secret);
    println!("非负数的证明数据：\n{:?}", range_proof_c1);
    pause_cn();

    println!(
        "\n{} {}\n",
        "【演示进度】开具密文凭证 ↦ 生成凭证的约束关系证明 ↦ ",
        "<<验证凭证的约束关系证明>>".yellow(),
    );

    print_highlight("现在我们在密文的基础上，一一验证以上约束关系是否正确。");
    print_highlight(
        "验证过程中只需要用到密文凭证c1, c2, c3，和相关的证明数据。",
    );
    print_alert("无需披露敏感金额的明文数据！");

    print_wide("对应的验证结果如下：");

    let meet_sum_balance =
        vcl::verify_sum_balance(&c1_credit, &c2_credit, &c3_credit, &sum_proof)
            .unwrap();
    if meet_sum_balance {
        print_highlight("✓ 密文验证成功：c1_value + c2_value = c3_value");
    } else {
        print_alert("✗ 密文验证失败：c1_value + c2_value != c3_value");
    }
    let meet_product_balance = vcl::verify_product_balance(
        &c1_credit,
        &c2_credit,
        &c3_credit,
        &product_proof,
    )
    .unwrap();
    if meet_product_balance {
        print_highlight("✓ 密文验证成功：c1_value * c2_value = c3_value");
    } else {
        print_alert("✗ 密文验证失败：c1_value * c2_value != c3_value");
    }
    let meet_range_constraint = vcl::verify_range(&c1_credit, &range_proof_c1);
    if meet_range_constraint {
        print_highlight("✓ 密文验证成功：c1_value >= 0");
    } else {
        print_alert("✗ 密文验证失败：c1_value < 0");
    }
    pause_cn();

    print_highlight(
        "如上所示，验证者可以使用公开密文数据来核实账本中金额的正确性，\
         而且无需获知敏感金额的明文数据。",
    );
    print_wide(
        "以上演示的四则运算关系和非负数等基础证明验证过程，\
         其效果等价于对以下明文数据直接进行核实：",
    );

    if meet_sum_balance {
        println!("✓ 金额符合预期：{} + {} = {}", value1, value2, value3);
    } else {
        println!("✗ 金额偏离预期：{} + {} != {}", value1, value2, value3);
    }
    if meet_product_balance {
        println!("✓ 金额符合预期：{} * {} = {}", value1, value2, value3);
    } else {
        println!("✗ 金额偏离预期：{} * {} != {}", value1, value2, value3);
    }
    if meet_range_constraint {
        println!("✓ 金额符合预期：{} >= 0", value1);
    } else {
        println!("✗ 金额偏离预期：{} < 0", value1);
    }
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
        "In this demo, you will experience how to generate confidential \
         credit from a plaintext ledger amount, and to apply basic \
         zero-knowledge proof (ZKP) on those confidential credits.",
    );

    println!(
        "{}\n{}\n{}\n{}\n",
        "[Demo progress]",
        "↦ <<Issue confidential credits>>".yellow(),
        "↦ Prove constraints among credential credits",
        "↦ Verify constraints among credential credits",
    );

    print_alert(
        "Now please enter the plaintext value of the first ledger amount to \
         be converted into a confidential credit c1. ▼▼▼",
    );
    print_highlight(
        "In this demo, we use 10000 as the amount limit, which could be \
         extended for a higher limit in real applications. Please enter a \
         integer number between 0 and 10000.",
    );

    let value1 = wait_for_number_en();
    let (c1_credit, c1_secret) = vcl::make_credit(value1);
    println!(
        "\n{}",
        "A complete confidential credit for c1 consists of two parts.".green()
    );
    println!(
        " ▶ Public part: a publicly verifiable credential credit.\n{}",
        &c1_credit
    );
    println!(
        " ▶ Private part: secret parameters used to generate a publicly \
         verifiable credential credit, which represents the ownership of the \
         ledger amount.\n{}",
        c1_secret
    );
    print_wide(
        "For simplicity, we use confidential credit only for the public part. \
         For the private part, users should store it carefully, to protect \
         their ownership.",
    );

    print_alert(
        "Now please enter the plaintext value of the first ledger amount to \
         be converted into a confidential credit c2. ▼▼▼",
    );
    let value2 = wait_for_number_en();
    let (c2_credit, c2_secret) = vcl::make_credit(value2);

    print_alert(
        "Please enter the plaintext value of the first ledger amount to be \
         converted into a confidential credit c3. ▼▼▼",
    );
    let value3 = wait_for_number_en();
    let (c3_credit, c3_secret) = vcl::make_credit(value3);

    print_wide(
        "So far, we have generated the following publicly verifiable \
         credential credits:",
    );
    println!("c1: {:?}", point_to_bytes(&c1_credit.get_point()));
    println!("c2: {:?}", point_to_bytes(&c2_credit.get_point()));
    println!("c3: {:?}", point_to_bytes(&c3_credit.get_point()));
    pause_en();

    println!(
        "{}\n{}\n{}\n{}\n",
        "[Demo progress]",
        "↦ Issue confidential credits",
        "↦ <<Prove constraints among credential credits>>".yellow(),
        "↦ Verify constraints among credential credits",
    );

    print_highlight(
        "Now we will demonstrate the basic usage of using credential credits \
         together with ZKP.",
    );
    print_highlight(
        "Try to prove and verify whether the values c1_value, c2_value, \
         c3_value embedded in c1, c2, c3 satisfying the following constraints:",
    );
    print_highlight("  c1_value + c2_value =? c3_value");
    print_highlight("  c1_value * c2_value =? c3_value");
    print_highlight("  c1_value >=? 0");
    print_highlight(
        "If a constraint is not satisfied, the generated bogus proof will \
         fail to pass the verification.",
    );

    print_wide(
        " ▶ Attempt to prove a sum relationship: c1_value + c2_value =? \
         c3_value",
    );
    let sum_proof = vcl::prove_sum_balance(&c1_secret, &c2_secret, &c3_secret);
    println!("Proof data for the sum relationship:\n{:?}", sum_proof);
    pause_en();

    print_wide(
        " ▶ Attempt to prove a product relationship: c1_value * c2_value =? \
         c3_value",
    );
    let product_proof =
        vcl::prove_product_balance(&c1_secret, &c2_secret, &c3_secret);
    println!(
        "Proof data for the product relationship:\n{:?}",
        product_proof
    );
    pause_en();

    print_wide(" ▶ Attempt to prove a non-negative constraint: c1_value >=? 0");
    let range_proof_c1 = vcl::prove_range(&c1_secret);
    println!(
        "Proof data for the non-negative constraint:\n{:?}",
        range_proof_c1
    );
    pause_en();

    println!(
        "{}\n{}\n{}\n{}\n",
        "[Demo progress]",
        "↦ Issue confidential credits",
        "↦ Prove constraints among credential credits",
        "↦ <<Verify constraints among credential credits>>".yellow(),
    );

    print_highlight("Verification time!");
    print_highlight(
        "The above constraint can be verified only by using confidential \
         credits (e.g. c1, c2, c3) and the corresponding ZKP proof.",
    );
    print_alert("No need to reveal sensitive plaintext ledger amount!");

    print_wide("Verification results are listed below:");

    let meet_sum_balance =
        vcl::verify_sum_balance(&c1_credit, &c2_credit, &c3_credit, &sum_proof)
            .unwrap();
    if meet_sum_balance {
        print_highlight("✓ Pass: c1_value + c2_value = c3_value");
    } else {
        print_alert("✗ Fail: c1_value + c2_value != c3_value");
    }
    let meet_product_balance = vcl::verify_product_balance(
        &c1_credit,
        &c2_credit,
        &c3_credit,
        &product_proof,
    )
    .unwrap();
    if meet_product_balance {
        print_highlight("✓ Pass: c1_value * c2_value = c3_value");
    } else {
        print_alert("✗ Fail: c1_value * c2_value != c3_value");
    }
    let meet_range_constraint = vcl::verify_range(&c1_credit, &range_proof_c1);
    if meet_range_constraint {
        print_highlight("✓ Pass: c1_value >= 0");
    } else {
        print_alert("✗ Fail: c1_value < 0");
    }
    pause_en();

    print_highlight(
        "As seen above, a verifier can use confidential credit to verify the \
         correctness of ledger amount in VCL without knowing its sensitive \
         plaintext values.",
    );
    print_wide(
        "The above basic prove-verification processes for arithmetic \
         constraints and range constraints achieve the same effect as the \
         direct validation on the plaintext data.",
    );

    if meet_sum_balance {
        println!("✓ Ledger looks good: {} + {} = {}", value1, value2, value3);
    } else {
        println!(
            "✗ Ledger seems wrong: {} + {} != {}",
            value1, value2, value3
        );
    }
    if meet_product_balance {
        println!("✓ Ledger looks good: {} * {} = {}", value1, value2, value3);
    } else {
        println!(
            "✗ Ledger seems wrong: {} * {} != {}",
            value1, value2, value3
        );
    }
    if meet_range_constraint {
        println!("✓ Ledger looks good: {} >= 0", value1);
    } else {
        println!("✗ Ledger seems wrong: {} < 0", value1);
    }
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

// In this demo, we set the upper limit of input value to 10000.
const MAX_INPUT_VALUE: i64 = 10000;

fn wait_for_number(error_message: &str) -> u64 {
    let mut input = wait_for_input();
    let mut input_num = input.parse::<i64>();
    loop {
        match input_num {
            // TODO: Enable negative input in the demo.
            Ok(v) if (v >= 0) && (v <= MAX_INPUT_VALUE) => return v as u64,
            _ => {
                print_alert(error_message);
                input = wait_for_input();
                input_num = input.parse::<i64>();
            },
        }
    }
}

fn wait_for_number_cn() -> u64 {
    wait_for_number("请输入有效数字：")
}

fn wait_for_number_en() -> u64 {
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
