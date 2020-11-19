// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Minimalist demo of selective_disclosure.
use colored::*;
use protobuf::Message;
use selective_disclosure::{issuer, user, verifier};
use std::ops::Add;
use wedpr_crypto::utils;
use wedpr_protos::generated::selective_disclosure::{
    AttributeTemplate, CredentialInfo, CredentialSignature, CredentialTemplate,
    Predicate, StringToStringPair, VerificationRule,
};

fn main() {
    print_highlight2(
        "#\n# Welcome to selective disclosure demo!",
        "# 欢迎来到选择性披露demo演示!\n#",
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
    print_wide("示例加载中...");
    let mut tmp = AttributeTemplate::new();
    tmp.mut_attribute_key().push(format!("id"));
    tmp.mut_attribute_key().push(format!("contribution"));
    tmp.mut_attribute_key().push(format!("age"));
    let (credential_template, template_secret_key) =
        issuer::make_credential_template(&tmp).unwrap();
    print_wide(
        "本demo，我们将设定一个具体场景，\
         来让用户在场景中体验选择性披露的整个流程",
    );
    println!(
        "{}\n{}\n",
        "【场景介绍】",
        "用户申请“杰出青年”奖项".yellow()
    );
    println!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        "【场景整体流程介绍】",
        "首先用户需向权威机构提供权威机构所要求的个人信息，请求认证，获得原始证书，\
         然后用户将原始证书进行偏移，获得一次性证书。\
         用户申请奖项时，可以选择向奖项授予方提供一次性证书或者直接选择性地只披露身份，\
         奖项授予方根据用户证书或者用户披露的身份核验用户是否满足申请条件。".yellow(),
        "若用户选择提交一次性证书，则奖项授予方需验证：".green(),
        "①用户提交的证书确实经过权威机构认证；".yellow(),
        "②用户的年龄在18岁至40岁之间（包含18岁及40岁）且贡献级大于6。".yellow(),
        "若用户选择披露身份，则奖项授予方需根据身份寻求权威机构的认证，核验用户其他信息：".green(),
        "用户的年龄在18岁至40岁之间（包含18岁及40岁）且贡献级大于6。".yellow()
    );
    pause_cn();

    print_wide("本demo将从用户角度进行演示。");

    println!(
        "{} {} {}\n",
        "【演示进度】",
        "<<用户根据权威机构公布的属性模板填写自己的属性内容>>".yellow(),
        "↦ 用户根据权威机构公布的证书模板与自己的属性内容，生成证书签名请求 ↦ \
         用户获得权威机构认证后的原始证书 ↦ \
         用户对原始证书进行偏移，生成一次性证书 ↦ \
         用户选择提交信息方式：向奖项授予方提供一次性证书或披露身份ID ↦ \
         用户获得奖项授予方的申请资格筛选结果",
    );
    pause_cn();

    print_alert2(
        "权威机构事先已制定并公布以下属性模板，即用户需要填写以下信息：",
        "属性1：用户ID；属性2：贡献级；属性3：年龄",
    );
    print_highlight2(
        "在这个demo中，我们暂定身份ID输入范围为[0,10000]，贡献级输入范围为[0,\
         9].",
        "年龄输入范围为[0,100]（真实业务可按需扩展）",
    );

    print_alert("现在，请用户输入第一个属性值——身份ID：▼▼▼");
    print_highlight("请输入0到10000之间的整数");
    let value1 = wait_for_number_cn();
    let mut credential_info = CredentialInfo::new();
    let mut pair = StringToStringPair::new();
    pair.set_key(format!("id"));
    pair.set_value(format!("{}", value1));
    credential_info.mut_attribute_pair().push(pair.clone());

    print_alert("请用户输入第二个属性值——贡献级：▼▼▼");
    print_highlight("请输入0到9之间的整数");
    let mut value2 = wait_for_number_cn();
    if value2 > 9 || value2 < 0 {
        print_alert("请重新输入有效数字：");
        value2 = wait_for_number_cn();
    }
    pair.set_key(format!("contribution"));
    pair.set_value(format!("{}", value2.to_string()));
    credential_info.mut_attribute_pair().push(pair.clone());

    print_alert("请用户输入第三个属性值——年龄：▼▼▼");
    print_highlight("请输入0到100之间的整数");
    let value3 = wait_for_number_cn();
    if value3 > 100 || value3 < 0 {
        print_alert("请重新输入有效数字：");
        value2 = wait_for_number_cn();
    }
    pair.set_key(format!("age"));
    pair.set_value(format!("{}", value3.to_string()));
    credential_info.mut_attribute_pair().push(pair.clone());
    pause_cn();

    println!(
        "{} {} {} {} {}\n",
        "【演示进度】",
        "用户根据权威机构公布的属性模板填写自己的属性内容",
        "↦ <<用户根据权威机构公布的证书模板与自己的属性内容，\
         生成证书签名请求>>"
            .yellow(),
        "↦ 用户获得权威机构认证后的原始证书 ↦ \
         用户对原始证书进行偏移，生成一次性证书 ↦ \
         用户选择提交信息方式：向奖项授予方提供一次性证书或披露身份ID",
        "↦ 用户获得奖项授予方的申请资格筛选结果",
    );
    pause_cn();

    let (
        credential_signature_request,
        master_secret_str,
        credential_secrets_blinding_factors_str,
        nonce_credential_str,
    ) = user::make_credential(&credential_info, &credential_template).unwrap();

    println!(
        "{} {:?}",
        "用户生成的证书签名请求为：\n".yellow(),
        credential_signature_request
    );
    pause_cn();
    println!(
        "{}\n",
        "可见，用户向权威机构提供的证书签名请求中，开头包含了用户的属性值，\
         权威机构需要核查用户提供的属性信息是否正确。确定用户信息正确后，\
         权威机构才会进行签名认证。"
            .yellow(),
    );

    pause_cn();
    println!(
        "{} {} {} {}\n",
        "【演示进度】",
        "用户根据权威机构公布的属性模板填写自己的属性内容 ↦ \
         用户根据权威机构公布的证书模板与自己的属性内容，生成证书签名请求",
        "↦ <<用户获得权威机构认证后的原始证书>>".yellow(),
        "↦ 用户对原始证书进行偏移，生成一次性证书 ↦ \
         用户选择提交信息方式：向奖项授予方提供一次性证书或披露身份ID ↦ \
         用户获得奖项授予方的申请资格筛选结果",
    );
    pause_cn();
    let user_id = value1.to_string();
    let (credential_signature, cred_issuance_nonce_str) =
        issuer::sign_credential(
            &credential_template,
            &template_secret_key,
            &credential_signature_request,
            &user_id,
            &nonce_credential_str,
        )
        .unwrap();
    println!(
        "{} {:?}",
        "用户获得认证后的原始证书为：\n".yellow(),
        credential_signature
    );
    pause_cn();

    print_alert(
        "可见，权威机构认证后返回给用户的原始证书中，\
         已不包含属性名和用户的属性值。",
    );
    pause_cn();

    println!(
        "{} {} {} {}\n",
        "【演示进度】",
        "用户根据权威机构公布的属性模板填写自己的属性内容 ↦ \
         用户根据权威机构公布的证书模板与自己的属性内容，生成证书签名请求 ↦ \
         用户获得权威机构认证后的原始证书",
        "↦ <<用户对原始证书进行偏移，生成一次性证书>>".yellow(),
        "↦ 用户选择提交信息方式：向奖项授予方提供一次性证书或披露身份ID ↦ \
         用户获得奖项授予方的申请资格筛选结果",
    );

    pause_cn();

    let new_credential_signature = user::blind_credential_signature(
        &credential_signature,
        &credential_info,
        &credential_template,
        &master_secret_str,
        &credential_secrets_blinding_factors_str,
        &cred_issuance_nonce_str,
    )
    .unwrap();
    println!(
        "{} {:?}",
        "用户生成的一次性证书为：\n".yellow(),
        new_credential_signature
    );

    pause_cn();
    print_alert(
        "可见，用户偏移后的一次性证书与权威机构签发的原始证书内容已不同。",
    );
    pause_cn();

    println!(
        "{}\n{}\n{}\n",
        "请选择以下信息提供方式：".yellow(),
        "▶ 输入1，表示用户向奖项授予方提供一次性证书，\
         并证明一次性证书的正确性。",
        "▶ 输入2，表示用户向奖项授予方选择性地只披露身份ID，\
         奖项授予方通过身份ID去核验用户其他信息。",
    );
    println!("{}\n", "请选择信息提供方式（1或2）：▼▼▼",);

    let mut choice = wait_for_input();
    pause_cn();
    loop {
        // The default option.
        if choice == "1" || choice.is_empty() {
            flow_credential(
                &new_credential_signature,
                &credential_info,
                &credential_template,
                &master_secret_str,
            );
            break;
        } else if choice == "2" {
            flow_disclosure(
                &user_id,
                value2,
                value3,
                &new_credential_signature,
                &credential_info,
                &credential_template,
                &master_secret_str,
            );
            break;
        } else {
            print_alert("输入错误！请重新输入有效选项：");
            choice = wait_for_input();
        }
    }
    pause_cn();

    print_alert("十分感谢您的试用！");
    println!(
        "\n{}\n\n{}\n{}\n",
        "关于WeDPR，如需了解更多，欢迎通过以下方式联系我们：",
        "1. 微信公众号【微众银行区块链】",
        "2. 官方邮箱【wedpr@webank.com】"
    );
    println!();
}

fn flow_credential(
    new_credential_signature: &CredentialSignature,
    credential_info: &CredentialInfo,
    credential_template: &CredentialTemplate,
    master_secret_str: &str,
)
{
    println!(
        "{} {} {} {}\n",
        "【演示进度】",
        "用户根据权威机构公布的属性模板填写自己的属性内容 ↦ \
         用户根据权威机构公布的证书模板与自己的属性内容，生成证书签名请求 ↦ \
         用户获得权威机构认证后的原始证书 ↦ \
         用户对原始证书进行偏移，生成一次性证书",
        "↦ <<用户向奖项授予方提供一次性证书，并证明一次性证书的正确性>>"
            .yellow(),
        "↦ 用户获得奖项授予方对一次性证书的验证结果",
    );
    pause_cn();
    let mut rules = VerificationRule::new();
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name("contribution".to_string());
    predicate_rule.set_predicate_type("GT".to_string());
    predicate_rule.set_value(6);
    rules.mut_predicate_attribute().push(predicate_rule);
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name("age".to_string());
    predicate_rule.set_predicate_type("LE".to_string());
    predicate_rule.set_value(40);
    rules.mut_predicate_attribute().push(predicate_rule);
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name("age".to_string());
    predicate_rule.set_predicate_type("GE".to_string());
    predicate_rule.set_value(18);
    rules.mut_predicate_attribute().push(predicate_rule);
    let request_result = user::prove_selected_credential_info(
        &rules,
        &new_credential_signature,
        &credential_info,
        &credential_template,
        &master_secret_str,
    );
    let request = match request_result {
        Ok(v) => v,
        Err(_) => {
            print_wide("您输入的信息不满足申请条件，无法生成对应证明。");
            print_highlight("谢谢参与，您尚不具备杰出青年评选资格。");
            return;
        },
    };
    println!("{} {:?}", "用户的证明为：\n".yellow(), request);

    pause_cn();
    println!(
        "{} {} {}\n",
        "【演示进度】",
        "用户根据权威机构公布的属性模板填写自己的属性内容 ↦ \
         用户根据权威机构公布的证书模板与自己的属性内容，生成证书签名请求 ↦ \
         用户获得权威机构认证后的原始证书 ↦ \
         用户对原始证书进行偏移，生成一次性证书 ↦ \
         用户向奖项授予方提供一次性证书，并证明一次性证书的正确性",
        "↦ <<用户获得奖项授予方对一次性证书的验证结果>>".yellow(),
    );

    pause_cn();
    let result = verifier::verify_proof(&rules, &request).unwrap();
    println!("奖项授予方对用户一次性证书的筛选结果为：{:?}", result);
    pause_cn();
    if result == true {
        print_highlight("恭喜您，您具有杰出青年评选资格！");
    } else {
        print_highlight("谢谢参与，您尚不具备杰出青年评选资格。");
    }
}

fn flow_disclosure(
    id: &str,
    value2: u64,
    value3: u64,
    new_credential_signature: &CredentialSignature,
    credential_info: &CredentialInfo,
    credential_template: &CredentialTemplate,
    master_secret_str: &str,
)
{
    println!(
        "{} {} {} {}\n",
        "【演示进度】",
        "用户根据权威机构公布的属性模板填写自己的属性内容 ↦ \
         用户根据权威机构公布的证书模板与自己的属性内容，生成证书签名请求 ↦ \
         用户获得权威机构认证后的原始证书 ↦ \
         用户对原始证书进行偏移，生成一次性证书",
        "↦ <<用户向奖项授予方选择性披露身份>>".yellow(),
        "↦ 用户获得奖项授予方通过身份人工核验确定的筛选结果",
    );
    pause_cn();
    let mut rules = VerificationRule::new();
    rules.mut_revealed_attribute().push("id".to_string());

    let request_result = user::prove_selected_credential_info(
        &rules,
        &new_credential_signature,
        &credential_info,
        &credential_template,
        &master_secret_str,
    );
    let request = match request_result {
        Ok(v) => v,
        Err(_) => {
            print_wide("您输入的信息不满足申请条件，无法生成对应证明。");
            return;
        },
    };

    let attrs =
        verifier::get_revealed_attrs_from_verification_request(&request)
            .unwrap();
    println!("{}\n{:?}", "披露属性为：".yellow(), attrs);
    print_alert(
        "现在，奖项授予方根据用户披露的身份ID，\
         去权威机构查询该用户是否具有申请资格。",
    );
    pause_cn();
    if value2 > 6 && value3 >= 18 && value3 <= 40 {
        print_wide("权威机构告知奖项授予方：该用户具有申请资格。");
        print_highlight("恭喜您，您具有杰出青年评选资格！");
    } else {
        print_wide("权威机构告知奖项授予方：该用户不具有申请资格。");
        print_highlight("谢谢参与，您尚不具备杰出青年评选资格。");
    }
}
fn flow_en() {}

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

fn wait_for_sl_input(error_message: &str) -> String {
    let mut input = wait_for_input();
    loop {
        let input_copy = input.clone();
        let mut flags = 0;
        for c in input_copy.chars() {
            let input_num = c.to_digit(10);
            match input_num {
                None => {
                    print_alert(error_message);
                    input = wait_for_input();
                    break;
                },
                _ => flags += 1,
            }
        }
        if flags == input_copy.len() {
            return input;
        }
    }
    input
}

fn wait_for_sl_input_cn() -> String {
    wait_for_sl_input("请输入有效输入：")
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
