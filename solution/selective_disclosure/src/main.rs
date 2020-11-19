// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Minimalist demo of selective_disclosure.
use colored::*;

use selective_disclosure::{issuer, user, verifier};
use std;
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
    println!(
        "{}\n{}\n",
        "凭证模板初始化中，请耐心等待。",
        "本次初始化为一次性开销，模板可复用。",
    );
    let mut tmp = AttributeTemplate::new();
    tmp.mut_attribute_key().push(format!("contribution"));
    tmp.mut_attribute_key().push(format!("age"));
    let (credential_template, template_secret_key) =
        issuer::make_credential_template(&tmp).unwrap();
    print_wide(
        "本demo，我们将设定一个具体场景，\
         来让用户在场景中体验选择性披露的整个流程。",
    );
    println!(
        "{}\n{}\n{}\n",
        "【场景介绍】",
        "用户申请“优秀青年”奖项".yellow(),
        "优秀青年申请条件：年龄在[18,40]区间内且贡献级大于6。".yellow(),
    );
    println!(
        "{}\n{}\n{}\n{}\n{}\n",
        "【场景整体流程介绍】",
        "首先，用户需向权威机构提供个人信息，请求认证，获得认证后的凭证。",
        "然后，用户可以选择以下不同方式提出奖项申请：",
        "①用户提交满足申请条件的断言证明;".yellow(),
        "②用户选择性披露部分明文信息及其正确性证明;".yellow(),
    );
    pause_cn();

    print_highlight("本demo将从用户角度进行演示。");
    println!(
        "{} {} {}\n",
        "【演示进度】",
        "<<用户填写凭证模板>>".yellow(),
        "↦ 用户请求认证 ↦ 用户获得认证后的凭证 ↦ 用户选择申请方式并提交申请 ↦ \
         用户获得申请的筛选结果",
    );

    print_alert("权威机构制定并公布凭证模板，要求用户填写：年龄和贡献级");
    print_highlight(
        "在这个demo中，我们暂定年龄输入范围为[0,100]，贡献级输入范围为[0,\
         10]（真实业务可按需扩展）\n",
    );

    print_alert("现在，请用户输入年龄：▼▼▼");
    print_highlight("请输入0到100之间的整数");
    let mut user_age = wait_for_number_cn();
    let mut credential_info = CredentialInfo::new();
    let mut pair = StringToStringPair::new();
    if user_age > 100 {
        print_alert("请重新输入有效数字：");
        user_age = wait_for_number_cn();
    }
    pair.set_key(format!("age"));
    pair.set_value(format!("{}", user_age.to_string()));
    credential_info.mut_attribute_pair().push(pair.clone());

    print_alert("请用户输入贡献级：▼▼▼");
    print_highlight("请输入0到10之间的整数");
    let mut user_contribution = wait_for_number_cn();
    if user_contribution > 10 {
        print_alert("请重新输入有效数字：");
        user_contribution = wait_for_number_cn();
    }
    pair.set_key(format!("contribution"));
    pair.set_value(format!("{}", user_contribution.to_string()));
    credential_info.mut_attribute_pair().push(pair.clone());

    println!(
        "{} {} {} {}\n",
        "【演示进度】",
        "用户填写凭证模板 ↦",
        "<<用户请求认证>>".yellow(),
        "↦ 用户获得认证后的凭证 ↦ 用户选择申请方式并提交申请 ↦ \
         用户获得申请的筛选结果",
    );
    let (
        credential_signature_request,
        master_secret_str,
        credential_secrets_blinding_factors_str,
        nonce_credential_str,
    ) = user::make_credential(&credential_info, &credential_template).unwrap();

    println!(
        "{} {:?}",
        "用户生成的认证请求为：\n".yellow(),
        credential_signature_request
    );
    println!(
        "\n{}{}\n",
        "可见，用户向权威机构提供的凭证认证请求中，开头包含了用户的明文信息，"
            .yellow(),
        "权威机构核查用户信息正确后才会进行认证。".yellow(),
    );
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】用户填写凭证模板 ↦ 用户请求认证 ↦",
        "<<用户获得认证后的凭证>>".yellow(),
        "↦ 用户选择申请方式并提交申请 ↦ 用户获得申请的筛选结果",
    );

    let value1 = String::new();
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
        "{} {:?}\n",
        "用户获得的认证后凭证为：\n".yellow(),
        credential_signature
    );

    print_alert(
        "可见，权威机构认证后返回给用户的认证凭证中，\
         已不包含属性名和用户的属性值。",
    );
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】用户填写凭证模板 ↦ 用户请求凭证授权 ↦ \
         用户获取授权后的凭证 ↦",
        "<<用户选择申请方式并提交申请>>".yellow(),
        "↦ 用户获得申请的筛选结果",
    );

    print_highlight(
        "为防止权威机构对认证凭证的使用进行跟踪，\
         用户首先需对认证凭证进行混淆，获得混淆凭证。",
    );
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
        "\n{} {:?}\n",
        "用户生成得混淆凭证为：\n".yellow(),
        new_credential_signature
    );
    print_alert("可见，混淆凭证与权威机构认证的凭证内容已不同。");
    pause_cn();
    println!(
        "{}\n{}\n{}{}\n",
        "现在，请用户选择以下信息提供方式：".yellow(),
        "▶ 输入1，表示用户提供断言证明。",
        "▶ 输入2，表示用户提供贡献级明文信息及其正确性证明，",
        "奖项授予方通过贡献级确定用户的奖项评级。"
    );
    print_highlight(
        "(如，贡献级 = 10 为一等奖，贡献级 = 9 为二等奖，贡献级 = 7或8 \
         为三等奖)",
    );

    print_wide("请选择信息提供方式（1或2）：▼▼▼");

    let mut choice = wait_for_input();
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
                user_contribution,
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
    print_alert("请提供断言证明。");
    print_highlight("若用户信息不满足申请条件，则无法生成断言证明");

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
            print_wide("您输入的信息不满足申请条件，无法生成断言证明。");
            print_highlight("谢谢参与，您尚不具备优秀青年评选资格。");
            return;
        },
    };

    println!("断言证明已生成，证明大小约为52KB。");

    println!(
        "\n{} {}\n",
        "【演示进度】用户填写凭证模板 ↦ 用户请求认证 ↦ 用户获得认证后的凭证 ↦ \
         用户选择申请方式并提交申请",
        "↦ <<用户获得申请的筛选结果>>".yellow(),
    );

    let result = verifier::verify_proof(&rules, &request).unwrap();
    println!("奖项授予方对用户断言证明的验证结果为：{:?}", result);
    if result == true {
        print_highlight("恭喜您，您具有优秀青年评选资格！");
    } else {
        print_highlight("谢谢参与，您尚不具备优秀青年评选资格。");
    }
}

fn flow_disclosure(
    contribution: u64,
    new_credential_signature: &CredentialSignature,
    credential_info: &CredentialInfo,
    credential_template: &CredentialTemplate,
    master_secret_str: &str,
)
{
    print_alert("请提供凭证中已认证的贡献级信息。");
    print_highlight(
        "此时，为防止用户提供未认证的贡献级信息，\
         用户首先需对贡献级信息生成正确性证明。",
    );

    let mut rules = VerificationRule::new();
    rules
        .mut_revealed_attribute()
        .push("contribution".to_string());
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name("age".to_string());
    predicate_rule.set_predicate_type("GE".to_string());
    predicate_rule.set_value(18);
    rules.mut_predicate_attribute().push(predicate_rule);
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name("age".to_string());
    predicate_rule.set_predicate_type("LE".to_string());
    predicate_rule.set_value(40);
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
            print_highlight("谢谢参与，您尚不具备优秀青年评选资格。");
            return;
        },
    };

    let attrs =
        verifier::get_revealed_attrs_from_verification_request(&request)
            .unwrap();
    println!(
        "{}\n{:?}",
        "用户直接披露的凭证中已认证信息为：".yellow(),
        attrs
    );
    print_alert("现在，奖项授予方根据用户披露的贡献级信息进行评级。");
    pause_cn();
    if contribution >= 7 && contribution <= 8 {
        print_highlight("恭喜您，您具有优秀青年三等奖评选资格！");
    } else if contribution == 9 {
        print_highlight("谢谢参与，您具有优秀青年二等奖评选资格！");
    } else if contribution == 10 {
        print_highlight("谢谢参与，您具有优秀青年一等奖评选资格！");
    } else {
        print_highlight("谢谢参与，您尚不具备优秀青年评选资格。");
    }
}
fn flow_en() {}

// Utility functions
fn print_highlight(message: &str) {
    println!("{}\n", message.green());
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

// fn wait_for_number_en() -> u64 {
//    wait_for_number("Please input a valid number:")
//}

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

// fn pause_en() {
//    pause("Press any key to continue...");
//}
