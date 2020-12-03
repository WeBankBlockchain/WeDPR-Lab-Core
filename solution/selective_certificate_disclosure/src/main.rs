// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Minimalist demo of selective certificate disclosure.

use colored::*;

use selective_certificate_disclosure::{issuer, user, utils, verifier};
use std;
use wedpr_protos::generated::scd::{
    AttributeDict, CertificateSchema, CertificateSignature,
    CertificateTemplate, Predicate, StringToStringPair, TemplatePrivateKey,
    VerificationRuleSet, VerifyRequest,
};
use wedpr_utils::error::WedprError;

fn main() {
    print_highlight2(
        "#\n# Welcome to selective certificate disclosure (SCD) demo!",
        "# 欢迎来到选择性认证披露demo演示!\n#",
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

const DEFAULT_USER_ID: &str = "12345";
const ATTRIBUTE_CONTRIBUTION: &str = "contribution";
const ATTRIBUTE_AGE: &str = "age";

fn flow_cn() {
    println!(
        "{}\n{}\n",
        "凭证模板初始化中，请耐心等待。。。",
        "该计算为一次性开销，复用模板时无需再次等待。",
    );
    let (certificate_template, template_private_key) =
        issuer_init_certificate_template();
    print_wide(
        "本demo中，你将体验如何申请并使用具备选择性认证披露功能的新一代数字凭证。\
        为了更容易理解其效果，我们设定了如下示例应用场景。",
    );
    println!(
        "{}\n{}\n{}\n",
        "【场景介绍】",
        "用户申请“优秀青年”奖项".yellow(),
        "优秀青年申请条件：年龄在[18,40]区间内，且贡献级大于6。".yellow(),
    );
    println!(
        "{}\n{}\n{}\n{}\n{}\n",
        "【流程介绍】",
        "首先，用户需向权威机构提供个人信息，请求认证，然后获得认证后的凭证。",
        "最后，用户可以基于选择性认证披露功能，选择以下不同方式提出奖项申请，\
         以满足其隐私偏好：",
        "A. 用户经提交满足申请条件的断言证明，但不披露任何明文信息。".yellow(),
        "B. 用户选择性披露部分明文信息及其正确性证明，\
         但不披露任何未被选择的明文信息。"
            .yellow(),
    );
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】",
        "<<用户基于模板填写凭证信息>>".yellow(),
        "↦ 用户请求权威机构进行认证 ↦ 用户获得认证后的凭证 ↦ \
         用户选择申请方式并提交申请 ↦ 用户获得申请的筛选结果",
    );

    print_alert("首先，权威机构制定并公布凭证模板，要求用户填写：年龄和贡献级");
    print_highlight(
        "我们暂定所有输入为整数，年龄输入范围为[0,100]，贡献级输入范围为[0,\
         10]（真实业务可按需扩展）",
    );

    let mut certificate_attribute_dict = AttributeDict::new();

    print_alert("现在，请用户输入年龄 [0, 100]：▼▼▼");
    let age = wait_for_number_with_limit_cn(100);
    user_fill_age_attribute(&mut certificate_attribute_dict, age);

    print_alert("请用户输入贡献级 [0, 10]：▼▼▼");
    let contribution = wait_for_number_with_limit_cn(10);
    user_fill_contribution_attribute(
        &mut certificate_attribute_dict,
        contribution,
    );

    println!(
        "{} {} {}\n",
        "【演示进度】用户基于模板填写凭证信息 ↦",
        "<<用户请求权威机构进行认证>>".yellow(),
        "↦ 用户获得认证后的凭证 ↦ 用户选择申请方式并提交申请 ↦ \
         用户获得申请的筛选结果"
    );
    let (
        sign_certificate_request,
        user_private_key_str,
        certificate_secrets_blinding_factors_str,
        user_nonce_str,
    ) = user::fill_certificate(
        &certificate_attribute_dict,
        &certificate_template,
    )
    .unwrap();

    println!(
        "{}\n{:?}",
        "用户生成的认证请求为：".yellow(),
        sign_certificate_request
    );
    println!(
        "\n{}\n",
        "该凭证认证请求中包含了用户的明文信息，\
         权威机构核查用户信息正确后才能进行有效的认证。"
            .yellow()
    );
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】用户基于模板填写凭证信息 ↦ 用户请求权威机构进行认证 ↦",
        "<<用户获得认证后的凭证>>".yellow(),
        "↦ 用户选择申请方式并提交申请 ↦ 用户获得申请的筛选结果"
    );

    let (certificate_signature, issuer_nonce_str) = issuer::sign_certificate(
        &certificate_template,
        &template_private_key,
        &sign_certificate_request,
        &DEFAULT_USER_ID.to_string(),
        &user_nonce_str,
    )
    .unwrap();
    println!(
        "{}\n{:?}\n",
        "用户获得的认证后凭证为：".yellow(),
        certificate_signature
    );

    print_alert("该认证凭证中，已不包含属性名和用户的属性值。");
    print_highlight(
        "但是，为防止权威机构对认证凭证的使用进行跟踪，用户在使用该凭证前，\
         需要对认证凭证进行混淆，获得混淆凭证。",
    );
    pause_cn();

    let new_certificate_signature = user::blind_certificate_signature(
        &certificate_signature,
        &certificate_attribute_dict,
        &certificate_template,
        &user_private_key_str,
        &certificate_secrets_blinding_factors_str,
        &issuer_nonce_str,
    )
    .unwrap();
    println!(
        "\n{}\n{:?}\n",
        "用户生成得混淆凭证为：".yellow(),
        new_certificate_signature
    );
    print_alert(
        "混淆后，凭证中关键字段与权威机构认证后返回的凭证内容已大不相同。",
    );
    pause_cn();

    println!(
        "{} {} {}\n",
        "【演示进度】用户基于模板填写凭证信息 ↦ 用户请求权威机构进行认证 ↦ \
         用户获得认证后的凭证 ↦",
        "<<用户选择申请方式并提交申请>>".yellow(),
        "↦ 用户获得申请的筛选结果"
    );

    println!(
        "{}\n{}\n{}",
        "现在，请用户选择以下信息提供方式：".yellow(),
        "▶ 输入\"1\" 选择仅提供断言证明，证明满足全部申报条件，\
         但不透露任何字段值（默认选项）。",
        "▶ 输入\"2\" 选择提供贡献级明文信息及其正确性证明，\
         奖项授予方通过贡献级确定用户的奖项评级，但不透露年龄。"
    );
    println!(
        "{}\n{}\n{}",
        "  贡献级 = 10   为 一等奖",
        "  贡献级 = 9    为 二等奖",
        "  贡献级 = 7或8 为 三等奖",
    );

    let mut choice = wait_for_input();
    loop {
        // The default option.
        if choice == "1" || choice.is_empty() {
            subflow_predicate_only_cn(
                &new_certificate_signature,
                &certificate_attribute_dict,
                &certificate_template,
                &user_private_key_str,
            );
            break;
        } else if choice == "2" {
            subflow_mixed_disclosure_cn(
                contribution,
                &new_certificate_signature,
                &certificate_attribute_dict,
                &certificate_template,
                &user_private_key_str,
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

fn subflow_predicate_only_cn(
    new_certificate_signature: &CertificateSignature,
    certificate_attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
    user_private_key_str: &str,
)
{
    print_alert("断言证明生成中。。。");
    print_highlight(
        "若您之前输入的信息不满足申请条件，将无法生成有效的断言证明。",
    );

    let mut rule_set = VerificationRuleSet::new();
    // Set contribution threshold predicate.
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(ATTRIBUTE_CONTRIBUTION.to_string());
    predicate_rule.set_predicate_type("GT".to_string());
    predicate_rule.set_predicate_value(6);
    rule_set.mut_attribute_predicate().push(predicate_rule);
    // Set age range predicate.
    user_set_age_range_predicate(&mut rule_set);

    let request_result = user_prove_rule_set(
        new_certificate_signature,
        certificate_attribute_dict,
        certificate_template,
        user_private_key_str,
        &mut rule_set,
    );
    let request = match request_result {
        Ok(v) => v,
        Err(_) => {
            print_wide("断言证明生成失败。");
            print_highlight("谢谢参与，您尚不具备优秀青年评选资格。");
            return;
        },
    };

    println!("断言证明已成功生成。");
    pause_cn();

    println!(
        "{} {}\n",
        "【演示进度】用户基于模板填写凭证信息 ↦ 用户请求权威机构进行认证 ↦ \
         用户获得认证后的凭证 ↦ 用户选择申请方式并提交申请 ↦",
        "<<用户获得申请的筛选结果>>".yellow(),
    );

    let result = verifier_verify_rule_set(&mut rule_set, &request);
    println!("奖项授予方对用户断言证明的验证结果为：{:?}", result);
    // This result should not be false.
    assert!(result);
    print_highlight("恭喜您，您具有优秀青年评选资格！");
}

fn subflow_mixed_disclosure_cn(
    contribution: u64,
    new_certificate_signature: &CertificateSignature,
    certificate_attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
    user_private_key_str: &str,
)
{
    print_alert(
        "凭证中已认证的贡献级信息正确性证明，和年龄断言证明生成中。。。",
    );
    print_highlight(
        "为防止用户对贡献级信息进行篡改，用户需要为贡献级信息生成正确性证明。",
    );

    let mut rule_set = VerificationRuleSet::new();
    // Set contribution attribute to reveal.
    rule_set
        .mut_revealed_attribute_name()
        .push(ATTRIBUTE_CONTRIBUTION.to_string());
    // Set age range predicate.
    user_set_age_range_predicate(&mut rule_set);

    let request_result = user_prove_rule_set(
        new_certificate_signature,
        certificate_attribute_dict,
        certificate_template,
        user_private_key_str,
        &mut rule_set,
    );
    let request = match request_result {
        Ok(v) => v,
        Err(_) => {
            print_wide("年龄断言证明生成失败。");
            print_highlight("谢谢参与，您尚不具备优秀青年评选资格。");
            return;
        },
    };

    // This verification should be done before calling get_revealed_attributes.
    assert!(verifier_verify_rule_set(&mut rule_set, &request));
    let attrs = verifier::get_revealed_attributes(&request).unwrap();
    println!(
        "{}\n{:?}",
        "用户直接披露的凭证中已认证信息为：".yellow(),
        attrs
    );
    pause_cn();

    println!(
        "{} {}\n",
        "【演示进度】用户基于模板填写凭证信息 ↦ 用户请求权威机构进行认证 ↦ \
         用户获得认证后的凭证 ↦ 用户选择申请方式并提交申请 ↦",
        "<<用户获得申请的筛选结果>>".yellow(),
    );

    print_alert(
        "验证其有效性之后，奖项授予方根据用户披露的贡献级信息进行评级。",
    );
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

fn flow_en() {
    println!(
        "{}\n{}\n",
        "Certificate template is initializing. Please wait...",
        "This template initialization is one-time cost. No need to wait when \
         reusing this template.",
    );
    let (certificate_template, template_private_key) =
        issuer_init_certificate_template();
    print_wide(
        "In this demo, you will experience how to apply and use the next \
         generation digital certificate with selective disclosure capability. \
         We use the following application scenario for easy demonstration of \
         this new capability.",
    );
    println!(
        "{}\n{}\n{}\n",
        "[Background]",
        "Outstanding young citizen award application".yellow(),
        "For a qualified applicant, your age should be in the range of \
         [18-40], and your contribution level should be higher than 6."
            .yellow(),
    );
    println!(
        "{}\n{}\n{}\n{}\n{}\n",
        "[Story]",
        "First, you provide personal information to the authority to testify \
         its validity, and then receive a certificate from the authority.",
        "At last, you can use selective disclosure capability to choose \
         different ways for this application according to your privacy \
         preference.",
        "A. Provide selected attribute predicate only, without revealing any \
         plaintext information."
            .yellow(),
        "B. Provide selected attribute values, and prove their validity \
         without revealing any unselected attribute values."
            .yellow(),
    );
    pause_en();

    println!(
        "{} {} {}\n",
        "[Demo progress]",
        "<<Fill certificate template>>".yellow(),
        "↦ Request the authority to verify and sign the certificate ↦ Obtain \
         the signed certificate ↦ Use selective disclosure ↦ Check \
         application result",
    );

    print_alert(
        "First. the authority publishes a certificate template, where a user \
         can fill the age and the contribution level.",
    );
    print_highlight(
        "We assume all inputs are integers, age range is between [0, 100], \
         and contribution level is [0, 10], where those limits can be easily \
         lifted in real applications.",
    );

    let mut certificate_attribute_dict = AttributeDict::new();

    print_alert("Now, please enter your age [0, 100]: ▼▼▼");
    let age = wait_for_number_with_limit_en(100);
    user_fill_age_attribute(&mut certificate_attribute_dict, age);

    print_alert("Please enter your contribution level [0, 10]: ▼▼▼");
    let contribution = wait_for_number_with_limit_en(10);
    user_fill_contribution_attribute(
        &mut certificate_attribute_dict,
        contribution,
    );

    println!(
        "{} {} {}\n",
        "[Demo progress] Fill certificate template ↦",
        "<<Request the authority to verify and sign the certificate>>".yellow(),
        "↦ Obtain the signed certificate ↦ Use selective disclosure ↦ Check \
         application result",
    );
    let (
        sign_certificate_request,
        user_private_key_str,
        certificate_secrets_blinding_factors_str,
        user_nonce_str,
    ) = user::fill_certificate(
        &certificate_attribute_dict,
        &certificate_template,
    )
    .unwrap();

    println!(
        "{}\n{:?}",
        "The filled certificate verification request is:".yellow(),
        sign_certificate_request
    );
    println!(
        "\n{}\n",
        "This request contains your plaintext attribute values, which is \
         required by the authority to testify their validity."
            .yellow()
    );
    pause_en();

    println!(
        "{} {} {}\n",
        "[Demo progress] Fill certificate template ↦ Request the authority to \
         verify and sign the certificate ↦",
        "<<Obtain the signed certificate>>".yellow(),
        "↦ Use selective disclosure ↦ Check application result",
    );

    let value1 = String::new();
    let user_id = value1.to_string();
    let (certificate_signature, issuer_nonce_str) = issuer::sign_certificate(
        &certificate_template,
        &template_private_key,
        &sign_certificate_request,
        &user_id,
        &user_nonce_str,
    )
    .unwrap();
    println!(
        "{}\n{:?}\n",
        "You receive the following signed certificate.".yellow(),
        certificate_signature
    );

    print_alert(
        "There is no plaintext attribute values in the above signed \
         certificate.",
    );
    print_highlight(
        "But, in order to prevent the authority to track the certificate \
         usage, you can further blind this certificate before using it.",
    );
    pause_en();

    let new_certificate_signature = user::blind_certificate_signature(
        &certificate_signature,
        &certificate_attribute_dict,
        &certificate_template,
        &user_private_key_str,
        &certificate_secrets_blinding_factors_str,
        &issuer_nonce_str,
    )
    .unwrap();
    println!(
        "\n{}\n{:?}\n",
        "The blinded certificate is:".yellow(),
        new_certificate_signature
    );
    print_alert(
        "After blinding, the critical value fields in the certificate look \
         very different now.",
    );
    pause_en();

    println!(
        "{} {} {}\n",
        "[Demo progress] Fill certificate template ↦ Request the authority to \
         verify and sign the certificate ↦ Obtain the signed certificate ↦",
        "<<Use selective disclosure>>".yellow(),
        "↦ Check application result",
    );

    println!(
        "{}\n{}\n{}",
        "Now, you can select the following disclosure ways for your \
         application."
            .yellow(),
        "▶ Enter 1 to provide predicates only, i.e. proving the fact that all \
         conditions are satisfied without revealing any plaintext values \
         (default option).",
        "▶ Enter 2 to provide testified contribution level value for verifier \
         to decide the award level, but keep age secretly, and prove the age \
         is in the qualification range."
    );
    println!(
        "{}\n{}\n{}",
        "  Contribution level 10  ↦ 1st Prize",
        "  Contribution level 9   ↦ 2nd Prize",
        "  Contribution level 7/8 ↦ 3rd Prize",
    );

    let mut choice = wait_for_input();
    loop {
        // The default option.
        if choice == "1" || choice.is_empty() {
            subflow_predicate_only_en(
                &new_certificate_signature,
                &certificate_attribute_dict,
                &certificate_template,
                &user_private_key_str,
            );
            break;
        } else if choice == "2" {
            subflow_mixed_disclosure_en(
                contribution,
                &new_certificate_signature,
                &certificate_attribute_dict,
                &certificate_template,
                &user_private_key_str,
            );
            break;
        } else {
            print_alert("Invalid option! Please select again:");
            choice = wait_for_input();
        }
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

fn subflow_predicate_only_en(
    new_certificate_signature: &CertificateSignature,
    certificate_attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
    user_private_key_str: &str,
)
{
    print_alert("Generating proofs for predicates ...");
    print_highlight(
        "If your certificate (based on your previous inputs) does not satisfy \
         all the required conditions, the proof generation will fail.",
    );

    let mut rule_set = VerificationRuleSet::new();
    // Set contribution threshold predicate.
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(ATTRIBUTE_CONTRIBUTION.to_string());
    predicate_rule.set_predicate_type("GT".to_string());
    predicate_rule.set_predicate_value(6);
    rule_set.mut_attribute_predicate().push(predicate_rule);
    // Set age range predicate.
    user_set_age_range_predicate(&mut rule_set);

    let request_result = user_prove_rule_set(
        new_certificate_signature,
        certificate_attribute_dict,
        certificate_template,
        user_private_key_str,
        &mut rule_set,
    );
    let request = match request_result {
        Ok(v) => v,
        Err(_) => {
            print_wide("The proof generation failed.");
            print_highlight(
                "Unfortunately, you are not yet qualified for the award.",
            );
            return;
        },
    };

    println!("The proof generation succeeded.");
    pause_en();

    println!(
        "{} {}\n",
        "[Demo progress] Fill certificate template ↦ Request the authority to \
         verify and sign the certificate ↦ Obtain the signed certificate ↦ \
         Use selective disclosure ↦",
        "<<Check application result>>".yellow()
    );

    let result = verifier_verify_rule_set(&mut rule_set, &request);
    println!("The verification result is: {:?}", result);
    // This result should not be false.
    assert!(result);
    print_highlight("Congratulation! You are qualified to apply this award!");
}

fn subflow_mixed_disclosure_en(
    contribution: u64,
    new_certificate_signature: &CertificateSignature,
    certificate_attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
    user_private_key_str: &str,
)
{
    print_alert(
        "Extracting the contribution level and generating proof for the age \
         ...",
    );
    print_highlight(
        "In order to prevent tempering the testified attribute value, you \
         also need to generate the corresponding proof for those plaintext \
         values that you decided to disclose.",
    );

    let mut rule_set = VerificationRuleSet::new();
    // Set contribution attribute to reveal.
    rule_set
        .mut_revealed_attribute_name()
        .push(ATTRIBUTE_CONTRIBUTION.to_string());
    // Set age range predicate.
    user_set_age_range_predicate(&mut rule_set);

    let request_result = user_prove_rule_set(
        new_certificate_signature,
        certificate_attribute_dict,
        certificate_template,
        user_private_key_str,
        &mut rule_set,
    );
    let request = match request_result {
        Ok(v) => v,
        Err(_) => {
            print_wide("The proof generation failed.");
            print_highlight(
                "Unfortunately, you are not yet qualified for the award.",
            );
            return;
        },
    };

    // This verification should be done before calling get_revealed_attributes.
    assert!(verifier_verify_rule_set(&mut rule_set, &request));
    let attrs = verifier::get_revealed_attributes(&request).unwrap();
    println!("{}\n{:?}", "The disclosed values are:".yellow(), attrs);
    pause_en();

    println!(
        "{} {}\n",
        "[Demo progress] Fill certificate template ↦ Request the authority to \
         verify and sign the certificate ↦ Obtain the signed certificate ↦ \
         Use selective disclosure ↦",
        "<<Check application result>>".yellow()
    );

    print_alert(
        "According to the testify contribution level and the fact that your \
         age is in the qualification range:",
    );
    if contribution >= 7 && contribution <= 8 {
        print_highlight("You are qualified to apply 3rd Prize!");
    } else if contribution == 9 {
        print_highlight("You are qualified to apply 2nd Prize!");
    } else if contribution == 10 {
        print_highlight("You are qualified to apply 1st Prize!");
    } else {
        print_highlight(
            "Unfortunately, you are not yet qualified for the award.",
        );
    }
}

fn issuer_init_certificate_template(
) -> (CertificateTemplate, TemplatePrivateKey) {
    let mut schema = CertificateSchema::new();
    schema
        .mut_attribute_name()
        .push(ATTRIBUTE_CONTRIBUTION.to_string());
    schema.mut_attribute_name().push(ATTRIBUTE_AGE.to_string());
    let (certificate_template, template_private_key) =
        issuer::make_certificate_template(&schema).unwrap();
    (certificate_template, template_private_key)
}

fn user_fill_contribution_attribute(
    certificate_attribute_dict: &mut AttributeDict,
    contribution: u64,
)
{
    let mut contribution_kv = StringToStringPair::new();
    contribution_kv.set_key(ATTRIBUTE_CONTRIBUTION.to_string());
    contribution_kv.set_value(contribution.to_string());
    certificate_attribute_dict
        .mut_pair()
        .push(contribution_kv.clone());
}

fn user_fill_age_attribute(
    certificate_attribute_dict: &mut AttributeDict,
    age: u64,
)
{
    let mut age_kv = StringToStringPair::new();
    age_kv.set_key(ATTRIBUTE_AGE.to_string());
    age_kv.set_value(age.to_string());
    certificate_attribute_dict.mut_pair().push(age_kv);
}

fn user_set_age_range_predicate(rule_set: &mut VerificationRuleSet) {
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(ATTRIBUTE_AGE.to_string());
    predicate_rule.set_predicate_type("GE".to_string());
    predicate_rule.set_predicate_value(18);
    rule_set.mut_attribute_predicate().push(predicate_rule);
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(ATTRIBUTE_AGE.to_string());
    predicate_rule.set_predicate_type("LE".to_string());
    predicate_rule.set_predicate_value(40);
    rule_set.mut_attribute_predicate().push(predicate_rule);
}

fn user_prove_rule_set(
    new_certificate_signature: &CertificateSignature,
    certificate_attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
    user_private_key_str: &str,
    rule_set: &mut VerificationRuleSet,
) -> Result<VerifyRequest, WedprError>
{
    // In most cases, this nonce should be provided by the verifier to prevent
    // replaying attacks.
    let verification_nonce_str = utils::get_random_nonce_str().unwrap();
    user::prove_selective_disclosure(
        rule_set,
        new_certificate_signature,
        certificate_attribute_dict,
        certificate_template,
        user_private_key_str,
        &verification_nonce_str,
    )
}

fn verifier_verify_rule_set(
    rule_set: &mut VerificationRuleSet,
    request: &VerifyRequest,
) -> bool
{
    verifier::verify_selective_disclosure(&rule_set, &request).unwrap()
}

// Utility functions
// TODO: Extract those common functions to solution utility.
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

fn wait_for_number(error_message: &str, upper_limit: i64) -> u64 {
    let mut input = wait_for_input();
    let mut input_num = input.parse::<i64>();
    loop {
        match input_num {
            // TODO: Enable negative input in the demo.
            Ok(v) if (v >= 0) && (v <= upper_limit) => return v as u64,
            _ => {
                print_alert(error_message);
                input = wait_for_input();
                input_num = input.parse::<i64>();
            },
        }
    }
}

fn wait_for_number_with_limit_cn(upper_limit: i64) -> u64 {
    wait_for_number("请输入有效数字：", upper_limit)
}

fn wait_for_number_with_limit_en(upper_limit: i64) -> u64 {
    wait_for_number("Please input a valid number:", upper_limit)
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
