// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Playground of SCD bounty targets.

use super::utils;
use wedpr_l_utils::error::WedprError;
extern crate wedpr_s_selective_certificate_disclosure;
use wedpr_s_selective_certificate_disclosure::{issuer, user, verifier};
extern crate wedpr_s_protos;
use wedpr_s_protos::generated::scd::{
    AttributeDict, CertificateSchema, CertificateSignature,
    CertificateTemplate, Predicate, StringToStringPair, TemplatePrivateKey,
    VerificationRuleSet, VerifyRequest,
};

const DEFAULT_USER_ID: &str = "12345";
const ATTRIBUTE: &str = "attribute";

pub fn flow_scd() {
    utils::print_highlight("## 欢迎来到SCD零知识断言证明靶场! ##");
    println!(
        "{}\n",
        "在此，我们提供了5种数值逻辑关系的零知识断言证明，分别为："
    );
    utils::print_alert("▶ 1. 大于关系的断言证明效果:");
    println!(
        "{}\n",
        "给定密文凭证，在不解密的前提下，验证密文凭证中的证书属性A\
         是否大于认证要求的最小值。"
    );
    utils::print_alert("▶ 2. 小于关系的断言证明效果:");
    println!(
        "{}\n",
        "给定密文凭证，在不解密的前提下，\
         验证密文凭证中的证书属性A是否小于认证要求的最大值。"
    );
    utils::print_alert("▶ 3. 相等关系的断言证明效果:");
    println!(
        "{}\n",
        "给定密文凭证，在不解密的前提下，\
         验证密文凭证中的证书属性A是否等于认证要求的属性值。"
    );
    utils::print_alert("▶ 4. 大于等于关系的断言证明效果:");
    println!(
        "{}\n",
        "给定密文凭证，在不解密的前提下，验证密文凭证中的证书属性A\
         是否大于等于认证要求的最小值。"
    );
    utils::print_alert("▶ 5. 小于等于关系的断言证明效果:");
    println!(
        "{}\n",
        "给定密文凭证，在不解密的前提下，验证密文凭证中的证书属性A\
         是否小于等于认证要求的最大值。"
    );
    println!();

    println!("现在请选择待挑战的零知识断言证明编号：▼▼▼");
    utils::print_alert5(
        "▶ 输入 \"1\" 选择相等关系的断言证明（默认选项）",
        "▶ 输入 \"2\" 选择大于关系的断言证明",
        "▶ 输入 \"3\" 选择小于关系的断言证明",
        "▶ 输入 \"4\" 选择大于等于关系的断言证明",
        "▶ 输入 \"5\" 选择小于等于关系的断言证明",
    );

    let mut choice = utils::wait_for_input();
    loop {
        if choice == "1" || choice.is_empty() {
            play_scd_prove_equal();
            break;
        } else if choice == "2" {
            play_scd_prove_greater();
            break;
        } else if choice == "3" {
            play_scd_prove_less();
            break;
        } else if choice == "4" {
            play_scd_prove_greater_or_equal();
            break;
        } else if choice == "5" {
            play_scd_prove_less_or_equal();
            break;
        } else {
            utils::print_alert("输入错误！请重新输入：");
            choice = utils::wait_for_input();
        }
    }
}

pub fn play_scd_prove_greater() {
    utils::print_highlight("大于断言证明靶场 载入中 。。。");
    let (certificate_template, template_private_key) =
        issuer_init_certificate_template();
    println!(
        "漏洞目标：找到一组数值，\
         输入认证要求的证书属性最小值min和证书属性值value，"
    );
    utils::print_alert3(
        "▶ 满足value <= min，但能够生成且通过大于断言证明；",
        "▶ 满足value > min，但不能生成大于断言证明;",
        "▶ 满足value > min，能够生成大于断言证明，但无法通过大于断言验证。",
    );

    utils::print_alert("现在请输入认证要求的证书属性最小值min：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let min = utils::wait_for_number_cn();
    let mut rule_set = generate_greater_predicate_rule(min);

    utils::print_alert("现在请输入密文证书中的属性值value：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let value = utils::wait_for_number_cn();
    let mut certificate_attribute_dict = AttributeDict::new();

    let predicate_proof = generate_predicate_proof(
        &mut certificate_attribute_dict,
        &certificate_template,
        template_private_key,
        value,
        &mut rule_set,
    );

    let mut satisfy_predication = true;
    let _request = match predicate_proof {
        Ok(v) => {
            println!("✓ 大于断言证明生成成功。");
            let verify_predication = verify_rule_set(&mut rule_set, &v);

            if verify_predication {
                println!("✓ 大于断言证明验证成功。");
                println!(
                    "您的输入：(value: {}) > (min: \
                     {})，所以成功生成且通过了大于断言验证。",
                    value, min,
                );
                utils::print_failure();
            } else {
                println!("X 大于断言证明验证失败。");
                println!(
                    "您的输入：(value: {}) =< (min: \
                     {})，所以未通过大于断言验证。",
                    value, min,
                );
                utils::print_failure();
            }
            satisfy_predication = satisfy_predication == verify_predication;
        },
        Err(_) => {
            utils::print_wide("X 大于断言证明生成失败。");
            println!(
                "您的输入：(value: {}) =< (min: \
                 {})，所以未能生成大于断言证明。",
                value, min,
            );
            utils::print_failure();
            satisfy_predication = false;
        },
    };

    if (value <= min && satisfy_predication)
        || (value > min && !satisfy_predication)
    {
        utils::print_alert("恭喜您，找到了大于断言证明的漏洞输入！");
        println!("您找到的漏洞输入为：\nvalue = {}\nmin = {}\n", value, min,);
    } else {
        return;
    }
}

pub fn play_scd_prove_less() {
    utils::print_highlight("小于断言证明靶场 载入中 。。。");
    let (certificate_template, template_private_key) =
        issuer_init_certificate_template();

    println!(
        "漏洞目标：找到一组数值，\
         输入认证要求的证书属性最大值max和证书属性值value，"
    );
    utils::print_alert3(
        "▶ 满足value >= max，但能够生成且通过小于断言证明；",
        "▶ 满足value < max，但不能生成小于断言证明;",
        "▶ 满足value < max，能够生成小于断言证明，但无法通过小于断言验证。",
    );

    utils::print_alert("现在请输入认证要求的证书属性最大值max：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let max = utils::wait_for_number_cn();
    let mut rule_set = generate_less_predicate_rule(max);

    utils::print_alert("现在请输入密文证书中的属性值value：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let value = utils::wait_for_number_cn();
    let mut certificate_attribute_dict = AttributeDict::new();

    let predicate_proof = generate_predicate_proof(
        &mut certificate_attribute_dict,
        &certificate_template,
        template_private_key,
        value,
        &mut rule_set,
    );

    let mut satisfy_predication = true;
    let _request = match predicate_proof {
        Ok(v) => {
            println!("✓ 小于断言证明生成成功。");
            let verify_predication = verify_rule_set(&mut rule_set, &v);
            if verify_predication {
                println!("✓ 小于断言证明验证成功。");
                println!(
                    "您的输入：(value: {}) < (max: \
                     {})，所以成功生成且通过了小于断言验证。",
                    value, max,
                );
                utils::print_failure();
            } else {
                println!("X 小于断言证明验证失败。");
                println!(
                    "您的输入：(value: {}) >= (max: \
                     {})，所以未通过小于断言验证。",
                    value, max,
                );
                utils::print_failure();
            }
            satisfy_predication = satisfy_predication == verify_predication;
        },
        Err(_) => {
            utils::print_wide("X 小于断言证明生成失败。");
            println!(
                "您的输入：(value: {}) >= (max: \
                 {})，所以未能生成小于断言证明。",
                value, max,
            );
            utils::print_failure();
            satisfy_predication = false;
        },
    };
    if (value > max && satisfy_predication)
        || (value <= max && !satisfy_predication)
    {
        utils::print_alert("恭喜您，找到了小于断言证明的漏洞输入！");
        println!("您找到的漏洞输入为：\nvalue = {}\nmax = {}\n", value, max,);
    } else {
        return;
    }
}

pub fn play_scd_prove_equal() {
    utils::print_highlight("相等断言证明靶场 载入中 。。。");
    let (certificate_template, template_private_key) =
        issuer_init_certificate_template();

    println!(
        "漏洞目标：找到一组数值，输入认证要求的证书属性值expected \
         value和证书属性值value，"
    );
    utils::print_alert3(
        "▶ 满足value != expected value，但能够生成且通过相等断言证明；",
        "▶ 满足value = expected value，但不能生成相等断言证明;",
        "▶ 满足value = expected \
         value，能够生成相等断言证明，但无法通过相等断言验证。",
    );

    utils::print_alert("现在请输入认证要求的证书属性值expected value：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let expected_value = utils::wait_for_number_cn();
    let mut rule_set = generate_equal_predicate_rule(expected_value);

    utils::print_alert("现在请输入密文证书中的属性值value：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let value = utils::wait_for_number_cn();
    let mut certificate_attribute_dict = AttributeDict::new();

    let predicate_proof = generate_predicate_proof(
        &mut certificate_attribute_dict,
        &certificate_template,
        template_private_key,
        value,
        &mut rule_set,
    );

    let mut satisfy_predication = true;
    let _request = match predicate_proof {
        Ok(v) => {
            println!("✓ 相等断言证明生成成功。");
            let verify_predication = verify_rule_set(&mut rule_set, &v);
            if verify_predication {
                println!("✓ 相等断言证明验证成功。");
                println!(
                    "您的输入：(value: {}) = (expected_value: \
                     {})，所以成功生成且通过了相等断言验证。",
                    value, expected_value,
                );
                utils::print_failure();
            } else {
                println!("X 相等断言证明验证失败。");
                println!(
                    "您的输入：(value: {}) != (expected_value: \
                     {})，所以未通过相等断言验证。",
                    value, expected_value,
                );
                utils::print_failure();
            }
            satisfy_predication = satisfy_predication == verify_predication;
        },
        Err(_) => {
            utils::print_wide("X 相等断言证明生成失败。");
            println!(
                "您的输入：(value: {}) != (expected_value: \
                 {})，所以未能生成相等断言证明。",
                value, expected_value,
            );
            utils::print_failure();
            satisfy_predication = false;
        },
    };
    if (value != expected_value && satisfy_predication)
        || (value == expected_value && !satisfy_predication)
    {
        utils::print_alert("恭喜您，找到了相等断言证明的漏洞输入！");
        println!(
            "您找到的漏洞输入为：\nvalue = {}\nexpected_value = {}\n",
            value, expected_value,
        );
    } else {
        return;
    }
}

pub fn play_scd_prove_greater_or_equal() {
    utils::print_highlight("大于等于断言证明靶场 载入中 。。。");
    let (certificate_template, template_private_key) =
        issuer_init_certificate_template();
    println!(
        "漏洞目标：找到一组数值，\
         输入认证要求的证书属性最小值min和证书属性值value，"
    );
    utils::print_alert3(
        "▶ 满足value < min，但能够生成且通过大于等于断言证明；",
        "▶ 满足value >= min，但不能生成大于等于断言证明;",
        "▶ 满足value >= min，能够生成大于等于断言证明，但无法通过大于等于断言验证。",
    );

    utils::print_alert("现在请输入认证要求的证书属性最小值min：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let min = utils::wait_for_number_cn();
    let mut rule_set = generate_greater_predicate_rule(min);

    utils::print_alert("现在请输入密文证书中的属性值value：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let value = utils::wait_for_number_cn();
    let mut certificate_attribute_dict = AttributeDict::new();

    let predicate_proof = generate_predicate_proof(
        &mut certificate_attribute_dict,
        &certificate_template,
        template_private_key,
        value,
        &mut rule_set,
    );

    let mut satisfy_predication = true;
    let _request = match predicate_proof {
        Ok(v) => {
            println!("✓ 大于等于断言证明生成成功。");
            let verify_predication = verify_rule_set(&mut rule_set, &v);

            if verify_predication {
                println!("✓ 大于等于断言证明验证成功。");
                println!(
                    "您的输入：(value: {}) >= (min: \
                     {})，所以成功生成且通过了大于断言验证。",
                    value, min,
                );
                utils::print_failure();
            } else {
                println!("X 大于等于断言证明验证失败。");
                println!(
                    "您的输入：(value: {}) < (min: \
                     {})，所以未通过大于等于断言验证。",
                    value, min,
                );
                utils::print_failure();
            }
            satisfy_predication = satisfy_predication == verify_predication;
        },
        Err(_) => {
            utils::print_wide("X 大于等于断言证明生成失败。");
            println!(
                "您的输入：(value: {}) < (min: \
                 {})，所以未能生成大于等于断言证明。",
                value, min,
            );
            utils::print_failure();
            satisfy_predication = false;
        },
    };

    if (value <= min && satisfy_predication)
        || (value > min && !satisfy_predication)
    {
        utils::print_alert("恭喜您，找到了大于等于断言证明的漏洞输入！");
        println!("您找到的漏洞输入为：\nvalue = {}\nmin = {}\n", value, min,);
    } else {
        return;
    }
}

pub fn play_scd_prove_less_or_equal() {
    utils::print_highlight("小于等于断言证明靶场 载入中 。。。");
    let (certificate_template, template_private_key) =
        issuer_init_certificate_template();
    println!(
        "漏洞目标：找到一组数值，\
         输入认证要求的证书属性最大值max和证书属性值value，"
    );
    utils::print_alert3(
        "▶ 满足value > max，但能够生成且通过小于等于断言证明；",
        "▶ 满足value <= min，但不能生成小于等于断言证明;",
        "▶ 满足value <= min，能够生成小于等于断言证明，但无法通过小于等于断言验证。",
    );

    utils::print_alert("现在请输入认证要求的证书属性最大值max：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let max = utils::wait_for_number_cn();
    let mut rule_set = generate_less_predicate_rule(max);

    utils::print_alert("现在请输入密文证书中的属性值value：▼▼▼");
    utils::print_highlight("输入范围为：[0, 2^32)。");
    let value = utils::wait_for_number_cn();
    let mut certificate_attribute_dict = AttributeDict::new();

    let predicate_proof = generate_predicate_proof(
        &mut certificate_attribute_dict,
        &certificate_template,
        template_private_key,
        value,
        &mut rule_set,
    );

    let mut satisfy_predication = true;
    let _request = match predicate_proof {
        Ok(v) => {
            println!("✓ 小于等于断言证明生成成功。");
            let verify_predication = verify_rule_set(&mut rule_set, &v);
            if verify_predication {
                println!("✓ 小于等于断言证明验证成功。");
                println!(
                    "您的输入：(value: {}) <= (max: \
                     {})，所以成功生成且通过了小于等于断言验证。",
                    value, max,
                );
                utils::print_failure();
            } else {
                println!("X 小于等于断言证明验证失败。");
                println!(
                    "您的输入：(value: {}) >= (max: \
                     {})，所以未通过小于等于断言验证。",
                    value, max,
                );
                utils::print_failure();
            }
            satisfy_predication = satisfy_predication == verify_predication;
        },
        Err(_) => {
            utils::print_wide("X 小于等于断言证明生成失败。");
            println!(
                "您的输入：(value: {}) > (max: \
                 {})，所以未能生成小于等于断言证明。",
                value, max,
            );
            utils::print_failure();
            satisfy_predication = false;
        },
    };
    if (value > max && satisfy_predication)
        || (value <= max && !satisfy_predication)
    {
        utils::print_alert("恭喜您，找到了小于等于断言证明的漏洞输入！");
        println!("您找到的漏洞输入为：\nvalue = {}\nmax = {}\n", value, max,);
    } else {
        return;
    }
}

fn generate_equal_predicate_rule(reference_value: u64) -> VerificationRuleSet {
    let mut rule_set = VerificationRuleSet::new();
    // Set threshold predicate.
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(ATTRIBUTE.to_string());
    predicate_rule.set_predicate_type("EQ".to_string());
    predicate_rule.set_predicate_value(reference_value);
    rule_set.mut_attribute_predicate().push(predicate_rule);
    rule_set
}

fn generate_greater_predicate_rule(
    reference_value: u64,
) -> VerificationRuleSet {
    let mut rule_set = VerificationRuleSet::new();
    // Set threshold predicate.
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(ATTRIBUTE.to_string());
    predicate_rule.set_predicate_type("GT".to_string());
    predicate_rule.set_predicate_value(reference_value);
    rule_set.mut_attribute_predicate().push(predicate_rule);
    rule_set
}

fn generate_less_predicate_rule(reference_value: u64) -> VerificationRuleSet {
    let mut rule_set = VerificationRuleSet::new();
    // Set threshold predicate.
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(ATTRIBUTE.to_string());
    predicate_rule.set_predicate_type("LT".to_string());
    predicate_rule.set_predicate_value(reference_value);
    rule_set.mut_attribute_predicate().push(predicate_rule);
    rule_set
}
fn generate_predicate_proof(
    certificate_attribute_dict: &mut AttributeDict,
    certificate_template: &CertificateTemplate,
    template_private_key: TemplatePrivateKey,
    value: u64,
    rule_set: &mut VerificationRuleSet,
) -> Result<VerifyRequest, WedprError> {
    user_fill_attribute(certificate_attribute_dict, value);
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

    let (certificate_signature, issuer_nonce_str) = issuer::sign_certificate(
        &certificate_template,
        &template_private_key,
        &sign_certificate_request,
        &DEFAULT_USER_ID.to_string(),
        &user_nonce_str,
    )
    .unwrap();

    let new_certificate_signature = user::blind_certificate_signature(
        &certificate_signature,
        &certificate_attribute_dict,
        &certificate_template,
        &user_private_key_str,
        &certificate_secrets_blinding_factors_str,
        &issuer_nonce_str,
    )
    .unwrap();
    let request_result = user_prove_rule_set(
        &new_certificate_signature,
        &certificate_attribute_dict,
        &certificate_template,
        &user_private_key_str,
        rule_set,
    );
    request_result
}

pub fn issuer_init_certificate_template(
) -> (CertificateTemplate, TemplatePrivateKey) {
    let mut schema = CertificateSchema::new();
    schema.mut_attribute_name().push(ATTRIBUTE.to_string());
    let (certificate_template, template_private_key) =
        issuer::make_certificate_template(&schema).unwrap();
    (certificate_template, template_private_key)
}

fn user_fill_attribute(
    certificate_attribute_dict: &mut AttributeDict,
    attribute: u64,
) {
    let mut attribute_kv = StringToStringPair::new();
    attribute_kv.set_key(ATTRIBUTE.to_string());
    attribute_kv.set_value(attribute.to_string());
    certificate_attribute_dict.mut_pair().push(attribute_kv);
}

fn user_prove_rule_set(
    new_certificate_signature: &CertificateSignature,
    certificate_attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
    user_private_key_str: &str,
    rule_set: &mut VerificationRuleSet,
) -> Result<VerifyRequest, WedprError> {
    // In most cases, this nonce should be provided by the verifier to prevent
    // replaying attacks.
    let verification_nonce_str = verifier::get_verification_nonce().unwrap();
    user::prove_selective_disclosure(
        rule_set,
        new_certificate_signature,
        certificate_attribute_dict,
        certificate_template,
        user_private_key_str,
        &verification_nonce_str,
    )
}

fn verify_rule_set(
    rule_set: &mut VerificationRuleSet,
    request: &VerifyRequest,
) -> bool {
    verifier::verify_selective_disclosure(&rule_set, &request).unwrap()
}
