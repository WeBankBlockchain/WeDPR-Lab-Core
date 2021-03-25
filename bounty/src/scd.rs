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

const DEFAULT_USER_ID: &str = "1001";
const TARGET_ATTRIBUTE: &str = "target";

/// UI flow of SCD bounty playground.
pub fn flow_scd() {
    utils::print_highlight(
        "\n##\n## Opening the gate of SCD bounty playground... ##\n##",
    );
    println!("{}\n", "List of available challenges:");
    utils::print_alert("▶ Enter 1 to select GT predicate: (default option)");
    println!(
        "{}\n",
        "Given a certificate, without reveal its plaintext attribute value \
         v,\nprove a > threshold value t."
    );
    utils::print_alert("▶ Enter 2 to select EQ predicate:");
    println!(
        "{}\n",
        "Given a certificate, without reveal its plaintext attribute value \
         v,\nprove a == threshold value t."
    );
    utils::print_alert("▶ Enter 3 to select GE predicate:");
    println!(
        "{}\n",
        "Given a certificate, without reveal its plaintext attribute value \
         v,\nprove a >= threshold value t."
    );
    println!();

    println!("Your choices: ▼▼▼");
    let mut choice = utils::wait_for_input();
    loop {
        if choice == "1" || choice.is_empty() {
            play_scd_prove_greater();
            break;
        } else if choice == "2" {
            play_scd_prove_equal();
            break;
        } else if choice == "3" {
            play_scd_prove_greater_or_equal();
            break;
        } else {
            utils::print_alert("Invalid input! Please try again:");
            choice = utils::wait_for_input();
        }
    }
}

fn play_scd_prove_greater() {
    // TODO: Refactor the code to reuse the common flow logic.
    utils::print_highlight("Loading the challenge for GT predicate...");
    let (certificate_template, template_private_key) =
        issuer_make_certificate_template();
    utils::print_wide(
        "Challenge goals:\nFind malicious plaintext v, t, which lead to:\n1) \
         proving and verifying GT predicate succeeded but v <= t\n2) proving \
         or verifying GT predicate failed but v > t",
    );

    utils::print_alert("Please enter v from [0, 2^32): ▼▼▼");
    let value = utils::wait_for_number_en();
    let mut certificate_attribute_dict = AttributeDict::new();

    utils::print_alert("Please enter t from [0, 2^32): ▼▼▼");
    let threshold = utils::wait_for_number_en();
    let mut rule_set = make_greater_predicate_rule(threshold);

    let proof_or_err = generate_predicate_proof(
        &mut certificate_attribute_dict,
        &certificate_template,
        template_private_key,
        value,
        &mut rule_set,
    );

    let mut is_rule_satisfied = true;
    match proof_or_err {
        Ok(v) => {
            println!("✓ Proof generated");
            if verifier_verify_rule_set(&mut rule_set, &v) {
                println!(
                    "✓ Proof verification succeeded due to your inputs {} > {}",
                    value, threshold,
                );
            } else {
                println!(
                    "✗ Proof verification failed due to your inputs: {} <= {}",
                    value, threshold,
                );
                is_rule_satisfied = false;
            }
        },
        Err(_) => {
            println!(
                "✗ Proof generation failed due to your inputs: {} <= {}",
                value, threshold,
            );
            is_rule_satisfied = false;
        },
    };

    if (value <= threshold && is_rule_satisfied)
        || (value > threshold && !is_rule_satisfied)
    {
        utils::print_alert(
            "Congratulation! You found malicious input breaking the algorithm.",
        );
        println!("The found inputs: v = {}\nt = {}\n", value, threshold,);
    } else {
        utils::print_try_again();
    }
}

fn play_scd_prove_equal() {
    // TODO: Refactor the code to reuse the common flow logic.
    utils::print_highlight("Loading the challenge for EQ predicate...");
    let (certificate_template, template_private_key) =
        issuer_make_certificate_template();
    utils::print_wide(
        "Challenge goals:\nFind malicious plaintext v, t, which lead to:\n1) \
         proving and verifying EQ predicate succeeded but v != t\n2) proving \
         or verifying EQ predicate failed but v == t",
    );

    utils::print_alert("Please enter v from [0, 2^32): ▼▼▼");
    let value = utils::wait_for_number_en();
    let mut certificate_attribute_dict = AttributeDict::new();

    utils::print_alert("Please enter t from [0, 2^32): ▼▼▼");
    let threshold = utils::wait_for_number_en();
    let mut rule_set = make_equal_predicate_rule(threshold);

    let proof_or_err = generate_predicate_proof(
        &mut certificate_attribute_dict,
        &certificate_template,
        template_private_key,
        value,
        &mut rule_set,
    );

    let mut is_rule_satisfied = true;
    match proof_or_err {
        Ok(v) => {
            println!("✓ Proof generated");
            if verifier_verify_rule_set(&mut rule_set, &v) {
                println!(
                    "✓ Proof verification succeeded due to your inputs {} == \
                     {}",
                    value, threshold,
                );
            } else {
                println!(
                    "✗ Proof verification failed due to your inputs: {} != {}",
                    value, threshold,
                );
                is_rule_satisfied = false;
            }
        },
        Err(_) => {
            println!(
                "✗ Proof generation failed due to your inputs: {} != {}",
                value, threshold,
            );
            is_rule_satisfied = false;
        },
    };

    if (value <= threshold && is_rule_satisfied)
        || (value > threshold && !is_rule_satisfied)
    {
        utils::print_alert(
            "Congratulation! You found malicious input breaking the algorithm.",
        );
        println!("The found inputs: v = {}\nt = {}\n", value, threshold,);
    } else {
        utils::print_try_again();
    }
}

fn play_scd_prove_greater_or_equal() {
    // TODO: Refactor the code to reuse the common flow logic.
    utils::print_highlight("Loading the challenge for GE predicate...");
    let (certificate_template, template_private_key) =
        issuer_make_certificate_template();
    utils::print_wide(
        "Challenge goals:\nFind malicious plaintext v, t, which lead to:\n1) \
         proving and verifying GE predicate succeeded but v < t\n2) proving \
         or verifying GE predicate failed but v >= t",
    );

    utils::print_alert("Please enter v from [0, 2^32): ▼▼▼");
    let value = utils::wait_for_number_en();
    let mut certificate_attribute_dict = AttributeDict::new();

    utils::print_alert("Please enter t from [0, 2^32): ▼▼▼");
    let threshold = utils::wait_for_number_en();
    let mut rule_set = make_greater_or_equal_predicate_rule(threshold);

    let proof_or_err = generate_predicate_proof(
        &mut certificate_attribute_dict,
        &certificate_template,
        template_private_key,
        value,
        &mut rule_set,
    );

    let mut is_rule_satisfied = true;
    match proof_or_err {
        Ok(v) => {
            println!("✓ Proof generated");
            if verifier_verify_rule_set(&mut rule_set, &v) {
                println!(
                    "✓ Proof verification succeeded due to your inputs {} >= \
                     {}",
                    value, threshold,
                );
            } else {
                println!(
                    "✗ Proof verification failed due to your inputs: {} < {}",
                    value, threshold,
                );
                is_rule_satisfied = false;
            }
        },
        Err(_) => {
            println!(
                "✗ Proof generation failed due to your inputs: {} < {}",
                value, threshold,
            );
            is_rule_satisfied = false;
        },
    };

    if (value <= threshold && is_rule_satisfied)
        || (value > threshold && !is_rule_satisfied)
    {
        utils::print_alert(
            "Congratulation! You found malicious input breaking the algorithm.",
        );
        println!("The found inputs: v = {}\nt = {}\n", value, threshold,);
    } else {
        utils::print_try_again();
    }
}

fn make_greater_predicate_rule(threshold: u64) -> VerificationRuleSet {
    let mut rule_set = VerificationRuleSet::new();
    // Set threshold predicate.
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(TARGET_ATTRIBUTE.to_string());
    predicate_rule.set_predicate_type("GT".to_string());
    predicate_rule.set_predicate_value(threshold);
    rule_set.mut_attribute_predicate().push(predicate_rule);
    rule_set
}

fn make_equal_predicate_rule(threshold: u64) -> VerificationRuleSet {
    let mut rule_set = VerificationRuleSet::new();
    // Set threshold predicate.
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(TARGET_ATTRIBUTE.to_string());
    predicate_rule.set_predicate_type("EQ".to_string());
    predicate_rule.set_predicate_value(threshold);
    rule_set.mut_attribute_predicate().push(predicate_rule);
    rule_set
}

fn make_greater_or_equal_predicate_rule(threshold: u64) -> VerificationRuleSet {
    let mut rule_set = VerificationRuleSet::new();
    // Set threshold predicate.
    let mut predicate_rule = Predicate::new();
    predicate_rule.set_attribute_name(TARGET_ATTRIBUTE.to_string());
    predicate_rule.set_predicate_type("GE".to_string());
    predicate_rule.set_predicate_value(threshold);
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
    user_fill_certificate_attribute(certificate_attribute_dict, value);
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

fn issuer_make_certificate_template(
) -> (CertificateTemplate, TemplatePrivateKey) {
    let mut schema = CertificateSchema::new();
    schema
        .mut_attribute_name()
        .push(TARGET_ATTRIBUTE.to_string());
    let (certificate_template, template_private_key) =
        issuer::make_certificate_template(&schema).unwrap();
    (certificate_template, template_private_key)
}

fn user_fill_certificate_attribute(
    certificate_attribute_dict: &mut AttributeDict,
    attribute: u64,
) {
    let mut attribute_kv = StringToStringPair::new();
    attribute_kv.set_key(TARGET_ATTRIBUTE.to_string());
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

fn verifier_verify_rule_set(
    rule_set: &mut VerificationRuleSet,
    request: &VerifyRequest,
) -> bool {
    verifier::verify_selective_disclosure(&rule_set, &request).unwrap()
}
