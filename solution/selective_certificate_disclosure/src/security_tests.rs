// Copyright 2026 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use crate::{issuer, user, verifier};
use std::sync::OnceLock;
use wedpr_s_protos::generated::scd::*;

fn trusted_template() -> &'static (CertificateTemplate, TemplatePrivateKey) {
    static TEMPLATE: OnceLock<(CertificateTemplate, TemplatePrivateKey)> =
        OnceLock::new();
    TEMPLATE.get_or_init(|| {
        let mut schema = CertificateSchema::new();
        schema.mut_attribute_name().push("age".to_owned());
        issuer::make_certificate_template(&schema).unwrap()
    })
}

fn certificate() -> (
    CertificateSignature,
    AttributeDict,
    String,
    String,
    String,
    CertificateSignature,
) {
    let (template, signing_key) = trusted_template();
    let mut attributes = AttributeDict::new();
    let mut pair = StringToStringPair::new();
    pair.set_key("age".to_owned());
    pair.set_value("25".to_owned());
    attributes.mut_pair().push(pair);
    let (request, secret, blinding, user_nonce) =
        user::fill_certificate(&attributes, template).unwrap();
    let (signature, issuer_nonce) = issuer::sign_certificate(
        template,
        signing_key,
        &request,
        "synthetic-user",
        &user_nonce,
    )
    .unwrap();
    let blinded = user::blind_certificate_signature(
        &signature,
        &attributes,
        template,
        &secret,
        &blinding,
        &issuer_nonce,
    )
    .unwrap();
    (
        blinded,
        attributes,
        secret,
        blinding,
        issuer_nonce,
        signature,
    )
}

fn proof_request() -> (VerificationRuleSet, VerifyRequest, String) {
    let (signature, attributes, secret, _, _, _) = certificate();
    let mut rules = VerificationRuleSet::new();
    let mut predicate = Predicate::new();
    predicate.set_attribute_name("age".to_owned());
    predicate.set_predicate_type("GE".to_owned());
    predicate.set_predicate_value(18);
    rules.mut_attribute_predicate().push(predicate);
    let nonce = verifier::get_verification_nonce().unwrap();
    let request = user::prove_selective_disclosure(
        &rules,
        &signature,
        &attributes,
        &trusted_template().0,
        &secret,
        &nonce,
    )
    .unwrap();
    (rules, request, nonce)
}

#[test]
fn legacy_verification_without_issuer_or_challenge_context_fails_closed() {
    // A client can generate this entire issuer/key/certificate/proof chain.
    // Possession of a valid proof alone does not establish trusted attestation.
    let (rules, request, _) = proof_request();
    assert!(verifier::verify_selective_disclosure(&rules, &request).is_err());
}

#[test]
fn verification_uses_the_pinned_issuer_and_server_challenge() {
    let (rules, request, nonce) = proof_request();
    let template = &trusted_template().0;
    assert!(verifier::verify_selective_disclosure_with_context(
        &rules, &request, template, &nonce
    )
    .unwrap());
    let fresh_nonce = verifier::get_verification_nonce().unwrap();
    assert!(verifier::verify_selective_disclosure_with_context(
        &rules,
        &request,
        template,
        &fresh_nonce
    )
    .is_err());
    let mut retagged = request.clone();
    retagged.set_verification_nonce(fresh_nonce.clone());
    assert!(!matches!(
        verifier::verify_selective_disclosure_with_context(
            &rules,
            &retagged,
            template,
            &fresh_nonce
        ),
        Ok(true)
    ));
    let mut wrong_issuer = template.clone();
    wrong_issuer
        .mut_template_public_key()
        .set_key("{}".to_owned());
    assert!(verifier::verify_selective_disclosure_with_context(
        &rules,
        &request,
        &wrong_issuer,
        &nonce
    )
    .is_err());
    let mut substituted = request.clone();
    substituted.set_certificate_template(wrong_issuer);
    assert!(verifier::verify_selective_disclosure_with_context(
        &rules,
        &substituted,
        template,
        &nonce
    )
    .is_err());
}

#[test]
fn predicate_values_cannot_wrap_or_overflow_indy_arithmetic() {
    let (rules, request, nonce) = proof_request();
    let (signature, attributes, secret, _, _, _) = certificate();
    for (kind, value) in [
        ("GE", u64::max_value()),
        ("GT", i64::max_value() as u64),
        ("unknown", 18),
    ] {
        let mut invalid = rules.clone();
        invalid.mut_attribute_predicate()[0]
            .set_predicate_type(kind.to_owned());
        invalid.mut_attribute_predicate()[0].set_predicate_value(value);
        assert!(verifier::verify_selective_disclosure_with_context(
            &invalid,
            &request,
            &trusted_template().0,
            &nonce
        )
        .is_err());
        assert!(user::prove_selective_disclosure(
            &invalid,
            &signature,
            &attributes,
            &trusted_template().0,
            &secret,
            &nonce
        )
        .is_err());
    }
    let mut negative = attributes.clone();
    negative.mut_pair()[0].set_value(i64::min_value().to_string());
    let result = std::panic::catch_unwind(|| {
        user::prove_selective_disclosure(
            &rules,
            &signature,
            &negative,
            &trusted_template().0,
            &secret,
            &nonce,
        )
    });
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());
}

#[test]
fn duplicate_or_missing_attributes_are_rejected_before_signing() {
    let (template, key) = trusted_template();
    let mut attributes = AttributeDict::new();
    let mut pair = StringToStringPair::new();
    pair.set_key("age".to_owned());
    pair.set_value("25".to_owned());
    attributes.mut_pair().push(pair.clone());
    let (mut request, _, _, nonce) =
        user::fill_certificate(&attributes, template).unwrap();
    pair.set_value("99".to_owned());
    attributes.mut_pair().push(pair.clone());
    assert!(user::fill_certificate(&attributes, template).is_err());
    request
        .mut_certificate_attribute_dict()
        .mut_pair()
        .push(pair);
    assert!(issuer::sign_certificate(
        template,
        key,
        &request,
        "synthetic",
        &nonce
    )
    .is_err());
    assert!(user::fill_certificate(&AttributeDict::new(), template).is_err());
}

#[test]
fn invalid_issuer_nonce_returns_error_instead_of_panicking() {
    let (_, attributes, secret, blinding, _, signature) = certificate();
    let incorrect_nonce = verifier::get_verification_nonce().unwrap();
    let outcome = std::panic::catch_unwind(|| {
        user::blind_certificate_signature(
            &signature,
            &attributes,
            &trusted_template().0,
            &secret,
            &blinding,
            &incorrect_nonce,
        )
    });
    assert!(
        outcome.is_ok(),
        "invalid certificate input must not unwind into JNI"
    );
    assert!(outcome.unwrap().is_err());
}

#[test]
fn malformed_subproof_counts_return_errors_without_panicking() {
    let (rules, request, nonce) = proof_request();
    let original: serde_json::Value =
        serde_json::from_str(request.get_verification_proof()).unwrap();
    for count in [0, 2] {
        let mut value = original.clone();
        value["proofs"] = serde_json::Value::Array(
            (0..count).map(|_| original["proofs"][0].clone()).collect(),
        );
        let mut malformed = request.clone();
        malformed.set_verification_proof(value.to_string());
        let outcome = std::panic::catch_unwind(|| {
            verifier::verify_selective_disclosure_with_context(
                &rules,
                &malformed,
                &trusted_template().0,
                &nonce,
            )
        });
        assert!(
            outcome.is_ok(),
            "untrusted proof count must not unwind into JNI"
        );
        assert!(!matches!(outcome.unwrap(), Ok(true)));
    }
}

#[test]
fn malformed_proof_fields_fail_without_unwinding() {
    let (rules, request, nonce) = proof_request();
    let original: serde_json::Value =
        serde_json::from_str(request.get_verification_proof()).unwrap();
    for value in [
        serde_json::Value::Null,
        serde_json::json!(false),
        serde_json::json!(0),
        serde_json::json!(""),
        serde_json::json!("not-a-number"),
        serde_json::json!("-1"),
    ] {
        for field in ["e", "v", "a_prime", "m2"] {
            let mut malformed = original.clone();
            malformed["proofs"][0]["primary_proof"]["eq_proof"][field] =
                value.clone();
            let mut changed = request.clone();
            changed.set_verification_proof(malformed.to_string());
            let outcome = std::panic::catch_unwind(|| {
                verifier::verify_selective_disclosure_with_context(
                    &rules,
                    &changed,
                    &trusted_template().0,
                    &nonce,
                )
            });
            assert!(outcome.is_ok());
            assert!(!matches!(outcome.unwrap(), Ok(true)));
        }
    }
    let mut unsupported = original;
    unsupported["proofs"][0]["non_revoc_proof"] = serde_json::json!({});
    let mut changed = request;
    changed.set_verification_proof(unsupported.to_string());
    assert!(verifier::verify_selective_disclosure_with_context(
        &rules,
        &changed,
        &trusted_template().0,
        &nonce
    )
    .is_err());
}

#[test]
fn duplicate_predicate_proofs_and_oversized_numbers_are_rejected_early() {
    let (rules, request, nonce) = proof_request();
    let original: serde_json::Value =
        serde_json::from_str(request.get_verification_proof()).unwrap();
    let mut duplicate = original.clone();
    let proof = duplicate["proofs"][0]["primary_proof"]["ne_proofs"][0].clone();
    duplicate["proofs"][0]["primary_proof"]["ne_proofs"]
        .as_array_mut()
        .unwrap()
        .push(proof);
    let mut changed = request.clone();
    changed.set_verification_proof(duplicate.to_string());
    assert!(verifier::verify_selective_disclosure_with_context(
        &rules,
        &changed,
        &trusted_template().0,
        &nonce
    )
    .is_err());
    let mut oversized = original;
    oversized["proofs"][0]["primary_proof"]["eq_proof"]["e"] =
        serde_json::json!("9".repeat(100_000));
    changed.set_verification_proof(oversized.to_string());
    assert!(verifier::verify_selective_disclosure_with_context(
        &rules,
        &changed,
        &trusted_template().0,
        &nonce
    )
    .is_err());
    changed.set_verification_proof(
        " ".repeat(4 * 1024 * 1024) + request.get_verification_proof(),
    );
    assert!(verifier::verify_selective_disclosure_with_context(
        &rules,
        &changed,
        &trusted_template().0,
        &nonce
    )
    .is_err());
}
