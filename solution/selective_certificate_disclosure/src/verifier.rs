// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a certificate verifier.

use crate::utils;
use wedpr_indy_crypto::cl::verifier;
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::scd::{
    AttributeDict, CertificateTemplate, StringToStringPair,
    VerificationRuleSet, VerifyRequest,
};

/// Gets revealed attributes selected by a user.
/// Before calling this function, verify_selective_disclosure_with_context
/// must return true for this VerifyRequest and the verifier's trusted context.
pub fn get_revealed_attributes(
    verify_request: &VerifyRequest,
) -> Result<AttributeDict, WedprError> {
    let proof: wedpr_indy_crypto::cl::Proof =
        utils::deserialize_certificate_proof(
            verify_request.get_verification_proof(),
        )?;
    let eq_value = utils::safe_indy_check(proof.get_revealed_attrs_value())?;
    let mut attrs = AttributeDict::new();
    for (attr, value) in eq_value {
        let mut pair = StringToStringPair::new();
        pair.set_key(attr);
        pair.set_value(utils::safe_indy_check(value.to_dec())?);
        attrs.mut_pair().push(pair);
    }
    Ok(attrs)
}

/// Deprecated entry point without trusted issuer or challenge context.
/// It always fails closed; use verify_selective_disclosure_with_context.
pub fn verify_selective_disclosure(
    _rule_set: &VerificationRuleSet,
    _verify_request: &VerifyRequest,
) -> Result<bool, WedprError> {
    Err(WedprError::VerificationError)
}

/// Verify against the issuer template and challenge saved by the verifier.
/// The caller must consume the challenge atomically once verification succeeds.
pub fn verify_selective_disclosure_with_context(
    rule_set: &VerificationRuleSet,
    verify_request: &VerifyRequest,
    trusted_template: &CertificateTemplate,
    expected_nonce: &str,
) -> Result<bool, WedprError> {
    if expected_nonce.is_empty()
        || verify_request.get_verification_nonce() != expected_nonce
        || verify_request.get_certificate_template() != trusted_template
    {
        return Err(WedprError::VerificationError);
    }
    utils::validate_rule_set(rule_set)?;
    let (certificate_schema, non_certificate_schema) =
        utils::build_certificate_schema(
            trusted_template.get_certificate_schema(),
        )?;

    let proof: wedpr_indy_crypto::cl::Proof =
        utils::deserialize_certificate_proof(
            verify_request.get_verification_proof(),
        )?;

    let eq_value = utils::safe_indy_check(proof.get_revealed_attrs_value())?;

    let mut sub_proof_request_builder = utils::safe_indy_check(
        verifier::Verifier::new_sub_proof_request_builder(),
    )?;
    for revealed in rule_set.get_revealed_attribute_name() {
        utils::safe_indy_check(
            sub_proof_request_builder.add_revealed_attr(revealed),
        )?;
    }
    for predicate in rule_set.get_attribute_predicate() {
        if predicate.get_predicate_type() == "EQ" {
            for (proof_attr, value) in &eq_value {
                if proof_attr == predicate.get_attribute_name() {
                    let expected = utils::safe_indy_check(value.to_dec())?;
                    let read_value = predicate.get_predicate_value() as i64;
                    if !(expected.eq(&read_value.to_string())) {
                        return Err(WedprError::VerificationError);
                    }
                }
            }
            utils::safe_indy_check(
                sub_proof_request_builder
                    .add_revealed_attr(predicate.get_attribute_name()),
            )?;
        } else {
            utils::safe_indy_check(sub_proof_request_builder.add_predicate(
                predicate.get_attribute_name(),
                predicate.get_predicate_type(),
                predicate.get_predicate_value() as i64,
            ))?;
        }
    }

    let sub_proof_request =
        utils::safe_indy_check(sub_proof_request_builder.finalize())?;

    let cred_pub_key: wedpr_indy_crypto::cl::CredentialPublicKey =
        utils::safe_deserialize(
            trusted_template.get_template_public_key().get_key(),
        )?;

    let proof_request_nonce: wedpr_indy_crypto::cl::Nonce =
        utils::safe_deserialize(expected_nonce)?;

    let mut proof_verifier =
        utils::safe_indy_check(verifier::Verifier::new_proof_verifier())?;

    utils::safe_indy_check(proof_verifier.add_sub_proof_request(
        &sub_proof_request,
        &certificate_schema,
        &non_certificate_schema,
        &cred_pub_key,
        None,
        None,
    ))?;

    utils::safe_indy_check(proof_verifier.verify(&proof, &proof_request_nonce))
}

/// Generates a new nonce as the challenge for a user to generate a fresh proof.
pub fn get_verification_nonce() -> Result<String, WedprError> {
    utils::get_random_nonce_str()
}
