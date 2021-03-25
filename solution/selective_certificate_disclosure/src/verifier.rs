// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a certificate verifier.

use crate::utils;
use wedpr_indy_crypto::cl::verifier;
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::scd::{
    AttributeDict, StringToStringPair, VerificationRuleSet, VerifyRequest,
};

/// Gets revealed attributes selected by a user.
/// Before calling this function, verify_selective_disclosure should be called
/// to verify the validity of the VerifyRequest.
pub fn get_revealed_attributes(
    verify_request: &VerifyRequest,
) -> Result<AttributeDict, WedprError> {
    let proof: wedpr_indy_crypto::cl::Proof =
        utils::safe_deserialize(verify_request.get_verification_proof())?;
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

/// Verifies the validity of a VerifyRequest containing selected attribute
/// values and their value predicates.
pub fn verify_selective_disclosure(
    rule_set: &VerificationRuleSet,
    verify_request: &VerifyRequest,
) -> Result<bool, WedprError> {
    let (certificate_schema, non_certificate_schema) =
        utils::build_certificate_schema(
            verify_request
                .get_certificate_template()
                .get_certificate_schema(),
        )?;

    let proof: wedpr_indy_crypto::cl::Proof =
        utils::safe_deserialize(verify_request.get_verification_proof())?;

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
                        wedpr_println!(
                            "predicate_eq_value not equal \
                             predicate.get_value(), expected = {:?}, \
                             read_value = {:?}",
                            expected,
                            read_value
                        );
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
            verify_request
                .get_certificate_template()
                .get_template_public_key()
                .get_key(),
        )?;

    let proof_request_nonce: wedpr_indy_crypto::cl::Nonce =
        utils::safe_deserialize(verify_request.get_verification_nonce())?;

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
