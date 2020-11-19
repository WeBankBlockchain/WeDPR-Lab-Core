// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of selective_disclosure solution.

use crate::utils;
use indy_crypto::cl::verifier;
use wedpr_protos::generated::selective_disclosure::{
    RevealedAttributeInfo, StringToStringPair, VerificationRequest,
    VerificationRule,
};
use wedpr_utils::error::WedprError;

/// Verifier get revealed attributions from verification request used by
/// selective disclosure solution.
pub fn get_revealed_attrs_from_verification_request(
    request: &VerificationRequest,
) -> Result<RevealedAttributeInfo, WedprError> {
    let proof: indy_crypto::cl::Proof =
        utils::convert_deserialize(request.get_verification_proof())?;
    let eq_value = utils::convert_error(proof.get_revealed_attrs_value())?;
    let mut attrs = RevealedAttributeInfo::new();
    for (attr, value) in eq_value {
        let mut pair = StringToStringPair::new();
        pair.set_key(attr);
        pair.set_value(utils::convert_error(value.to_dec())?);
        attrs.mut_attr().push(pair);
    }
    Ok(attrs)
}

/// Verifier verify proof with verification request used by selective disclosure
/// solution.
pub fn verify_proof(
    rules: &VerificationRule,
    request: &VerificationRequest,
) -> Result<bool, WedprError>
{
    let (credential_schema, non_credential_schema) =
        utils::build_credential_schema(
            request.get_credential_template().get_credential_schema(),
        )?;

    let proof: indy_crypto::cl::Proof =
        utils::convert_deserialize(request.get_verification_proof())?;

    let eq_value = utils::convert_error(proof.get_revealed_attrs_value())?;

    let mut sub_proof_request_builder = utils::convert_error(
        verifier::Verifier::new_sub_proof_request_builder(),
    )?;
    for revealed in rules.get_revealed_attribute() {
        utils::convert_error(
            sub_proof_request_builder.add_revealed_attr(revealed),
        )?;
    }
    for predicate in rules.get_predicate_attribute() {
        if predicate.get_predicate_type() == "EQ" {
            for (proof_attr, value) in &eq_value {
                if proof_attr == predicate.get_attribute_name() {
                    let expected = utils::convert_error(value.to_dec())?;
                    let read_value = predicate.get_value() as i64;
                    if !(expected.eq(&format!("{}", read_value))) {
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
            utils::convert_error(
                sub_proof_request_builder
                    .add_revealed_attr(predicate.get_attribute_name()),
            )?;
        } else {
            utils::convert_error(sub_proof_request_builder.add_predicate(
                predicate.get_attribute_name(),
                predicate.get_predicate_type(),
                predicate.get_value() as i64,
            ))?;
        }
    }

    let sub_proof_request =
        utils::convert_error(sub_proof_request_builder.finalize())?;

    let cred_pub_key: indy_crypto::cl::CredentialPublicKey =
        utils::convert_deserialize(
            request
                .get_credential_template()
                .get_public_key()
                .get_credential_public_key(),
        )?;

    let proof_request_nonce: indy_crypto::cl::Nonce =
        utils::convert_deserialize(request.get_verification_nonce())?;

    let mut proof_verifier =
        utils::convert_error(verifier::Verifier::new_proof_verifier())?;

    utils::convert_error(proof_verifier.add_sub_proof_request(
        &sub_proof_request,
        &credential_schema,
        &non_credential_schema,
        &cred_pub_key,
        None,
        None,
    ))?;

    utils::convert_error(proof_verifier.verify(&proof, &proof_request_nonce))
}
