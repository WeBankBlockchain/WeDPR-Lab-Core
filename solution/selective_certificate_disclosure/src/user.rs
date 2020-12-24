// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a certificate user (holder).

use crate::utils;
use wedpr_indy_crypto::cl::{issuer, prover, verifier, Nonce};
use wedpr_protos::generated::scd::{
    AttributeDict, CertificateSignature, CertificateTemplate,
    SignCertificateRequest, VerificationRuleSet, VerifyRequest,
};
use wedpr_utils::error::WedprError;

/// Fills a certificate and generates a SignCertificateRequest for an issuer to
/// sign.
// TODO: Wrap the output as PB if necessary.
pub fn fill_certificate(
    attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
) -> Result<(SignCertificateRequest, String, String, String), WedprError>
{
    let cred_key_correctness_proof: wedpr_indy_crypto::cl::CredentialKeyCorrectnessProof =
        utils::safe_deserialize(
            certificate_template.get_template_correctness_proof(),
        )?;
    let cred_pub_key: wedpr_indy_crypto::cl::CredentialPublicKey =
        utils::safe_deserialize(
            certificate_template.get_template_public_key().get_key(),
        )?;

    let user_private_key =
        utils::safe_indy_check(prover::Prover::new_master_secret())?;
    let user_nonce: Nonce = utils::get_random_nonce()?;

    let mut credential_values_builder = utils::safe_indy_check(
        issuer::Issuer::new_credential_values_builder(),
    )?;
    let master_value = utils::safe_indy_check(user_private_key.value())?;
    utils::safe_indy_check(
        credential_values_builder
            .add_value_hidden("user_private_key", &master_value),
    )?;
    for pair in attribute_dict.get_pair() {
        utils::safe_indy_check(
            credential_values_builder
                .add_dec_known(pair.get_key(), pair.get_value()),
        )?
    }
    let cred_values =
        utils::safe_indy_check(credential_values_builder.finalize())?;

    let (
        blinded_certificate_secrets,
        certificate_secrets_blinding_factors,
        blinded_certificate_secrets_correctness_proof,
    ) = utils::safe_indy_check(prover::Prover::blind_credential_secrets(
        &cred_pub_key,
        &cred_key_correctness_proof,
        &cred_values,
        &user_nonce,
    ))?;

    let blinded_certificate_secrets_str =
        utils::safe_serialize(&blinded_certificate_secrets)?;
    let certificate_secrets_blinding_factors_str =
        utils::safe_serialize(&certificate_secrets_blinding_factors)?;
    let blinded_certificate_secrets_correctness_proof_str =
        utils::safe_serialize(&blinded_certificate_secrets_correctness_proof)?;

    let mut sign_certificate_request = SignCertificateRequest::new();
    sign_certificate_request
        .set_blinded_certificate_secrets(blinded_certificate_secrets_str);
    sign_certificate_request.set_blinded_certificate_secrets_correctness_proof(
        blinded_certificate_secrets_correctness_proof_str,
    );
    sign_certificate_request
        .set_certificate_attribute_dict(attribute_dict.clone());

    let user_private_key_str = utils::safe_serialize(user_private_key)?;
    let user_nonce_str = utils::safe_serialize(user_nonce)?;

    Ok((
        sign_certificate_request,
        user_private_key_str,
        certificate_secrets_blinding_factors_str,
        user_nonce_str,
    ))
}

/// Blinds the signature of a signed certificate to prevent the issuer from
/// tracking its usage.
pub fn blind_certificate_signature(
    certificate_signature: &CertificateSignature,
    attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
    user_private_key: &str,
    certificate_secrets_blinding_factors: &str,
    issuer_nonce_str: &str,
) -> Result<CertificateSignature, WedprError>
{
    let mut cred_signature: wedpr_indy_crypto::cl::CredentialSignature =
        utils::safe_deserialize(
            certificate_signature.get_certificate_signature(),
        )?;
    let signature_correctness_proof: wedpr_indy_crypto::cl::SignatureCorrectnessProof = utils::safe_deserialize(
        certificate_signature.get_signature_correctness_proof()
    )?;

    let certificate_secrets_blinding_factors: wedpr_indy_crypto::cl::CredentialSecretsBlindingFactors = utils::safe_deserialize(
        certificate_secrets_blinding_factors
    )?;

    let issuer_nonce: wedpr_indy_crypto::cl::Nonce =
        utils::safe_deserialize(issuer_nonce_str)?;
    let cred_pub_key: wedpr_indy_crypto::cl::CredentialPublicKey =
        utils::safe_deserialize(
            certificate_template.get_template_public_key().get_key(),
        )?;

    let mut credential_values_builder = utils::safe_indy_check(
        issuer::Issuer::new_credential_values_builder(),
    )?;
    let master_key: wedpr_indy_crypto::cl::MasterSecret =
        utils::safe_deserialize(user_private_key)?;
    let master_value = utils::safe_indy_check(master_key.value())?;
    utils::safe_indy_check(
        credential_values_builder
            .add_value_hidden("user_private_key", &master_value),
    )?;
    for pair in attribute_dict.get_pair() {
        utils::safe_indy_check(
            credential_values_builder
                .add_dec_known(pair.get_key(), pair.get_value()),
        )?
    }
    let cred_values =
        utils::safe_indy_check(credential_values_builder.finalize())?;

    prover::Prover::process_credential_signature(
        &mut cred_signature,
        &cred_values,
        &signature_correctness_proof,
        &certificate_secrets_blinding_factors,
        &cred_pub_key,
        &issuer_nonce,
        None,
        None,
        None,
    )
    .unwrap();
    let cred_signature_str = utils::safe_serialize(&cred_signature)?;
    let signature_correctness_proof_str =
        utils::safe_serialize(&signature_correctness_proof)?;

    let mut blinded_certificate_signature = CertificateSignature::new();
    blinded_certificate_signature.set_certificate_signature(cred_signature_str);
    blinded_certificate_signature
        .set_signature_correctness_proof(signature_correctness_proof_str);

    Ok(blinded_certificate_signature)
}

/// Generate a VerifyRequest to prove the validity of selected attribute values
/// and their value predicates from a certificate, while those unselected
/// attributes will not be revealed.
pub fn prove_selective_disclosure(
    rule_set: &VerificationRuleSet,
    certificate_signature: &CertificateSignature,
    attribute_dict: &AttributeDict,
    certificate_template: &CertificateTemplate,
    user_private_key_str: &str,
    verification_nonce_str: &str,
) -> Result<VerifyRequest, WedprError>
{
    let (certificate_schema, non_certificate_schema) =
        utils::build_certificate_schema(
            certificate_template.get_certificate_schema(),
        )?;

    let cred_pub_key: wedpr_indy_crypto::cl::CredentialPublicKey =
        utils::safe_deserialize(
            certificate_template.get_template_public_key().get_key(),
        )?;

    let cred_signature: wedpr_indy_crypto::cl::CredentialSignature =
        utils::safe_deserialize(
            certificate_signature.get_certificate_signature(),
        )?;

    let mut credential_values_builder = utils::safe_indy_check(
        issuer::Issuer::new_credential_values_builder(),
    )?;
    let master_key: wedpr_indy_crypto::cl::MasterSecret =
        utils::safe_deserialize(user_private_key_str)?;
    let master_value = utils::safe_indy_check(master_key.value())?;
    utils::safe_indy_check(
        credential_values_builder
            .add_value_hidden("user_private_key", &master_value),
    )?;
    for pair in attribute_dict.get_pair() {
        utils::safe_indy_check(
            credential_values_builder
                .add_dec_known(pair.get_key(), pair.get_value()),
        )?
    }
    let cred_values =
        utils::safe_indy_check(credential_values_builder.finalize())?;

    let mut proof_builder =
        utils::safe_indy_check(prover::Prover::new_proof_builder())?;
    utils::safe_indy_check(
        proof_builder.add_common_attribute("user_private_key"),
    )?;

    let mut sub_proof_request_builder =
        verifier::Verifier::new_sub_proof_request_builder().unwrap();

    for predicate in rule_set.get_attribute_predicate() {
        if predicate.get_predicate_type() == "EQ" {
            for pair in attribute_dict.get_pair() {
                if pair.get_key() == predicate.get_attribute_name() {
                    let expected = pair.get_value();
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
            // revealed_attr must be in predicate
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

    for revealed in rule_set.get_revealed_attribute_name() {
        utils::safe_indy_check(
            sub_proof_request_builder.add_revealed_attr(revealed),
        )?;
    }

    let sub_proof_request =
        utils::safe_indy_check(sub_proof_request_builder.finalize())?;

    utils::safe_indy_check(proof_builder.add_sub_proof_request(
        &sub_proof_request,
        &certificate_schema,
        &non_certificate_schema,
        &cred_signature,
        &cred_values,
        &cred_pub_key,
        None,
        None,
    ))?;

    let verification_nonce: Nonce =
        utils::safe_deserialize(&verification_nonce_str)?;
    let proof =
        utils::safe_indy_check(proof_builder.finalize(&verification_nonce))?;

    let proof_str = utils::safe_serialize(&proof)?;

    let mut request = VerifyRequest::new();
    request.set_certificate_template(certificate_template.clone());
    request.set_verification_proof(proof_str);
    request.set_verification_nonce(verification_nonce_str.to_string());

    Ok(request)
}
