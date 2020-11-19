// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of selective_disclosure solution.

use crate::utils;
use indy_crypto::{
    bn::BigNumber,
    cl::{issuer, prover, verifier, Nonce},
};
use wedpr_protos::generated::selective_disclosure::{
    CredentialInfo, CredentialSignature, CredentialSignatureRequest,
    CredentialTemplate, VerificationRequest, VerificationRule,
};
use wedpr_utils::error::WedprError;

/// User make credential used by selective disclosure solution.
pub fn make_credential(
    input: &CredentialInfo,
    credential_template: &CredentialTemplate,
) -> Result<(CredentialSignatureRequest, String, String, String), WedprError>
{
    let cred_key_correctness_proof: indy_crypto::cl::CredentialKeyCorrectnessProof =
        utils::convert_deserialize(
            credential_template.get_credential_key_correctness_proof(),
        )?;
    let cred_pub_key: indy_crypto::cl::CredentialPublicKey =
        utils::convert_deserialize(
            credential_template
                .get_public_key()
                .get_credential_public_key(),
        )?;

    let master_secret =
        utils::convert_error(prover::Prover::new_master_secret())?;
    let nonce_credential: Nonce = utils::convert_error(BigNumber::rand(80))?;

    let mut credential_values_builder =
        utils::convert_error(issuer::Issuer::new_credential_values_builder())?;
    let master_value = utils::convert_error(master_secret.value())?;
    utils::convert_error(
        credential_values_builder
            .add_value_hidden("master_secret", &master_value),
    )?;
    for pair in input.get_attribute_pair() {
        utils::convert_error(
            credential_values_builder
                .add_dec_known(pair.get_key(), pair.get_value()),
        )?
    }
    let cred_values =
        utils::convert_error(credential_values_builder.finalize())?;

    let (
        blinded_credential_secrets,
        credential_secrets_blinding_factors,
        blinded_credential_secrets_correctness_proof,
    ) = utils::convert_error(prover::Prover::blind_credential_secrets(
        &cred_pub_key,
        &cred_key_correctness_proof,
        &cred_values,
        &nonce_credential,
    ))?;

    let blinded_credential_secrets_str =
        utils::convert_serialize(&blinded_credential_secrets)?;
    let credential_secrets_blinding_factors_str =
        utils::convert_serialize(&credential_secrets_blinding_factors)?;
    let blinded_credential_secrets_correctness_proof_str =
        utils::convert_serialize(
            &blinded_credential_secrets_correctness_proof,
        )?;

    let mut credential_signature_request = CredentialSignatureRequest::new();
    credential_signature_request
        .set_blinded_credential_secrets(blinded_credential_secrets_str);
    credential_signature_request
        .set_blinded_credential_secrets_correctness_proof(
            blinded_credential_secrets_correctness_proof_str,
        );
    credential_signature_request.set_credential_info(input.clone());

    let master_secret_str = utils::convert_serialize(master_secret)?;
    let nonce_credential_str = utils::convert_serialize(nonce_credential)?;

    Ok((
        credential_signature_request,
        master_secret_str,
        credential_secrets_blinding_factors_str,
        nonce_credential_str,
    ))
}

/// User blind credential signed by issuer, used by selective disclosure
/// solution.
pub fn blind_credential_signature(
    credential_signature: &CredentialSignature,
    credential_info: &CredentialInfo,
    credential_template: &CredentialTemplate,
    master_secret: &str,
    credential_secrets_blinding_factors: &str,
    nonce_sign: &str,
) -> Result<CredentialSignature, WedprError>
{
    let mut cred_signature: indy_crypto::cl::CredentialSignature =
        utils::convert_deserialize(
            credential_signature.get_credential_signature(),
        )?;
    let signature_correctness_proof: indy_crypto::cl::SignatureCorrectnessProof = utils::convert_deserialize(
        credential_signature.get_signature_correctness_proof()
    )?;

    let credential_secrets_blinding_factors: indy_crypto::cl::CredentialSecretsBlindingFactors = utils::convert_deserialize(
        credential_secrets_blinding_factors
    )?;

    let cred_issuance_nonce: indy_crypto::cl::Nonce =
        utils::convert_deserialize(nonce_sign)?;
    let cred_pub_key: indy_crypto::cl::CredentialPublicKey =
        utils::convert_deserialize(
            credential_template
                .get_public_key()
                .get_credential_public_key(),
        )?;

    let mut credential_values_builder =
        utils::convert_error(issuer::Issuer::new_credential_values_builder())?;
    let master_key: indy_crypto::cl::MasterSecret =
        utils::convert_deserialize(master_secret)?;
    let master_value = utils::convert_error(master_key.value())?;
    utils::convert_error(
        credential_values_builder
            .add_value_hidden("master_secret", &master_value),
    )?;
    for pair in credential_info.get_attribute_pair() {
        utils::convert_error(
            credential_values_builder
                .add_dec_known(pair.get_key(), pair.get_value()),
        )?
    }
    let cred_values =
        utils::convert_error(credential_values_builder.finalize())?;

    prover::Prover::process_credential_signature(
        &mut cred_signature,
        &cred_values,
        &signature_correctness_proof,
        &credential_secrets_blinding_factors,
        &cred_pub_key,
        &cred_issuance_nonce,
        None,
        None,
        None,
    )
    .unwrap();
    let cred_signature_str = utils::convert_serialize(&cred_signature)?;
    let signature_correctness_proof_str =
        utils::convert_serialize(&signature_correctness_proof)?;

    let mut credential_signature = CredentialSignature::new();
    credential_signature.set_credential_signature(cred_signature_str);
    credential_signature
        .set_signature_correctness_proof(signature_correctness_proof_str);

    Ok(credential_signature)
}

/// User prove encrypted info with signed credential, used by selective
/// disclosure solution.
pub fn prove_selected_credential_info(
    rules: &VerificationRule,
    credential_signature: &CredentialSignature,
    credential_info: &CredentialInfo,
    credential_template: &CredentialTemplate,
    master_secret: &str,
) -> Result<VerificationRequest, WedprError>
{
    let (credential_schema, non_credential_schema) =
        utils::build_credential_schema(
            credential_template.get_credential_schema(),
        )?;

    let cred_pub_key: indy_crypto::cl::CredentialPublicKey =
        utils::convert_deserialize(
            credential_template
                .get_public_key()
                .get_credential_public_key(),
        )?;

    let cred_signature: indy_crypto::cl::CredentialSignature =
        utils::convert_deserialize(
            credential_signature.get_credential_signature(),
        )?;

    let mut credential_values_builder =
        utils::convert_error(issuer::Issuer::new_credential_values_builder())?;
    let master_key: indy_crypto::cl::MasterSecret =
        utils::convert_deserialize(master_secret)?;
    let master_value = utils::convert_error(master_key.value())?;
    utils::convert_error(
        credential_values_builder
            .add_value_hidden("master_secret", &master_value),
    )?;
    for pair in credential_info.get_attribute_pair() {
        utils::convert_error(
            credential_values_builder
                .add_dec_known(pair.get_key(), pair.get_value()),
        )?
    }
    let cred_values =
        utils::convert_error(credential_values_builder.finalize())?;

    let mut proof_builder =
        utils::convert_error(prover::Prover::new_proof_builder())?;
    utils::convert_error(proof_builder.add_common_attribute("master_secret"))?;

    let mut sub_proof_request_builder =
        verifier::Verifier::new_sub_proof_request_builder().unwrap();

    for predicate in rules.get_predicate_attribute() {
        if predicate.get_predicate_type() == "EQ" {
            for pair in credential_info.get_attribute_pair() {
                if pair.get_key() == predicate.get_attribute_name() {
                    let expected = pair.get_value();
                    let read_value = predicate.get_value() as i64;
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

    for revealed in rules.get_revealed_attribute() {
        utils::convert_error(
            sub_proof_request_builder.add_revealed_attr(revealed),
        )?;
    }

    let sub_proof_request =
        utils::convert_error(sub_proof_request_builder.finalize())?;

    utils::convert_error(proof_builder.add_sub_proof_request(
        &sub_proof_request,
        &credential_schema,
        &non_credential_schema,
        &cred_signature,
        &cred_values,
        &cred_pub_key,
        None,
        None,
    ))?;
    let proof_request_nonce: Nonce = utils::convert_error(BigNumber::rand(80))?;

    let proof =
        utils::convert_error(proof_builder.finalize(&proof_request_nonce))?;

    let proof_str = utils::convert_serialize(&proof)?;
    let proof_request_nonce_str =
        utils::convert_serialize(&proof_request_nonce)?;

    let mut request = VerificationRequest::new();
    request.set_credential_template(credential_template.clone());
    request.set_verification_proof(proof_str);
    request.set_verification_nonce(proof_request_nonce_str);

    Ok(request)
}
