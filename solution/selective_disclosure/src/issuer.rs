// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of selective disclosure solution.

use crate::utils;
use indy_crypto::{
    bn::BigNumber,
    cl::{issuer, Nonce},
};
use wedpr_protos::generated::selective_disclosure::{
    AttributeTemplate, CredentialSignature, CredentialSignatureRequest,
    CredentialTemplate, TemplatePublicKey, TemplateSecretKey,
};
use wedpr_utils::error::WedprError;

/// Issuer make credential template for users used by selective disclosure
/// solution.
pub fn make_credential_template(
    template: &AttributeTemplate,
) -> Result<(CredentialTemplate, TemplateSecretKey), WedprError> {
    let (credential_schema, non_credential_schema) =
        utils::build_credential_schema(template)?;

    let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
        utils::convert_error(issuer::Issuer::new_credential_def(
            &credential_schema,
            &non_credential_schema,
            true,
        ))?;
    let cred_key_correctness_proof_str =
        utils::convert_serialize(&cred_key_correctness_proof)?;
    let cred_pub_key_str = utils::convert_serialize(&cred_pub_key)?;
    let cred_priv_key_str = utils::convert_serialize(&cred_priv_key)?;

    let mut template_public_key = TemplatePublicKey::new();

    template_public_key.set_credential_public_key(cred_pub_key_str);

    let mut template_secret_key = TemplateSecretKey::new();
    template_secret_key.set_credential_secret_key(cred_priv_key_str);

    let mut credential_template = CredentialTemplate::new();
    credential_template.set_public_key(template_public_key);
    credential_template
        .set_credential_key_correctness_proof(cred_key_correctness_proof_str);
    credential_template.set_credential_schema(template.clone());

    Ok((credential_template, template_secret_key))
}

/// Issuer sign credential made by users, used by selective disclosure solution.
pub fn sign_credential(
    credential_template: &CredentialTemplate,
    template_secret_key: &TemplateSecretKey,
    credential_request: &CredentialSignatureRequest,
    user_id: &str,
    nonce: &str,
) -> Result<(CredentialSignature, String), WedprError>
{
    let credential_info = credential_request.get_credential_info();
    let blinded_credential_secrets: indy_crypto::cl::BlindedCredentialSecrets =
        utils::convert_deserialize(
            credential_request.get_blinded_credential_secrets(),
        )?;
    let blinded_credential_secrets_correctness_proof: indy_crypto::cl::BlindedCredentialSecretsCorrectnessProof =
        utils::convert_deserialize(
            credential_request.get_blinded_credential_secrets_correctness_proof()
        )?;

    let cred_priv_key: indy_crypto::cl::CredentialPrivateKey =
        utils::convert_deserialize(
            template_secret_key.get_credential_secret_key(),
        )?;

    let cred_pub_key: indy_crypto::cl::CredentialPublicKey =
        utils::convert_deserialize(
            credential_template
                .get_public_key()
                .get_credential_public_key(),
        )?;
    let mut credential_values_builder =
        utils::convert_error(issuer::Issuer::new_credential_values_builder())?;
    for pair in credential_info.get_attribute_pair() {
        utils::convert_error(
            credential_values_builder
                .add_dec_known(pair.get_key(), pair.get_value()),
        )?
    }

    let cred_values =
        utils::convert_error(credential_values_builder.finalize())?;

    let nonce_credential: Nonce = utils::convert_deserialize(nonce)?;

    let cred_issuance_nonce: Nonce =
        utils::convert_error(BigNumber::rand(80usize))?;

    let (cred_signature, signature_correctness_proof) =
        utils::convert_error(issuer::Issuer::sign_credential(
            user_id,
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &nonce_credential,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        ))?;

    let cred_signature_str = utils::convert_serialize(&cred_signature)?;
    let signature_correctness_proof_str =
        utils::convert_serialize(&signature_correctness_proof)?;
    let cred_issuance_nonce_str =
        utils::convert_serialize(&cred_issuance_nonce)?;

    let mut credential_signature = CredentialSignature::new();
    credential_signature.set_credential_signature(cred_signature_str);
    credential_signature
        .set_signature_correctness_proof(signature_correctness_proof_str);

    Ok((credential_signature, cred_issuance_nonce_str))
}
