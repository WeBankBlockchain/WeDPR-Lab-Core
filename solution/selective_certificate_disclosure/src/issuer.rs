// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library for a certificate issuer.

use crate::utils;
use indy_crypto::cl::{issuer, Nonce};
use wedpr_protos::generated::scd::{
    CertificateSchema, CertificateSignature, CertificateTemplate,
    SignCertificateRequest, TemplatePrivateKey, TemplatePublicKey,
};
use wedpr_utils::error::WedprError;

/// Makes a certificate template for users to fill data.
// TODO: Wrap the output as PB if necessary.
pub fn make_certificate_template(
    schema: &CertificateSchema,
) -> Result<(CertificateTemplate, TemplatePrivateKey), WedprError> {
    let (credential_schema, non_credential_schema) =
        utils::build_certificate_schema(schema)?;

    let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
        utils::safe_indy_check(issuer::Issuer::new_credential_def(
            &credential_schema,
            &non_credential_schema,
            true,
        ))?;
    let cred_key_correctness_proof_str =
        utils::safe_serialize(&cred_key_correctness_proof)?;
    let cred_pub_key_str = utils::safe_serialize(&cred_pub_key)?;
    let cred_priv_key_str = utils::safe_serialize(&cred_priv_key)?;

    let mut template_public_key = TemplatePublicKey::new();

    template_public_key.set_key(cred_pub_key_str);

    let mut template_private_key = TemplatePrivateKey::new();
    template_private_key.set_key(cred_priv_key_str);

    let mut certificate_template = CertificateTemplate::new();
    certificate_template.set_template_public_key(template_public_key);
    certificate_template
        .set_template_correctness_proof(cred_key_correctness_proof_str);
    certificate_template.set_certificate_schema(schema.clone());

    Ok((certificate_template, template_private_key))
}

/// Signs a verified certificate from a user.
// TODO: Wrap the output as PB if necessary.
pub fn sign_certificate(
    certificate_template: &CertificateTemplate,
    template_private_key: &TemplatePrivateKey,
    sign_request: &SignCertificateRequest,
    user_id: &str,
    user_nonce_str: &str,
) -> Result<(CertificateSignature, String), WedprError>
{
    let certificate_attribute_dict =
        sign_request.get_certificate_attribute_dict();
    let blinded_credential_secrets: indy_crypto::cl::BlindedCredentialSecrets =
        utils::safe_deserialize(sign_request.get_blinded_certificate_secrets())?;
    let blinded_credential_secrets_correctness_proof: indy_crypto::cl::BlindedCredentialSecretsCorrectnessProof =
        utils::safe_deserialize(
            sign_request.get_blinded_certificate_secrets_correctness_proof()
        )?;

    let cred_priv_key: indy_crypto::cl::CredentialPrivateKey =
        utils::safe_deserialize(template_private_key.get_key())?;

    let cred_pub_key: indy_crypto::cl::CredentialPublicKey =
        utils::safe_deserialize(
            certificate_template.get_template_public_key().get_key(),
        )?;
    let mut credential_values_builder = utils::safe_indy_check(
        issuer::Issuer::new_credential_values_builder(),
    )?;
    for pair in certificate_attribute_dict.get_pair() {
        utils::safe_indy_check(
            credential_values_builder
                .add_dec_known(pair.get_key(), pair.get_value()),
        )?
    }

    let cred_values =
        utils::safe_indy_check(credential_values_builder.finalize())?;

    let user_nonce: Nonce = utils::safe_deserialize(user_nonce_str)?;

    let issuer_nonce: Nonce = utils::get_random_nonce()?;

    let (cred_signature, signature_correctness_proof) =
        utils::safe_indy_check(issuer::Issuer::sign_credential(
            user_id,
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &user_nonce,
            &issuer_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        ))?;

    let cred_signature_str = utils::safe_serialize(&cred_signature)?;
    let signature_correctness_proof_str =
        utils::safe_serialize(&signature_correctness_proof)?;
    let issuer_nonce_str = utils::safe_serialize(&issuer_nonce)?;

    let mut certificate_signature = CertificateSignature::new();
    certificate_signature.set_certificate_signature(cred_signature_str);
    certificate_signature
        .set_signature_correctness_proof(signature_correctness_proof_str);

    Ok((certificate_signature, issuer_nonce_str))
}

#[cfg(test)]
mod tests {
    use super::*;
//    use crate::user::fill_certificate;
//    use crate::user::blind_certificate_signature;
//    use wedpr_protos::generated::scd::{
//        AttributeDict};

    #[test]
    fn test_make_certificate_template() {
        let attribute_name1 = "id";
        let attribute_name2 = "age";
        let mut attr_vec = Vec::new();
        attr_vec.push(attribute_name1.to_string());
        attr_vec.push(attribute_name2.to_string());
        let mut schema = CertificateSchema::new();
        schema
            .mut_attribute_name()
            .push(attribute_name1.to_string());
        schema.mut_attribute_name().
            push(attribute_name2.to_string());
        let (certificate_template, _template_private_key) =
            make_certificate_template(&schema).unwrap();
        let get_attribute = certificate_template.get_certificate_schema().get_attribute_name();
        assert_eq!(attr_vec, get_attribute);
    }
}

