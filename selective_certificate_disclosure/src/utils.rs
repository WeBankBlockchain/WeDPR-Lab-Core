// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of SCD utility functions.

use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::scd::CertificateSchema;
extern crate serde;
extern crate serde_json;
use wedpr_indy_crypto::{
    bn::BigNumber,
    cl::{
        issuer, CredentialSchema, NonCredentialSchema,
        NonCredentialSchemaBuilder, Nonce,
    },
    errors::IndyCryptoError,
};

/// Builds credential schema.
pub fn build_certificate_schema(
    template: &CertificateSchema,
) -> Result<(CredentialSchema, NonCredentialSchema), WedprError> {
    let mut credential_schema_builder =
        safe_indy_check(issuer::Issuer::new_credential_schema_builder())?;
    for value in template.get_attribute_name() {
        safe_indy_check(credential_schema_builder.add_attr(value))?
    }
    let credential_schema =
        safe_indy_check(credential_schema_builder.finalize())?;
    let mut non_credential_schema_builder =
        safe_indy_check(NonCredentialSchemaBuilder::new())?;
    safe_indy_check(
        non_credential_schema_builder.add_attr("user_private_key"),
    )?;
    let non_credential_schema =
        safe_indy_check(non_credential_schema_builder.finalize())?;
    Ok((credential_schema, non_credential_schema))
}

/// Checks whether a Result containing a IndyCryptoError, and converts it to
/// WedprError if yes.
pub fn safe_indy_check<T>(
    result: Result<T, IndyCryptoError>,
) -> Result<T, WedprError> {
    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            wedpr_println!("Encounter IndyCryptoError: {:?}", e);
            return Err(WedprError::IndyCryptoError);
        },
    }
}

// TODO: Change json serialize to bytes
/// Serializes an object to a string, otherwise raises an error.
pub fn safe_serialize<T>(input_object: T) -> Result<String, WedprError>
where T: serde::ser::Serialize {
    match serde_json::to_string(&input_object) {
        Ok(v) => Ok(v),
        Err(e) => {
            wedpr_println!("safe_serialize failed: {:?}", e);
            return Err(WedprError::DecodeError);
        },
    }
}

/// Deserializes a string to an object, otherwise raises an error.
pub fn safe_deserialize<'a, T>(input_str: &'a str) -> Result<T, WedprError>
where T: serde::Deserialize<'a> {
    match serde_json::from_str(input_str) {
        Ok(v) => Ok(v),
        Err(e) => {
            wedpr_println!("safe_deserialize failed: {:?}", e);
            return Err(WedprError::DecodeError);
        },
    }
}

/// Gets Indy-compatible random nonce.
pub fn get_random_nonce() -> Result<Nonce, WedprError> {
    // Indy uses 80 bits random nonces.
    safe_indy_check(BigNumber::rand(80))
}

/// Gets Indy-compatible random nonce.
pub fn get_random_nonce_str() -> Result<String, WedprError> {
    safe_serialize(get_random_nonce()?)
}
