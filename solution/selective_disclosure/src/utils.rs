// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of selective_disclosure solution.

use wedpr_protos::generated::selective_disclosure::AttributeTemplate;
use wedpr_utils::error::WedprError;
extern crate serde;
extern crate serde_json;
use indy_crypto::{
    cl::{
        issuer, CredentialSchema, NonCredentialSchema,
        NonCredentialSchemaBuilder,
    },
    errors::IndyCryptoError,
};

/// Convert indy error to wedpr error.
pub fn convert_error<T>(
    arg: Result<T, IndyCryptoError>,
) -> Result<T, WedprError> {
    match arg {
        Ok(v) => Ok(v),
        Err(e) => {
            wedpr_println!("WedprError::IndyCryptoError: {:?}", e);
            return Err(WedprError::IndyCryptoError);
        },
    }
}

/// Build credential scheme.
pub fn build_credential_schema(
    template: &AttributeTemplate,
) -> Result<(CredentialSchema, NonCredentialSchema), WedprError> {
    let mut credential_schema_builder =
        convert_error(issuer::Issuer::new_credential_schema_builder())?;
    for value in template.get_attribute_key() {
        convert_error(credential_schema_builder.add_attr(value))?
    }
    let credential_schema =
        convert_error(credential_schema_builder.finalize())?;
    let mut non_credential_schema_builder =
        convert_error(NonCredentialSchemaBuilder::new())?;
    convert_error(non_credential_schema_builder.add_attr("master_secret"))?;
    let non_credential_schema =
        convert_error(non_credential_schema_builder.finalize())?;
    Ok((credential_schema, non_credential_schema))
}

/// Convert serialize error.
pub fn convert_serialize<T>(arg: T) -> Result<String, WedprError>
where T: serde::ser::Serialize {
    match serde_json::to_string(&arg) {
        Ok(v) => Ok(v),
        Err(e) => {
            wedpr_println!("WedprError::convert_serialize: {:?}", e);
            return Err(WedprError::FormatError);
        },
    }
}

/// Convert deserialize error.
pub fn convert_deserialize<'a, T>(arg: &'a str) -> Result<T, WedprError>
where T: serde::Deserialize<'a> {
    match serde_json::from_str(arg) {
        Ok(v) => Ok(v),
        Err(e) => {
            wedpr_println!("WedprError::convert_deserialize: {:?}", e);
            return Err(WedprError::FormatError);
        },
    }
}
