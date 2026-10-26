// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of SCD utility functions.

use std::collections::BTreeSet;
use wedpr_l_utils::error::WedprError;
use wedpr_s_protos::generated::scd::{
    AttributeDict, CertificateSchema, VerificationRuleSet,
};
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

pub fn validate_rule_set(
    rules: &VerificationRuleSet,
) -> Result<(), WedprError> {
    for predicate in rules.get_attribute_predicate() {
        let value = predicate.get_predicate_value();
        let kind = predicate.get_predicate_type();
        if value > i64::max_value() as u64
            || (kind == "GT" && value == i64::max_value() as u64)
            || !matches!(kind, "EQ" | "GE" | "GT" | "LE" | "LT")
        {
            return Err(WedprError::ArgumentError);
        }
    }
    Ok(())
}

// Indy asserts that its proof count matches the configured credential count.
// This API configures one credential; reject malformed envelopes before Indy.
pub fn deserialize_certificate_proof(
    input: &str,
) -> Result<wedpr_indy_crypto::cl::Proof, WedprError> {
    // A single CL credential proof is much smaller than these limits. Bound
    // untrusted parsing and modular-exponent sizes before constructing BIGNUMs.
    if input.len() > 4 * 1024 * 1024 {
        return Err(WedprError::FormatError);
    }
    let value: serde_json::Value = safe_deserialize(input)?;
    validate_proof_json_strings(&value)?;
    if value
        .get("proofs")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        != Some(1)
    {
        return Err(WedprError::FormatError);
    }
    let inequalities = value["proofs"][0]["primary_proof"]["ne_proofs"]
        .as_array()
        .ok_or(WedprError::FormatError)?;
    let mut predicates = BTreeSet::new();
    for proof in inequalities {
        let predicate = &proof["predicate"];
        let key = (
            predicate["attr_name"]
                .as_str()
                .ok_or(WedprError::FormatError)?,
            predicate["p_type"]
                .as_str()
                .ok_or(WedprError::FormatError)?,
            predicate["value"].as_i64().ok_or(WedprError::FormatError)?,
        );
        if !predicates.insert(key) {
            return Err(WedprError::FormatError);
        }
    }
    // This solution has no revocation-registry API. Do not deserialize unused
    // untrusted pairing proofs which the configured verifier cannot validate.
    if value["proofs"][0]
        .get("non_revoc_proof")
        .map_or(false, |proof| !proof.is_null())
    {
        return Err(WedprError::FormatError);
    }
    serde_json::from_value(value).map_err(|_| WedprError::DecodeError)
}

fn validate_proof_json_strings(
    value: &serde_json::Value,
) -> Result<(), WedprError> {
    match value {
        serde_json::Value::String(value) if value.len() > 4096 => {
            return Err(WedprError::FormatError)
        },
        serde_json::Value::Array(values) => {
            for value in values {
                validate_proof_json_strings(value)?;
            }
        },
        serde_json::Value::Object(values) => {
            for value in values.values() {
                validate_proof_json_strings(value)?;
            }
        },
        _ => {},
    }
    Ok(())
}

pub fn validate_attributes(
    attributes: &AttributeDict,
    schema: &CertificateSchema,
) -> Result<(), WedprError> {
    let expected: BTreeSet<_> = schema
        .get_attribute_name()
        .iter()
        .map(String::as_str)
        .collect();
    let actual: BTreeSet<_> = attributes
        .get_pair()
        .iter()
        .map(|pair| pair.get_key())
        .collect();
    if expected.len() != schema.get_attribute_name().len()
        || actual.len() != attributes.get_pair().len()
        || expected != actual
    {
        return Err(WedprError::ArgumentError);
    }
    Ok(())
}

pub fn validate_prover_predicates(
    rules: &VerificationRuleSet,
    attributes: &AttributeDict,
) -> Result<(), WedprError> {
    validate_rule_set(rules)?;
    for predicate in rules.get_attribute_predicate() {
        if predicate.get_predicate_type() == "EQ" {
            continue;
        }
        let pair = attributes
            .get_pair()
            .iter()
            .find(|pair| pair.get_key() == predicate.get_attribute_name())
            .ok_or(WedprError::ArgumentError)?;
        let value = pair
            .get_value()
            .parse::<i64>()
            .map_err(|_| WedprError::ArgumentError)?;
        let threshold = predicate.get_predicate_value() as i64;
        let delta = match predicate.get_predicate_type() {
            "GE" => value.checked_sub(threshold),
            "GT" => value
                .checked_sub(threshold)
                .and_then(|delta| delta.checked_sub(1)),
            "LE" => threshold.checked_sub(value),
            "LT" => threshold
                .checked_sub(value)
                .and_then(|delta| delta.checked_sub(1)),
            _ => None,
        }
        .ok_or(WedprError::ArgumentError)?;
        if delta < 0 {
            return Err(WedprError::VerificationError);
        }
    }
    Ok(())
}

/// Builds credential schema.
pub fn build_certificate_schema(
    template: &CertificateSchema,
) -> Result<(CredentialSchema, NonCredentialSchema), WedprError> {
    let names = template.get_attribute_name();
    if names
        .iter()
        .any(|name| name.is_empty() || name == "user_private_key")
        || names.iter().collect::<BTreeSet<_>>().len() != names.len()
    {
        return Err(WedprError::ArgumentError);
    }
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
        Err(_) => {
            wedpr_println!("Indy cryptographic operation failed");
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
        Err(_) => {
            wedpr_println!("serialization failed");
            return Err(WedprError::DecodeError);
        },
    }
}

/// Deserializes a string to an object, otherwise raises an error.
pub fn safe_deserialize<'a, T>(input_str: &'a str) -> Result<T, WedprError>
where T: serde::Deserialize<'a> {
    match serde_json::from_str(input_str) {
        Ok(v) => Ok(v),
        Err(_) => {
            wedpr_println!("deserialization failed");
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
