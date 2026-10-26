// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a certificate verifier in SCD
//! solution, targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use crate::input::c_char_pointer_to_string;
use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::{bytes_to_string, string_to_bytes};

use wedpr_s_protos::generated::scd::{
    CertificateTemplate, ScdResult, VerificationRuleSet, VerifyRequest,
};

/// C interface for 'wedpr_scd_get_revealed_attributes'.
#[no_mangle]
pub extern "C" fn wedpr_scd_get_revealed_attributes(
    verify_request_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let verify_request_pb = c_safe_c_char_pointer_to_proto!(
            verify_request_cstring,
            VerifyRequest
        );

        let revealed_attribute_dict =
            match wedpr_s_selective_certificate_disclosure::verifier::get_revealed_attributes(
                &verify_request_pb,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut scd_result = ScdResult::new();
        scd_result.set_revealed_attribute_dict(revealed_attribute_dict);
        c_safe_proto_to_c_char_pointer!(scd_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_scd_verify_selective_disclosure'.
#[no_mangle]
pub extern "C" fn wedpr_scd_verify_selective_disclosure(
    _rule_set_cstring: *mut c_char,
    _verify_request_cstring: *mut c_char,
) -> *mut c_char {
    ptr::null_mut()
}

/// Verify using server-owned issuer and challenge context.
#[no_mangle]
pub extern "C" fn wedpr_scd_verify_selective_disclosure_with_context(
    rule_set_cstring: *mut c_char,
    verify_request_cstring: *mut c_char,
    trusted_template_cstring: *mut c_char,
    expected_nonce_cstring: *mut c_char,
) -> *mut c_char {
    if rule_set_cstring.is_null()
        || verify_request_cstring.is_null()
        || trusted_template_cstring.is_null()
        || expected_nonce_cstring.is_null()
    {
        return ptr::null_mut();
    }
    let result = panic::catch_unwind(|| {
        let verify_request_pb = c_safe_c_char_pointer_to_proto!(
            verify_request_cstring,
            VerifyRequest
        );
        let rule_set_pb = c_safe_c_char_pointer_to_proto!(
            rule_set_cstring,
            VerificationRuleSet
        );

        let trusted_template = c_safe_c_char_pointer_to_proto!(
            trusted_template_cstring,
            CertificateTemplate
        );
        let expected_nonce =
            c_safe_c_char_pointer_to_string!(expected_nonce_cstring);
        let bool_result =
            match wedpr_s_selective_certificate_disclosure::verifier::verify_selective_disclosure_with_context(
                &rule_set_pb,
                &verify_request_pb,
                &trusted_template,
                &expected_nonce,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut scd_result = ScdResult::new();
        scd_result.set_bool_result(bool_result);
        c_safe_proto_to_c_char_pointer!(scd_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_scd_get_verification_nonce'.
#[no_mangle]
pub extern "C" fn wedpr_scd_get_verification_nonce() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let verification_nonce =
            match wedpr_s_selective_certificate_disclosure::verifier::get_verification_nonce(
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut scd_result = ScdResult::new();
        scd_result.set_verification_nonce(verification_nonce);
        c_safe_proto_to_c_char_pointer!(scd_result)
    });
    c_safe_return!(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_s_protos::generated::scd::{
        AttributeDict, CertificateSchema, Predicate, StringToStringPair,
    };

    #[test]
    fn null_certificate_inputs_fail_without_dereferencing() {
        assert!(crate::user::wedpr_scd_fill_certificate(
            ptr::null_mut(),
            ptr::null_mut()
        )
        .is_null());
        assert!(wedpr_scd_verify_selective_disclosure(
            ptr::null_mut(),
            ptr::null_mut()
        )
        .is_null());
        assert!(wedpr_scd_verify_selective_disclosure_with_context(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut()
        )
        .is_null());
    }

    #[test]
    fn context_verification_accepts_valid_c_inputs_and_rejects_stale_challenge()
    {
        use wedpr_s_selective_certificate_disclosure::{
            issuer, user, verifier,
        };
        let mut schema = CertificateSchema::new();
        schema.mut_attribute_name().push("age".to_owned());
        let (template, key) =
            issuer::make_certificate_template(&schema).unwrap();
        let mut attributes = AttributeDict::new();
        let mut pair = StringToStringPair::new();
        pair.set_key("age".to_owned());
        pair.set_value("25".to_owned());
        attributes.mut_pair().push(pair);
        let (request, secret, blinding, user_nonce) =
            user::fill_certificate(&attributes, &template).unwrap();
        let (signature, issuer_nonce) = issuer::sign_certificate(
            &template,
            &key,
            &request,
            "synthetic",
            &user_nonce,
        )
        .unwrap();
        let signature = user::blind_certificate_signature(
            &signature,
            &attributes,
            &template,
            &secret,
            &blinding,
            &issuer_nonce,
        )
        .unwrap();
        let mut rules = VerificationRuleSet::new();
        let mut predicate = Predicate::new();
        predicate.set_attribute_name("age".to_owned());
        predicate.set_predicate_type("GE".to_owned());
        predicate.set_predicate_value(18);
        rules.mut_attribute_predicate().push(predicate);
        let nonce = verifier::get_verification_nonce().unwrap();
        let request = user::prove_selective_disclosure(
            &rules,
            &signature,
            &attributes,
            &template,
            &secret,
            &nonce,
        )
        .unwrap();
        let c_rules =
            CString::new(bytes_to_string(&rules.write_to_bytes().unwrap()))
                .unwrap();
        let c_request =
            CString::new(bytes_to_string(&request.write_to_bytes().unwrap()))
                .unwrap();
        let c_template =
            CString::new(bytes_to_string(&template.write_to_bytes().unwrap()))
                .unwrap();
        let c_nonce = CString::new(nonce).unwrap();
        let output = wedpr_scd_verify_selective_disclosure_with_context(
            c_rules.as_ptr() as *mut c_char,
            c_request.as_ptr() as *mut c_char,
            c_template.as_ptr() as *mut c_char,
            c_nonce.as_ptr() as *mut c_char,
        );
        assert!(!output.is_null());
        let output = unsafe { CString::from_raw(output) };
        let decoded = string_to_bytes(output.to_str().unwrap()).unwrap();
        assert!(ScdResult::parse_from_bytes(&decoded)
            .unwrap()
            .get_bool_result());
        let stale =
            CString::new(verifier::get_verification_nonce().unwrap()).unwrap();
        assert!(wedpr_scd_verify_selective_disclosure_with_context(
            c_rules.as_ptr() as *mut c_char,
            c_request.as_ptr() as *mut c_char,
            c_template.as_ptr() as *mut c_char,
            stale.as_ptr() as *mut c_char
        )
        .is_null());
    }
}
