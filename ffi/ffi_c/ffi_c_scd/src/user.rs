// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a certificate user (holder) SCD
//! solution, targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_protos::generated::scd::{
    AttributeDict, CertificateSignature, CertificateTemplate, ScdResult,
    VerificationRuleSet,
};

use wedpr_crypto::utils::{bytes_to_string, string_to_bytes};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::c_char_pointer_to_string;

/// C interface for 'wedpr_scd_fill_certificate'.
#[no_mangle]
pub extern "C" fn wedpr_scd_fill_certificate(
    attribute_dict_cstring: *mut c_char,
    certificate_template_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let attribute_dict_pb = c_safe_c_char_pointer_to_proto!(
            attribute_dict_cstring,
            AttributeDict
        );
        let certificate_template_pb = c_safe_c_char_pointer_to_proto!(
            certificate_template_cstring,
            CertificateTemplate
        );

        let (
            sign_certificate_request,
            user_private_key_str,
            certificate_secrets_blinding_factors_str,
            issuer_nonce_str,
        ) = match wedpr_s_selective_certificate_disclosure::user::fill_certificate(
            &attribute_dict_pb,
            &certificate_template_pb,
        ) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let mut scd_result = ScdResult::new();
        scd_result.set_sign_certificate_request(sign_certificate_request);
        scd_result.set_user_private_key(user_private_key_str);
        scd_result.set_certificate_secrets_blinding_factors(
            certificate_secrets_blinding_factors_str,
        );
        scd_result.set_issuer_nonce(issuer_nonce_str);
        c_safe_proto_to_c_char_pointer!(scd_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_scd_blind_certificate_signature'.
#[no_mangle]
pub extern "C" fn wedpr_scd_blind_certificate_signature(
    certificate_signature_cstring: *mut c_char,
    attribute_dict_cstring: *mut c_char,
    certificate_template_cstring: *mut c_char,
    user_private_key_cstring: *mut c_char,
    certificate_secrets_blinding_factors_cstring: *mut c_char,
    issuer_nonce_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let certificate_signature_pb = c_safe_c_char_pointer_to_proto!(
            certificate_signature_cstring,
            CertificateSignature
        );
        let attribute_dict_pb = c_safe_c_char_pointer_to_proto!(
            attribute_dict_cstring,
            AttributeDict
        );
        let certificate_template_pb = c_safe_c_char_pointer_to_proto!(
            certificate_template_cstring,
            CertificateTemplate
        );
        let user_private_key =
            c_safe_c_char_pointer_to_string!(user_private_key_cstring);
        let certificate_secrets_blinding_factors = c_safe_c_char_pointer_to_string!(
            certificate_secrets_blinding_factors_cstring
        );
        let issuer_nonce =
            c_safe_c_char_pointer_to_string!(issuer_nonce_cstring);

        let blinded_certificate_signature =
            match wedpr_s_selective_certificate_disclosure::user::blind_certificate_signature(
                &certificate_signature_pb,
                &attribute_dict_pb,
                &certificate_template_pb,
                &user_private_key,
                &certificate_secrets_blinding_factors,
                &issuer_nonce,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut scd_result = ScdResult::new();
        scd_result.set_certificate_signature(blinded_certificate_signature);
        c_safe_proto_to_c_char_pointer!(scd_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_scd_prove_selective_disclosure'.
#[no_mangle]
pub extern "C" fn wedpr_scd_prove_selective_disclosure(
    rule_set_cstring: *mut c_char,
    certificate_signature_cstring: *mut c_char,
    attribute_dict_cstring: *mut c_char,
    certificate_template_cstring: *mut c_char,
    user_private_key_cstring: *mut c_char,
    verification_nonce_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let certificate_signature_pb = c_safe_c_char_pointer_to_proto!(
            certificate_signature_cstring,
            CertificateSignature
        );
        let attribute_dict_pb = c_safe_c_char_pointer_to_proto!(
            attribute_dict_cstring,
            AttributeDict
        );
        let certificate_template_pb = c_safe_c_char_pointer_to_proto!(
            certificate_template_cstring,
            CertificateTemplate
        );
        let rule_set_pb = c_safe_c_char_pointer_to_proto!(
            rule_set_cstring,
            VerificationRuleSet
        );
        let user_private_key =
            c_safe_c_char_pointer_to_string!(user_private_key_cstring);
        let verification_nonce =
            c_safe_c_char_pointer_to_string!(verification_nonce_cstring);

        let verify_request =
            match wedpr_s_selective_certificate_disclosure::user::prove_selective_disclosure(
                &rule_set_pb,
                &certificate_signature_pb,
                &attribute_dict_pb,
                &certificate_template_pb,
                &user_private_key,
                &verification_nonce
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut scd_result = ScdResult::new();
        scd_result.set_verify_request(verify_request);
        c_safe_proto_to_c_char_pointer!(scd_result)
    });
    c_safe_return!(result)
}
