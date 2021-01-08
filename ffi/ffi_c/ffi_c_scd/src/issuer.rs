// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a certificate issuer in SCD
//! solution, targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_s_protos::generated::scd::{
    CertificateSchema, CertificateTemplate, ScdResult, SignCertificateRequest,
    TemplatePrivateKey,
};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};

/// C interface for 'wedpr_scd_make_certificate_template'.
#[no_mangle]
pub extern "C" fn wedpr_scd_make_certificate_template(
    schema_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let schema_pb =
            c_safe_c_char_pointer_to_proto!(schema_cstring, CertificateSchema);

        let (certificate_template, template_private_key) =
            match wedpr_s_selective_certificate_disclosure::issuer::make_certificate_template(
                &schema_pb,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut scd_result = ScdResult::new();
        scd_result.set_certificate_template(certificate_template);
        scd_result.set_template_private_key(template_private_key);
        c_safe_proto_to_c_char_pointer!(scd_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_scd_sign_certificate'.
#[no_mangle]
pub extern "C" fn wedpr_scd_sign_certificate(
    certificate_template_cstring: *mut c_char,
    template_private_key_cstring: *mut c_char,
    sign_request_cstring: *mut c_char,
    user_id_cstring: *mut c_char,
    user_nonce_cstring: *mut c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| {
        let certificate_template_pb = c_safe_c_char_pointer_to_proto!(
            certificate_template_cstring,
            CertificateTemplate
        );
        let template_private_key_pb = c_safe_c_char_pointer_to_proto!(
            template_private_key_cstring,
            TemplatePrivateKey
        );
        let sign_request_pb = c_safe_c_char_pointer_to_proto!(
            sign_request_cstring,
            SignCertificateRequest
        );
        let user_id = c_safe_c_char_pointer_to_string!(user_id_cstring);
        let user_nonce = c_safe_c_char_pointer_to_string!(user_nonce_cstring);

        let (certificate_signature, issuer_nonce_str) =
            match wedpr_s_selective_certificate_disclosure::issuer::sign_certificate(
                &certificate_template_pb,
                &template_private_key_pb,
                &sign_request_pb,
                &user_id,
                &user_nonce,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut scd_result = ScdResult::new();
        scd_result.set_certificate_signature(certificate_signature);
        scd_result.set_issuer_nonce(issuer_nonce_str);
        c_safe_proto_to_c_char_pointer!(scd_result)
    });
    c_safe_return!(result)
}
