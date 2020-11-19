// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of selective_disclosure solution,
//! targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_protos::generated::selective_disclosure::{
    AttributeTemplate, CredentialSignatureRequest, CredentialTemplate,
    SelectiveDisclosureResult, TemplateSecretKey,
};

use wedpr_crypto::utils::{bytes_to_string, string_to_bytes};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::c_char_pointer_to_string;

#[no_mangle]
/// C interface for 'wedpr_make_credential_template'.
pub extern "C" fn wedpr_make_credential_template(
    attribute_template_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let attribute_template_pb = c_safe_c_char_pointer_to_proto!(
            attribute_template_cstring,
            AttributeTemplate
        );
        let (credential_template, template_secret_key) =
            match selective_disclosure::issuer::make_credential_template(
                &attribute_template_pb,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };

        let mut sl_result = SelectiveDisclosureResult::new();
        sl_result.set_credential_template(credential_template);
        sl_result.set_template_secret_key(template_secret_key);
        c_safe_proto_to_c_char_pointer!(sl_result)
    });
    c_safe_return!(result)
}

#[no_mangle]
/// C interface for 'wedpr_sign_credential'.
pub extern "C" fn wedpr_sign_credential(
    credential_template_cstring: *mut c_char,
    template_secret_key_cstring: *mut c_char,
    credential_request_cstring: *mut c_char,
    user_id_cstring: *mut c_char,
    nonce_cstring: *mut c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| {
        let credential_template_pb = c_safe_c_char_pointer_to_proto!(
            credential_template_cstring,
            CredentialTemplate
        );
        let template_secret_key_pb = c_safe_c_char_pointer_to_proto!(
            template_secret_key_cstring,
            TemplateSecretKey
        );
        let credential_request_pb = c_safe_c_char_pointer_to_proto!(
            credential_request_cstring,
            CredentialSignatureRequest
        );
        let user_id = c_safe_c_char_pointer_to_string!(user_id_cstring);
        let nonce = c_safe_c_char_pointer_to_string!(nonce_cstring);
        let (credential_signature, cred_issuance_nonce_str) =
            match selective_disclosure::issuer::sign_credential(
                &credential_template_pb,
                &template_secret_key_pb,
                &credential_request_pb,
                &user_id,
                &nonce,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };

        let mut sl_result = SelectiveDisclosureResult::new();
        sl_result.set_credential_signature(credential_signature);
        sl_result.set_nonce(cred_issuance_nonce_str);
        c_safe_proto_to_c_char_pointer!(sl_result)
    });
    c_safe_return!(result)
}
