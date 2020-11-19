// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of selective_disclosure solution,
//! targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_protos::generated::selective_disclosure::{
    CredentialInfo, CredentialSignature, CredentialTemplate,
    SelectiveDisclosureResult, VerificationRule,
};

use wedpr_crypto::utils::{bytes_to_string, string_to_bytes};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::c_char_pointer_to_string;

#[no_mangle]
/// C interface for 'wedpr_sign_credential'.
pub extern "C" fn wedpr_make_credential(
    credential_info_cstring: *mut c_char,
    credential_template_cstring: *mut c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| {
        let credential_info_pb = c_safe_c_char_pointer_to_proto!(
            credential_info_cstring,
            CredentialInfo
        );
        let credential_template_pb = c_safe_c_char_pointer_to_proto!(
            credential_template_cstring,
            CredentialTemplate
        );

        let (
            credential_signature_request,
            master_secret_str,
            credential_secrets_blinding_factors_str,
            nonce_credential_str,
        ) = match selective_disclosure::user::make_credential(
            &credential_info_pb,
            &credential_template_pb,
        ) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let mut sl_result = SelectiveDisclosureResult::new();
        sl_result
            .set_credential_signature_request(credential_signature_request);
        sl_result.set_master_secret(master_secret_str);
        sl_result.set_credential_secrets_blinding_factors(
            credential_secrets_blinding_factors_str,
        );
        sl_result.set_nonce_credential(nonce_credential_str);
        c_safe_proto_to_c_char_pointer!(sl_result)
    });
    c_safe_return!(result)
}

#[no_mangle]
/// C interface for 'wedpr_blind_credential_signature'.
pub extern "C" fn wedpr_blind_credential_signature(
    credential_signature_cstring: *mut c_char,
    credential_info_cstring: *mut c_char,
    credential_template_cstring: *mut c_char,
    master_secret_cstring: *mut c_char,
    credential_secrets_blinding_factors_cstring: *mut c_char,
    nonce_credential_cstring: *mut c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| {
        let credential_signature_pb = c_safe_c_char_pointer_to_proto!(
            credential_signature_cstring,
            CredentialSignature
        );
        let credential_info_pb = c_safe_c_char_pointer_to_proto!(
            credential_info_cstring,
            CredentialInfo
        );
        let credential_template_pb = c_safe_c_char_pointer_to_proto!(
            credential_template_cstring,
            CredentialTemplate
        );
        let master_secret =
            c_safe_c_char_pointer_to_string!(master_secret_cstring);
        let credential_secrets_blinding_factors = c_safe_c_char_pointer_to_string!(
            credential_secrets_blinding_factors_cstring
        );
        let nonce_credential =
            c_safe_c_char_pointer_to_string!(nonce_credential_cstring);

        let new_credential_signature =
            match selective_disclosure::user::blind_credential_signature(
                &credential_signature_pb,
                &credential_info_pb,
                &credential_template_pb,
                &master_secret,
                &credential_secrets_blinding_factors,
                &nonce_credential,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };

        let mut sl_result = SelectiveDisclosureResult::new();
        sl_result.set_credential_signature(new_credential_signature);
        c_safe_proto_to_c_char_pointer!(sl_result)
    });
    c_safe_return!(result)
}

#[no_mangle]
/// C interface for 'wedpr_prove_credential_info'.
pub extern "C" fn wedpr_prove_credential_info(
    verification_predicate_rule_cstring: *mut c_char,
    credential_signature_cstring: *mut c_char,
    credential_info_cstring: *mut c_char,
    credential_template_cstring: *mut c_char,
    master_secret_cstring: *mut c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| {
        let credential_signature_pb = c_safe_c_char_pointer_to_proto!(
            credential_signature_cstring,
            CredentialSignature
        );
        let credential_info_pb = c_safe_c_char_pointer_to_proto!(
            credential_info_cstring,
            CredentialInfo
        );
        let credential_template_pb = c_safe_c_char_pointer_to_proto!(
            credential_template_cstring,
            CredentialTemplate
        );
        let verification_predicate_rule_pb = c_safe_c_char_pointer_to_proto!(
            verification_predicate_rule_cstring,
            VerificationRule
        );
        let master_secret =
            c_safe_c_char_pointer_to_string!(master_secret_cstring);

        let request =
            match selective_disclosure::user::prove_selected_credential_info(
                &verification_predicate_rule_pb,
                &credential_signature_pb,
                &credential_info_pb,
                &credential_template_pb,
                &master_secret,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };

        let mut sl_result = SelectiveDisclosureResult::new();
        sl_result.set_verification_request(request);
        c_safe_proto_to_c_char_pointer!(sl_result)
    });
    c_safe_return!(result)
}
