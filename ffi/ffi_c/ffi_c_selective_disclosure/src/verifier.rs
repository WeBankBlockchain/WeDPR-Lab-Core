// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of selective_disclosure solution,
//! targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_crypto::utils::{bytes_to_string, string_to_bytes};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::c_char_pointer_to_string;

use wedpr_protos::generated::selective_disclosure::{
    SelectiveDisclosureResult, VerificationRequest, VerificationRule,
};

#[no_mangle]
/// C interface for 'wedpr_get_revealed_attrs_from_verification_request'.
pub extern "C" fn wedpr_get_revealed_attrs_from_verification_request(
    verification_request_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let verification_request_pb = c_safe_c_char_pointer_to_proto!(
            verification_request_cstring,
            VerificationRequest
        );

        let revealed_attrs =
            match selective_disclosure::verifier::get_revealed_attrs_from_verification_request(
                &verification_request_pb,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut sl_result = SelectiveDisclosureResult::new();
        sl_result.set_revealed_attribute_info(revealed_attrs);
        c_safe_proto_to_c_char_pointer!(sl_result)
    });
    c_safe_return!(result)
}

#[no_mangle]
/// C interface for 'wedpr_verify_proof'.
pub extern "C" fn wedpr_verify_proof(
    verification_predicate_rule_cstring: *mut c_char,
    verification_request_cstring: *mut c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| {
        let verification_request_pb = c_safe_c_char_pointer_to_proto!(
            verification_request_cstring,
            VerificationRequest
        );
        let verification_predicate_rule_pb = c_safe_c_char_pointer_to_proto!(
            verification_predicate_rule_cstring,
            VerificationRule
        );

        let result = match selective_disclosure::verifier::verify_proof(
            &verification_predicate_rule_pb,
            &verification_request_pb,
        ) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let mut sl_result = SelectiveDisclosureResult::new();
        sl_result.set_result(result);
        c_safe_proto_to_c_char_pointer!(sl_result)
    });
    c_safe_return!(result)
}
