// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a certificate verifier in SCD
//! solution, targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_crypto::utils::{bytes_to_string, string_to_bytes};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::c_char_pointer_to_string;

use wedpr_protos::generated::scd::{
    ScdResult, VerificationRuleSet, VerifyRequest,
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
            match selective_certificate_disclosure::verifier::get_revealed_attributes(
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
    rule_set_cstring: *mut c_char,
    verify_request_cstring: *mut c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| {
        let verify_request_pb = c_safe_c_char_pointer_to_proto!(
            verify_request_cstring,
            VerifyRequest
        );
        let rule_set_pb = c_safe_c_char_pointer_to_proto!(
            rule_set_cstring,
            VerificationRuleSet
        );

        let bool_result =
            match selective_certificate_disclosure::verifier::verify_selective_disclosure(
                &rule_set_pb,
                &verify_request_pb,
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
