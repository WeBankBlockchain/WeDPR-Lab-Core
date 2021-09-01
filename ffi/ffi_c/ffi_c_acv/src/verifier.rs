// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a verifier in ABC
//! solution, targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_s_protos::generated::abv::{SystemParametersStorage, VoteStorage
};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::{bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE, SUCCESS};


/// C interface for 'wedpr_abv_verify_bounded_vote_request'.
#[no_mangle]
pub extern "C" fn wedpr_abv_verify_bounded_vote_request(
    param_cstring: *mut c_char,
    request_cstring: *mut c_char,
    public_key_cstring: *mut c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key =
            c_safe_c_char_pointer_to_bytes_with_error_value!(public_key_cstring, FAILURE);

        let param =
            c_safe_c_char_pointer_to_proto_with_error_value!(param_cstring, SystemParametersStorage, FAILURE);

        let request =
            c_safe_c_char_pointer_to_proto_with_error_value!(request_cstring, VoteRequest, FAILURE);

        let b_result =
            match wedpr_s_anonymous_bounded_voting::verifier::verify_bounded_vote_request(
                &param,
                &request,
                &public_key
            ) {
                Ok(v) => SUCCESS,
                Err(_) => return FAILURE,
            };
        b_result
    });
    c_safe_return_with_error_value!(result, FAILURE)
}


/// C interface for 'wedpr_abv_aggregate_vote_sum_response'.
#[no_mangle]
pub extern "C" fn wedpr_abv_aggregate_vote_sum_response(
    param_cstring: *mut c_char,
    storage_cstring: *mut c_char,
    vote_sum_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {

        let param =
            c_safe_c_char_pointer_to_proto!(param_cstring, SystemParametersStorage);

        let storage =
            c_safe_c_char_pointer_to_proto!(storage_cstring, VoteStorage);

        let mut vote_sum =
            c_safe_c_char_pointer_to_proto!(vote_sum_cstring, VoteStorage);

        let b_result =
            match wedpr_s_anonymous_bounded_voting::verifier::aggregate_vote_sum_response(
                &param,
                &storage,
                &mut vote_sum
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        if !b_result {
            return ptr::null_mut();
        }
        c_safe_proto_to_c_char_pointer!(vote_sum)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_abv_verify_count_request'.
#[no_mangle]
pub extern "C" fn wedpr_abv_verify_count_request(
    param_cstring: *mut c_char,
    encrypted_vote_sum_cstring: *mut c_char,
    counter_share_cstring: *mut c_char,
    request_cstring: *mut c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let counter_share_bytes =
            c_safe_c_char_pointer_to_bytes_with_error_value!(counter_share_cstring, FAILURE);

        let param =
            c_safe_c_char_pointer_to_proto_with_error_value!(param_cstring, SystemParametersStorage, FAILURE);

        let encrypted_vote_sum =
            c_safe_c_char_pointer_to_proto_with_error_value!(encrypted_vote_sum_cstring, VoteStorage, FAILURE);

        let request =
            c_safe_c_char_pointer_to_proto_with_error_value!(request_cstring, VoteRequest, FAILURE);

        let counter_share = match wedpr_l_crypto_zkp_utils::bytes_to_point(&counter_share_bytes) {
            Ok(v) => v,
            Err(_) => return FAILURE,
        };

        let b_result =
            match wedpr_s_anonymous_bounded_voting::verifier::verify_count_request(
                &param,
                &encrypted_vote_sum,
                &counter_share,
                &request,
            ) {
                Ok(v) => SUCCESS,
                Err(_) => return FAILURE,
            };
        b_result
    });
    c_safe_return_with_error_value!(result, FAILURE)
}