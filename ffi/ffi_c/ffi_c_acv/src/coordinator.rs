// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a voting coordinator in ABC
//! solution, targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_s_protos::generated::abv::{CandidateList, CounterSystemParametersStorage, RegistrationRequest, DecryptedResultPartStorage
};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};
use std::os::raw::{c_int, c_long, c_uint};


/// C interface for 'wedpr_abv_make_system_parameters'.
#[no_mangle]
pub extern "C" fn wedpr_abv_make_system_parameters(
    candidates_cstring: *mut c_char,
    counter_storage_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let candidates =
            c_safe_c_char_pointer_to_proto!(candidates_cstring, CandidateList);

        let counter_storage =
            c_safe_c_char_pointer_to_proto!(counter_storage_cstring, CounterSystemParametersStorage);

        let system_parameters_storage =
            match wedpr_s_anonymous_bounded_voting::coordinator::make_system_parameters(
                &candidates,
                &counter_storage,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        c_safe_proto_to_c_char_pointer!(system_parameters_storage)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_abv_certify_bounded_voter'.
#[no_mangle]
pub extern "C" fn wedpr_abv_certify_bounded_voter(
    secret_key_cstring: *mut c_char,
    blank_vote_value: c_uint,
    registration_request_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let registration_request =
            c_safe_c_char_pointer_to_proto!(registration_request_cstring, RegistrationRequest);
        let secret_key =
            c_safe_c_char_pointer_to_bytes!(secret_key_cstring);
        let value = blank_vote_value as u32;

        let response =
            match wedpr_s_anonymous_bounded_voting::coordinator::certify_bounded_voter(
                &secret_key,
                value,
                &registration_request,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        c_safe_proto_to_c_char_pointer!(response)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_abv_aggregate_decrypted_part_sum'.
#[no_mangle]
pub extern "C" fn wedpr_abv_aggregate_decrypted_part_sum(
    param_cstring: *mut c_char,
    decrypted_result_part_storage_cstring: *mut c_char,
    counting_result_sum_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let param =
            c_safe_c_char_pointer_to_proto!(param_cstring, SystemParametersStorage);

        let decrypted_result_part_storage =
            c_safe_c_char_pointer_to_proto!(decrypted_result_part_storage_cstring, DecryptedResultPartStorage);

        let mut counting_result_sum =
            c_safe_c_char_pointer_to_proto!(counting_result_sum_cstring, DecryptedResultPartStorage);


        let b_result =
            match wedpr_s_anonymous_bounded_voting::coordinator::aggregate_decrypted_part_sum(
                &param,
                &decrypted_result_part_storage,
                &mut counting_result_sum,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        if !b_result {
            return ptr::null_mut();
        }
        c_safe_proto_to_c_char_pointer!(counting_result_sum)
    });
    c_safe_return!(result)
}