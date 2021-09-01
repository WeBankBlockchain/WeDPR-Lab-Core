// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a counter in ABC
//! solution, targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

use wedpr_s_protos::generated::abv::{CounterSecret, VoteStorage
};

use libc::c_char;
use protobuf::{self, Message};
use std::{ffi::CString, panic, ptr};
use wedpr_ffi_common::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};
use std::os::raw::c_long;

/// C interface for 'wedpr_abv_make_counter_secret'.
#[no_mangle]
pub extern "C" fn wedpr_abv_make_counter_secret(
) -> *mut c_char {
    let result = panic::catch_unwind(|| {

        let secret =
            wedpr_s_anonymous_bounded_voting::counter::make_counter_secret();
        c_safe_proto_to_c_char_pointer!(secret)
    });
    c_safe_return!(result)
}


/// C interface for 'wedpr_abv_make_system_parameters_share'.
#[no_mangle]
pub extern "C" fn wedpr_abv_make_system_parameters_share(
    counter_id_cstring: *mut c_char,
    counter_secret_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let counter_id =
            c_safe_c_char_pointer_to_string!(counter_id_cstring);

        let counter_secret =
            c_safe_c_char_pointer_to_proto!(counter_secret_cstring, CounterSecret);

        let request =
            match wedpr_s_anonymous_bounded_voting::counter::make_system_parameters_share(
                &counter_id,
                &counter_secret,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        c_safe_proto_to_c_char_pointer!(request)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_abv_count'.
#[no_mangle]
pub extern "C" fn wedpr_abv_count(
    counter_id_cstring: *mut c_char,
    counter_secret_cstring: *mut c_char,
    storage_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let counter_id =
            c_safe_c_char_pointer_to_string!(counter_id_cstring);

        let counter_secret =
            c_safe_c_char_pointer_to_proto!(counter_secret_cstring, CounterSecret);

        let storage =
            c_safe_c_char_pointer_to_proto!(storage_cstring, VoteStorage);

        let request =
            match wedpr_s_anonymous_bounded_voting::counter::count(
                &counter_id,
                &counter_secret,
                &storage
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        c_safe_proto_to_c_char_pointer!(request)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_abv_finalize_vote_result'.
#[no_mangle]
pub extern "C" fn wedpr_abv_finalize_vote_result(
    param_cstring: *mut c_char,
    vote_sum_cstring: *mut c_char,
    counting_result_sum_cstring: *mut c_char,
    max_number: c_long,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {

        let param =
            c_safe_c_char_pointer_to_proto!(param_cstring, SystemParametersStorage);

        let vote_sum =
            c_safe_c_char_pointer_to_proto!(vote_sum_cstring, VoteStorage);

        let counting_result_sum =
            c_safe_c_char_pointer_to_proto!(counting_result_sum_cstring, DecryptedResultPartStorage);

        let request =
            match wedpr_s_anonymous_bounded_voting::counter::finalize_vote_result(
                &param,
                &vote_sum,
                &counting_result_sum,
                max_number
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        c_safe_proto_to_c_char_pointer!(request)
    });
    c_safe_return!(result)
}