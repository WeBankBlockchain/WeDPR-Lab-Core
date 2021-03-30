// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of HDK solution,
//! targeting C/C++ compatible architectures (including iOS).

use protobuf::{self, Message};
use wedpr_ffi_common::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};
use wedpr_s_hierarchical_deterministic_key;

use wedpr_s_protos::generated::hdk::HdkResult;

use libc::{c_char, c_int, c_uchar};
use std::{ffi::CString, panic, ptr};

// C/C++ FFI: C-style interfaces will be generated.

// Local macros and functions section.

/// C interface for 'wedpr_ktb_hdk_create_mnemonic_en'.
#[no_mangle]
pub extern "C" fn wedpr_ktb_hdk_create_mnemonic_en(
    word_count: c_uchar,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        // TODO: Extract a macro for this type of function call if feasible.
        let mnemonic =
            match wedpr_s_hierarchical_deterministic_key::hdk::create_mnemonic_en(word_count) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut hdk_result = HdkResult::new();
        hdk_result.set_mnemonic(mnemonic);
        c_safe_proto_to_c_char_pointer!(hdk_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_ktb_hdk_create_master_key_en'.
#[no_mangle]
pub extern "C" fn wedpr_ktb_hdk_create_master_key_en(
    password_cstring: *mut c_char,
    mnemonic_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let passwd = c_safe_c_char_pointer_to_string!(password_cstring);
        let mnemonic = c_safe_c_char_pointer_to_string!(mnemonic_cstring);

        // TODO: Extract a macro for this type of function call if feasible.
        let master_key = match wedpr_s_hierarchical_deterministic_key::hdk::create_master_key_en(
            &passwd, &mnemonic,
        ) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let mut hdk_result = HdkResult::new();
        hdk_result.set_master_key(master_key);
        c_safe_proto_to_c_char_pointer!(hdk_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_ktb_hdk_derive_extended_key'.
#[no_mangle]
pub extern "C" fn wedpr_ktb_hdk_derive_extended_key(
    master_key_cstring: *mut c_char,
    purpose_type: c_int,
    asset_type: c_int,
    account: c_int,
    change: c_int,
    address_index: c_int,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let master_key = c_safe_c_char_pointer_to_bytes!(master_key_cstring);

        let key_derivation_path = wedpr_s_hierarchical_deterministic_key::hdk::create_key_derivation_path(
            purpose_type,
            asset_type,
            account,
            change,
            address_index
        );
        // TODO: Extract a macro for this type of function call if feasible.
        let key_pair =
            match wedpr_s_hierarchical_deterministic_key::hdk::derive_extended_key(
                &master_key,
                &key_derivation_path
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };
        let mut hdk_result = HdkResult::new();
        hdk_result.set_key_pair(key_pair);
        c_safe_proto_to_c_char_pointer!(hdk_result)
    });
    c_safe_return!(result)
}
