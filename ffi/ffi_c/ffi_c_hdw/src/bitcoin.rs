// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use protobuf::{self, Message};
use wedpr_ffi_common::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};
use wedpr_s_hierarchical_deterministic_wallet;

use wedpr_s_protos::generated::hdw::HdwResult;

use libc::{c_char, c_uchar};
use std::{ffi::CString, panic, ptr};

// C/C++ FFI: C-style interfaces will be generated.

// Local macros and functions section.

/// C interface for 'wedpr_hdw_create_mnemonic'.
#[no_mangle]
pub extern "C" fn wedpr_hdw_create_mnemonic(
    word_count: c_uchar,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let mnemonic =
            match wedpr_s_hierarchical_deterministic_wallet::hdw::create_mnemonic_en(word_count) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };

        let mut hdw_result = HdwResult::new();
        hdw_result.set_mnemonic(mnemonic);
        c_safe_proto_to_c_char_pointer!(hdw_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_create_master_key'.
#[no_mangle]
pub extern "C" fn wedpr_create_master_key(
    passwd_cstring: *mut c_char,
    mnemonic_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let passwd = c_safe_c_char_pointer_to_string!(passwd_cstring);
        let mnemonic = c_safe_c_char_pointer_to_string!(mnemonic_cstring);
        let master_key = match wedpr_s_hierarchical_deterministic_wallet::hdw::create_master_key_en(
            &passwd, &mnemonic,
        ) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };

        let mut hdw_result = HdwResult::new();
        hdw_result.set_master_key(master_key);
        c_safe_proto_to_c_char_pointer!(hdw_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_extended_key'.
#[no_mangle]
pub extern "C" fn wedpr_extended_key(
    master_key_cstring: *mut c_char,
    purpose_type: c_uchar,
    coin_type: c_uchar,
    account: c_uchar,
    change: c_uchar,
    address_index: c_uchar,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let master_key_str =
            c_safe_c_char_pointer_to_string!(master_key_cstring);
        let master_key = match string_to_bytes(&master_key_str) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        let key_pair =
            match wedpr_s_hierarchical_deterministic_wallet::hdw::derive_extended_key(
                &master_key,
                purpose_type,
                coin_type,
                account,
                change,
                address_index,
            ) {
                Ok(v) => v,
                Err(_) => return ptr::null_mut(),
            };

        let mut hdw_result = HdwResult::new();
        hdw_result.set_key_pair(key_pair);
        c_safe_proto_to_c_char_pointer!(hdw_result)
    });
    c_safe_return!(result)
}
