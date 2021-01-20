// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of VCL solution, targeting C/C++
//! compatible architectures (including iOS).

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;
#[macro_use]
extern crate wedpr_macros;

use protobuf::{self, Message};
use wedpr_crypto::utils::{bytes_to_string, string_to_bytes};
use wedpr_ffi_common::utils::{c_char_pointer_to_string, FAILURE, SUCCESS};
use wedpr_s_verifiable_confidential_ledger;

use wedpr_protos::generated::{
    vcl::{EncodedConfidentialCredit, EncodedOwnerSecret, VclResult},
    zkp::BalanceProof,
};

use libc::{c_char, c_ulong};
use std::{ffi::CString, panic, ptr};

// C/C++ FFI: C-style interfaces will be generated.

// Local macros and functions section.

macro_rules! decode_credit {
    ($encoded_credit:expr) => {
        match wedpr_s_verifiable_confidential_ledger::vcl::ConfidentialCredit::decode(
            &$encoded_credit,
        ) {
            Ok(v) => v,
            Err(_) => return FAILURE,
        }
    };
}

macro_rules! decode_secret {
    ($encoded_secret:expr) => {
        match wedpr_s_verifiable_confidential_ledger::vcl::OwnerSecret::decode(
            &$encoded_secret,
        ) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        }
    };
}

/// C interface for 'wedpr_vcl_make_credit'.
#[no_mangle]
pub extern "C" fn wedpr_vcl_make_credit(value: c_ulong) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let (credit, secret) =
            wedpr_s_verifiable_confidential_ledger::vcl::make_credit(
                value as u64,
            );

        let mut vcl_result = VclResult::new();
        vcl_result.set_credit(encodable_struct_to_string!(credit));
        vcl_result.set_secret(encodable_struct_to_string!(secret));
        c_safe_proto_to_c_char_pointer!(vcl_result)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_vcl_prove_sum_balance'.
#[no_mangle]
pub extern "C" fn wedpr_vcl_prove_sum_balance(
    c1_secret_cstring: *mut c_char,
    c2_secret_cstring: *mut c_char,
    c3_secret_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let c1_secret = decode_secret!(c_safe_c_char_pointer_to_proto!(
            c1_secret_cstring,
            EncodedOwnerSecret
        ));
        let c2_secret = decode_secret!(c_safe_c_char_pointer_to_proto!(
            c2_secret_cstring,
            EncodedOwnerSecret
        ));
        let c3_secret = decode_secret!(c_safe_c_char_pointer_to_proto!(
            c3_secret_cstring,
            EncodedOwnerSecret
        ));

        let proof =
            wedpr_s_verifiable_confidential_ledger::vcl::prove_sum_balance(
                &c1_secret, &c2_secret, &c3_secret,
            );
        c_safe_proto_to_c_char_pointer!(proof)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_vcl_verify_sum_balance'.
#[no_mangle]
pub extern "C" fn wedpr_vcl_verify_sum_balance(
    c1_credit_cstring: *mut c_char,
    c2_credit_cstring: *mut c_char,
    c3_credit_cstring: *mut c_char,
    proof_cstring: *mut c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let proof = c_safe_c_char_pointer_to_proto_with_error_value!(
            proof_cstring,
            BalanceProof,
            FAILURE
        );
        let c1_credit =
            decode_credit!(c_safe_c_char_pointer_to_proto_with_error_value!(
                c1_credit_cstring,
                EncodedConfidentialCredit,
                FAILURE
            ));
        let c2_credit =
            decode_credit!(c_safe_c_char_pointer_to_proto_with_error_value!(
                c2_credit_cstring,
                EncodedConfidentialCredit,
                FAILURE
            ));
        let c3_credit =
            decode_credit!(c_safe_c_char_pointer_to_proto_with_error_value!(
                c3_credit_cstring,
                EncodedConfidentialCredit,
                FAILURE
            ));

        match wedpr_s_verifiable_confidential_ledger::vcl::verify_sum_balance(
            &c1_credit, &c2_credit, &c3_credit, &proof,
        ) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}

/// C interface for 'wedpr_vcl_prove_product_balance'.
#[no_mangle]
pub extern "C" fn wedpr_vcl_prove_product_balance(
    c1_secret_cstring: *mut c_char,
    c2_secret_cstring: *mut c_char,
    c3_secret_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let c1_secret = decode_secret!(c_safe_c_char_pointer_to_proto!(
            c1_secret_cstring,
            EncodedOwnerSecret
        ));
        let c2_secret = decode_secret!(c_safe_c_char_pointer_to_proto!(
            c2_secret_cstring,
            EncodedOwnerSecret
        ));
        let c3_secret = decode_secret!(c_safe_c_char_pointer_to_proto!(
            c3_secret_cstring,
            EncodedOwnerSecret
        ));

        let proof =
            wedpr_s_verifiable_confidential_ledger::vcl::prove_product_balance(
                &c1_secret, &c2_secret, &c3_secret,
            );
        c_safe_proto_to_c_char_pointer!(proof)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_vcl_verify_product_balance'.
#[no_mangle]
pub extern "C" fn wedpr_vcl_verify_product_balance(
    c1_credit_cstring: *mut c_char,
    c2_credit_cstring: *mut c_char,
    c3_credit_cstring: *mut c_char,
    proof_cstring: *mut c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let proof = c_safe_c_char_pointer_to_proto_with_error_value!(
            proof_cstring,
            BalanceProof,
            FAILURE
        );
        let c1_credit =
            decode_credit!(c_safe_c_char_pointer_to_proto_with_error_value!(
                c1_credit_cstring,
                EncodedConfidentialCredit,
                FAILURE
            ));
        let c2_credit =
            decode_credit!(c_safe_c_char_pointer_to_proto_with_error_value!(
                c2_credit_cstring,
                EncodedConfidentialCredit,
                FAILURE
            ));
        let c3_credit =
            decode_credit!(c_safe_c_char_pointer_to_proto_with_error_value!(
                c3_credit_cstring,
                EncodedConfidentialCredit,
                FAILURE
            ));

        match wedpr_s_verifiable_confidential_ledger::vcl::verify_product_balance(
            &c1_credit, &c2_credit, &c3_credit, &proof,
        ) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}

/// C interface for 'wedpr_vcl_prove_range'.
#[no_mangle]
pub extern "C" fn wedpr_vcl_prove_range(
    secret_cstring: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let secret = decode_secret!(c_safe_c_char_pointer_to_proto!(
            secret_cstring,
            EncodedOwnerSecret
        ));

        let proof =
            wedpr_s_verifiable_confidential_ledger::vcl::prove_range(&secret);
        c_safe_string_to_c_char_pointer!(proof)
    });
    c_safe_return!(result)
}

/// C interface for 'wedpr_vcl_verify_range'.
#[no_mangle]
pub extern "C" fn wedpr_vcl_verify_range(
    credit_cstring: *mut c_char,
    proof_cstring: *mut c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let proof = c_safe_c_char_pointer_to_string_with_error_value!(
            proof_cstring,
            FAILURE
        );
        let credit =
            decode_credit!(c_safe_c_char_pointer_to_proto_with_error_value!(
                credit_cstring,
                EncodedConfidentialCredit,
                FAILURE
            ));

        match wedpr_s_verifiable_confidential_ledger::vcl::verify_range(
            &credit, &proof,
        ) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}
