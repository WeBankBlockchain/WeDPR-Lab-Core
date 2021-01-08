// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of VCL solution, targeting
//! Java-compatible architectures (including Android).

extern crate jni;

#[macro_use]
extern crate wedpr_ffi_macros;

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jlong, jobject},
    JNIEnv,
};
use protobuf::{self, Message};
use wedpr_ffi_common::utils::{
    bytes_to_string, java_jstring_to_bytes, java_jstring_to_string,
    java_new_jobject, java_set_error_field_and_extract_jobject,
    string_to_bytes,
};
use wedpr_s_verifiable_confidential_ledger;

use wedpr_l_protos::generated::zkp::BalanceProof;
use wedpr_s_protos::generated::vcl::{
    EncodedConfidentialCredit, EncodedOwnerSecret,
};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.vcl'.

// Result class name is 'com.webank.wedpr.vcl.VclResult'.
const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/vcl/VclResult";

// Local macros and functions section.

macro_rules! decode_secret {
    ($_env:expr, $result_jobject:expr, $encoded_secret:expr) => {
        match wedpr_s_verifiable_confidential_ledger::vcl::OwnerSecret::decode(
            &$encoded_secret,
        ) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "Decode secret failed, input={}",
                        stringify!($encoded_secret)
                    ),
                )
            },
        }
    };
}

macro_rules! decode_credit {
    ($_env:expr, $result_jobject:expr, $encoded_credit:expr) => {
        match wedpr_s_verifiable_confidential_ledger::vcl::ConfidentialCredit::decode(
            &$encoded_credit,
        ) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "Decode credit failed, input={}",
                        stringify!($encoded_credit)
                    ),
                )
            },
        }
    };
}

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

// Java interface section.

// All functions are under class name 'com.webank.wedpr.vcl.NativeInterface'.

/// Java interface for 'com.webank.wedpr.vcl.NativeInterface->makeCredit'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_vcl_NativeInterface_makeCredit(
    _env: JNIEnv,
    _class: JClass,
    value: jlong,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let (credit, secret) =
        wedpr_s_verifiable_confidential_ledger::vcl::make_credit(value as u64);
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        credit.encode(),
        "confidentialCredit"
    );
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        secret.encode(),
        "ownerSecret"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.vcl.NativeInterface->proveSumBalance'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_vcl_NativeInterface_proveSumBalance(
    _env: JNIEnv,
    _class: JClass,
    c1_secret_jstring: JString,
    c2_secret_jstring: JString,
    c3_secret_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let c1_secret = decode_secret!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c1_secret_jstring,
            EncodedOwnerSecret
        )
    );
    let c2_secret = decode_secret!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c2_secret_jstring,
            EncodedOwnerSecret
        )
    );
    let c3_secret = decode_secret!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c3_secret_jstring,
            EncodedOwnerSecret
        )
    );

    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        wedpr_s_verifiable_confidential_ledger::vcl::prove_sum_balance(
            &c1_secret, &c2_secret, &c3_secret,
        ),
        "proof"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.vcl.NativeInterface->verifySumBalance'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_vcl_NativeInterface_verifySumBalance(
    _env: JNIEnv,
    _class: JClass,
    c1_credit_jstring: JString,
    c2_credit_jstring: JString,
    c3_credit_jstring: JString,
    proof_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let proof = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        proof_jstring,
        BalanceProof
    );

    let c1_credit = decode_credit!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c1_credit_jstring,
            EncodedConfidentialCredit
        )
    );
    let c2_credit = decode_credit!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c2_credit_jstring,
            EncodedConfidentialCredit
        )
    );
    let c3_credit = decode_credit!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c3_credit_jstring,
            EncodedConfidentialCredit
        )
    );

    let result =
        match wedpr_s_verifiable_confidential_ledger::vcl::verify_sum_balance(
            &c1_credit, &c2_credit, &c3_credit, &proof,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("verify_sum_balance failed, err = {:?}", e),
                )
            },
        };

    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        result,
        "verificationResult"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.vcl.NativeInterface->proveProductBalance'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_vcl_NativeInterface_proveProductBalance(
    _env: JNIEnv,
    _class: JClass,
    c1_secret_jstring: JString,
    c2_secret_jstring: JString,
    c3_secret_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let c1_secret = decode_secret!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c1_secret_jstring,
            EncodedOwnerSecret
        )
    );
    let c2_secret = decode_secret!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c2_secret_jstring,
            EncodedOwnerSecret
        )
    );
    let c3_secret = decode_secret!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c3_secret_jstring,
            EncodedOwnerSecret
        )
    );

    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        wedpr_s_verifiable_confidential_ledger::vcl::prove_product_balance(
            &c1_secret, &c2_secret, &c3_secret,
        ),
        "proof"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.vcl.NativeInterface->verifyProductBalance'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_vcl_NativeInterface_verifyProductBalance(
    _env: JNIEnv,
    _class: JClass,
    c1_credit_jstring: JString,
    c2_credit_jstring: JString,
    c3_credit_jstring: JString,
    proof_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let proof = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        proof_jstring,
        BalanceProof
    );

    let c1_credit = decode_credit!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c1_credit_jstring,
            EncodedConfidentialCredit
        )
    );
    let c2_credit = decode_credit!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c2_credit_jstring,
            EncodedConfidentialCredit
        )
    );
    let c3_credit = decode_credit!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            c3_credit_jstring,
            EncodedConfidentialCredit
        )
    );

    let result = match wedpr_s_verifiable_confidential_ledger::vcl::verify_product_balance(
        &c1_credit, &c2_credit, &c3_credit, &proof,
    ) {
        Ok(v) => v,
        Err(e) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("verify_product_balance failed, err = {:?}", e),
            )
        },
    };

    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        result,
        "verificationResult"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.vcl.NativeInterface->proveRange'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_vcl_NativeInterface_proveRange(
    _env: JNIEnv,
    _class: JClass,
    secret_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let secret = decode_secret!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            secret_jstring,
            EncodedOwnerSecret
        )
    );

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(
            &wedpr_s_verifiable_confidential_ledger::vcl::prove_range(&secret)
        ),
        "proof"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.vcl.NativeInterface->verifyRange'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_vcl_NativeInterface_verifyRange(
    _env: JNIEnv,
    _class: JClass,
    credit_jstring: JString,
    proof_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let proof_str =
        java_safe_jstring_to_string!(_env, result_jobject, proof_jstring);

    let proof = match string_to_bytes(&proof_str) {
        Ok(v) => v,
        Err(e) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("string_to_bytes failed, err = {:?}", e),
            )
        },
    };

    let credit = decode_credit!(
        _env,
        result_jobject,
        java_safe_jstring_to_pb!(
            _env,
            result_jobject,
            credit_jstring,
            EncodedConfidentialCredit
        )
    );

    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        wedpr_s_verifiable_confidential_ledger::vcl::verify_range(
            &credit, &proof
        ),
        "verificationResult"
    );
    result_jobject.into_inner()
}
