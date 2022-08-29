// Copyright 2022 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of ACV solution, targeting
//! Java-compatible architectures (including Android).
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};

use protobuf::{self, Message};
use wedpr_ffi_common::utils::{
    bytes_to_string, java_jstring_to_bytes, java_jstring_to_string,
    java_new_jobject, java_set_error_field_and_extract_jobject,
};

use wedpr_s_anonymous_ciphertext_voting;

use wedpr_s_protos::generated::acv::{CounterSecret, VoteStorage};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.acv'.

// Result class name is 'com.webank.wedpr.acv.CoordinatorResult'.
const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/acv/CounterResult";
fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

// Java interface section.
// All functions are under class name 'com.webank.wedpr.acv.NativeInterface'.
/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->makeCounterSecret'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_makeCounterSecret(
    _env: JNIEnv,
    _class: JClass,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let secret =
        wedpr_s_anonymous_ciphertext_voting::counter::make_counter_secret();
    // write the secret
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        secret,
        "counter_secret"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->makeCounterParametersShare'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_makeCounterParametersShare(
    _env: JNIEnv,
    _class: JClass,
    counter_id_str: JString,
    counter_secret: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let counter_id =
        java_safe_jstring_to_string!(_env, result_jobject, counter_id_str);
    let pb_counter_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        counter_secret,
        CounterSecret
    );
    let counter_parameters_share = match wedpr_s_anonymous_ciphertext_voting::counter::make_parameters_share(&counter_id, &pb_counter_secret)
    {
        Ok(v) => v,
        Err(e)=>{
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("makeCounterParametersShare failed, err = {:?}", e),
            )
        },
    };
    // write the counter_parameters_share
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        counter_parameters_share,
        "counter_parameters_share"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.acv.NativeInterface->count'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_count(
    _env: JNIEnv,
    _class: JClass,
    counter_id_str: JString,
    counter_secret: JString,
    encrypted_vote_sum: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let counter_id =
        java_safe_jstring_to_string!(_env, result_jobject, counter_id_str);
    let pb_counter_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        counter_secret,
        CounterSecret
    );
    let pb_encrypted_vote_sum = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        encrypted_vote_sum,
        VoteStorage
    );
    let decrypted_result_part =
        match wedpr_s_anonymous_ciphertext_voting::counter::count(
            &counter_id,
            &pb_counter_secret,
            &pb_encrypted_vote_sum,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("count failed, err = {:?}", e),
                )
            },
        };
    // write the decrypted_result_part
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        decrypted_result_part,
        "counter_decrypted_result"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.acv.NativeInterface->countUnlisted'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_countUnlisted(
    _env: JNIEnv,
    _class: JClass,
    counter_id_str: JString,
    counter_secret: JString,
    encrypted_vote_sum: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let counter_id =
        java_safe_jstring_to_string!(_env, result_jobject, counter_id_str);
    let pb_counter_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        counter_secret,
        CounterSecret
    );
    let pb_encrypted_vote_sum = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        encrypted_vote_sum,
        VoteStorage
    );
    let decrypted_result_part =
        match wedpr_s_anonymous_ciphertext_voting::counter::count_unlisted(
            &counter_id,
            &pb_counter_secret,
            &pb_encrypted_vote_sum,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("countUnlisted failed, err = {:?}", e),
                )
            },
        };
    // write the decrypted_result_part
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        decrypted_result_part,
        "counter_decrypted_result"
    );
    result_jobject.into_inner()
}
