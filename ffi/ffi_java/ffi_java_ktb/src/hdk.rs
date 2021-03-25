// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of HDK solution, targeting
//! Java-compatible architectures (including Android).

extern crate jni;

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jobject},
    JNIEnv,
};
use wedpr_ffi_common::utils::{
    bytes_to_string, java_jstring_to_bytes, java_jstring_to_string,
    java_new_jobject, java_set_error_field_and_extract_jobject,
};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.ktv.hdk'.

// Result class name is 'com/webank/wedpr/ktb/hdk/HdkResult'.
const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/ktb/hdk/HdkResult";

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

// Java interface section.

// All functions are under class name 'com.webank.wedpr.hdk.NativeInterface'.

/// Java interface for 'com.webank.wedpr.hdk.NativeInterface->createMnemonicEn'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_ktb_hdk_NativeInterface_createMnemonicEn(
    _env: JNIEnv,
    _class: JClass,
    word_count: jint,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    // TODO: Extract a macro for this type of function call if feasible.
    let mnemonic =
        match wedpr_s_hierarchical_deterministic_key::hdk::create_mnemonic_en(
            word_count as u8,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("create_mnemonic failed, err = {:?}", e),
                )
            },
        };
    java_safe_set_string_field!(_env, result_jobject, mnemonic, "mnemonic");
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.hdk.NativeInterface->createMasterKeyEn'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_ktb_hdk_NativeInterface_createMasterKeyEn(
    _env: JNIEnv,
    _class: JClass,
    password_jstring: JString,
    mnemonic_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let password =
        java_safe_jstring_to_string!(_env, result_jobject, password_jstring);
    let mnemonic =
        java_safe_jstring_to_string!(_env, result_jobject, mnemonic_jstring);

    // TODO: Extract a macro for this type of function call if feasible.
    let master_key =
        match wedpr_s_hierarchical_deterministic_key::hdk::create_master_key_en(
            &password, &mnemonic,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("create_master_key failed, err = {:?}", e),
                )
            },
        };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&master_key),
        "masterKey"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.hdk.NativeInterface->deriveExtendedKey'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_ktb_hdk_NativeInterface_deriveExtendedKey(
    _env: JNIEnv,
    _class: JClass,
    master_key_jstring: JString,
    purpose_type: jint,
    asset_type: jint,
    account: jint,
    change: jint,
    address_index: jint,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let master_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, master_key_jstring);

    let key_derivation_path =
        wedpr_s_hierarchical_deterministic_key::hdk::create_key_derivation_path(
            purpose_type,
            asset_type,
            account,
            change,
            address_index,
        );
    // TODO: Extract a macro for this type of function call if feasible.
    let key_pair =
        match wedpr_s_hierarchical_deterministic_key::hdk::derive_extended_key(
            &master_key,
            &key_derivation_path,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("extended_key failed, err = {:?}", e),
                )
            },
        };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&key_pair.get_extended_private_key()),
        "extendedPrivateKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&key_pair.get_extended_public_key()),
        "extendedPublicKey"
    );
    result_jobject.into_inner()
}
