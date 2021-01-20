// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

extern crate jni;

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jobject},
    JNIEnv,
};
use wedpr_ffi_common::utils::{
    java_jstring_to_string, java_new_jobject,
    java_set_error_field_and_extract_jobject,
};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.hdw'.

// Result class name is 'com/webank/wedpr/hdw/HdwResult'.
const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/hdw/HdwResult";

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

// Java interface section.

// All functions are under class name 'com.webank.wedpr.hdw.NativeInterface'.

/// Java interface for 'com.webank.wedpr.hdw.NativeInterface->createMnemonic'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_hdw_NativeInterface_createMnemonic(
    _env: JNIEnv,
    _class: JClass,
    word_count: jint,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let mnemonic =
        match wedpr_s_hierarchical_deterministic_wallet::hdw::create_mnemonic_en(
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

/// Java interface for 'com.webank.wedpr.hdw.NativeInterface->createMasterKey'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_hdw_NativeInterface_createMasterKey(
    _env: JNIEnv,
    _class: JClass,
    passwd_jstring: JString,
    mnemonic_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let passwd =
        java_safe_jstring_to_string!(_env, result_jobject, passwd_jstring);

    let mnemonic =
        java_safe_jstring_to_string!(_env, result_jobject, mnemonic_jstring);

    let master_key =
        match wedpr_s_hierarchical_deterministic_wallet::hdw::create_master_key_en(&passwd, &mnemonic) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("create_master_key failed, err = {:?}", e),
                )
            },
        };

    java_safe_set_string_field!(_env, result_jobject, master_key, "masterKey");
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.hdw.NativeInterface->extendedKey'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_hdw_NativeInterface_extendedKey(
    _env: JNIEnv,
    _class: JClass,
    master_key_jstring: JString,
    purpose_type: jint,
    coin_type: jint,
    account: jint,
    change: jint,
    address_index: jint,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let master_key =
        java_safe_jstring_to_string!(_env, result_jobject, master_key_jstring);

    let key_pair =
        match wedpr_s_hierarchical_deterministic_wallet::hdw::derive_extended_key(
            &master_key,
            purpose_type as u8,
            coin_type as u8,
            account as u8,
            change as u8,
            address_index as u8,
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
        key_pair.get_extended_private_key(),
        "extendedPrivateKey"
    );

    java_safe_set_string_field!(
        _env,
        result_jobject,
        key_pair.get_extended_public_key(),
        "extendedPublicKey"
    );
    result_jobject.into_inner()
}
