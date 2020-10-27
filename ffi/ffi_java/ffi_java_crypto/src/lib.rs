// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of crypto, targeting Java-compatible
//! architectures (including Android).

extern crate jni;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_macros;

use wedpr_crypto::{
    constant::{ECIES, HASH, SIGNATURE},
    signature::Signature,
};

use wedpr_ffi_common::utils::{
    java_jstring_to_bytes, java_new_jobject,
    java_set_error_field_and_extract_jobject,
};

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};

use wedpr_crypto::{ecies::Ecies, hash::Hash, utils::bytes_to_string};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.crypto'.

// Result class name is 'com.webank.wedpr.crypto.CryptoResult'.
const RESULT_CRYPTO_CLASS_NAME: &str = "com/webank/wedpr/crypto/CryptoResult";

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_CRYPTO_CLASS_NAME)
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1EciesEncrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1EciesEncrypt(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    message_hash_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let public_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, public_key_jstring);
    let encoded_message =
        java_safe_jstring_to_bytes!(_env, result_jobject, message_hash_jstring);

    let encrypted_data = match ECIES.encrypt(&public_key, &encoded_message) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "ECIES encrypt failed, encoded_message={}, public_key={}",
                    bytes_to_string(&encoded_message),
                    bytes_to_string(&public_key)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&encrypted_data),
        "encryptedData"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1EciesDecrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1EciesDecrypt(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    ciphertext_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);
    let ciphertext =
        java_safe_jstring_to_bytes!(_env, result_jobject, ciphertext_jstring);

    let decrypted_data = match ECIES.decrypt(&private_key, &ciphertext) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "ECIES decrypt failed, ciphertext={}",
                    bytes_to_string(&ciphertext)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&decrypted_data),
        "decryptedData"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1GenKeyPair'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1GenKeyPair(
    _env: JNIEnv,
    _class: JClass,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let (pk, sk) = SIGNATURE.generate_keypair();
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&pk),
        "publicKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&sk),
        "privateKey"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1Sign'.
// TODO: Add secp256k1SignUtf8 to allow non-encoded UTF8 input.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1Sign(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    msg_hash_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);

    let signature = match SIGNATURE.sign(&private_key, &msg_hash) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "secp256k1 sign failed, msg_hash={}",
                    bytes_to_string(&msg_hash)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&signature),
        "signature"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1Verify'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1Verify(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    msg_hash_jstring: JString,
    signature_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let public_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, public_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);
    let signature =
        java_safe_jstring_to_bytes!(_env, result_jobject, signature_jstring);

    let result = SIGNATURE.verify(&public_key, &msg_hash, &signature);

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->keccak256Hash'.
// TODO: Add keccak256HashUtf8 to allow non-encoded UTF8 input.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_keccak256Hash(
    _env: JNIEnv,
    _class: JClass,
    encoded_message_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let encoded_message_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jstring
    );

    let hash = HASH.hash(&encoded_message_bytes);

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&hash),
        "hash"
    );
    result_jobject.into_inner()
}
