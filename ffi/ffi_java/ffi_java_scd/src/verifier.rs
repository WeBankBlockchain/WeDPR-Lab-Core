// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a certificate verifier in SCD
//! solution, targeting Java-compatible architectures (including Android).

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};
use protobuf::{self, Message};

use wedpr_ffi_common::utils::{
    java_jstring_to_bytes, java_new_jobject,
    java_set_error_field_and_extract_jobject,
};

use selective_certificate_disclosure;

use wedpr_protos::generated::scd::{VerificationRuleSet, VerifyRequest};

use wedpr_crypto::utils::bytes_to_string;

const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/scd/VerifierResult";

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

/// Java interface for
/// 'com.webank.wedpr.scd.
/// NativeInterface->verifierGetRevealedAttrsFromVerifyRequest'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_scd_NativeInterface_verifierGetRevealedAttrsFromVerifyRequest(
    _env: JNIEnv,
    _class: JClass,
    verify_request_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let verify_request_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        verify_request_jstring,
        VerifyRequest
    );

    let revealed_attribute_dict =
        match selective_certificate_disclosure::verifier::get_revealed_attributes(
            &verify_request_pb,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "verifier get_revealed_attributes failed, err = {:?}",
                        e
                    ),
                )
            },
        };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        revealed_attribute_dict,
        "revealedAttributeDict"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.scd.NativeInterface->verifierVerifySelectiveDisclosure'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_scd_NativeInterface_verifierVerifySelectiveDisclosure(
    _env: JNIEnv,
    _class: JClass,
    rule_set_jstring: JString,
    verify_request_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let rule_set_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        rule_set_jstring,
        VerificationRuleSet
    );
    let verify_request_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        verify_request_jstring,
        VerifyRequest
    );

    let bool_result = match selective_certificate_disclosure::verifier::verify_selective_disclosure(
        &rule_set_pb,
        &verify_request_pb,
    ) {
        Ok(v) => v,
        Err(e) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("verifier verify_proof failed, err = {:?}", e),
            )
        },
    };
    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        bool_result,
        "boolResult"
    );
    result_jobject.into_inner()
}
