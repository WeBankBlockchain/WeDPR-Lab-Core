// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of selective_disclosure solution,
//! targeting Java-compatible architectures (including Android).

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};
use protobuf::{self, Message};

use wedpr_ffi_common::utils::{
    java_jstring_to_bytes, java_jstring_to_string, java_new_jobject,
    java_set_error_field_and_extract_jobject,
};

use selective_disclosure;

use wedpr_protos::generated::selective_disclosure::{
    CredentialInfo, CredentialSignature, CredentialTemplate, VerificationRule,
};

use wedpr_crypto::utils::bytes_to_string;

const RESULT_JAVA_CLASS_NAME: &str =
    "com/webank/wedpr/selectivedisclosure/UserResult";

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_selectivedisclosure_NativeInterface_userMakeCredential(
    _env: JNIEnv,
    _class: JClass,
    credential_info_jstring: JString,
    credential_template_jstring: JString,
) -> jobject
{
    // new jobject
    let result_jobject = get_result_jobject(&_env);

    let credential_info_input_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_info_jstring,
        CredentialInfo
    );

    let credential_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_template_jstring,
        CredentialTemplate
    );

    let (
        credential_signature_request,
        master_secret_str,
        credential_secrets_blinding_factors_str,
        nonce_credential_str,
    ) = match selective_disclosure::user::make_credential(
        &credential_info_input_pb,
        &credential_template_pb,
    ) {
        Ok(v) => v,
        Err(e) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("user make_credential failed, err = {:?}", e),
            )
        },
    };

    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        credential_signature_request,
        "credentialSignatureRequest"
    );

    java_safe_set_string_field!(
        _env,
        result_jobject,
        master_secret_str,
        "masterSecret"
    );

    java_safe_set_string_field!(
        _env,
        result_jobject,
        credential_secrets_blinding_factors_str,
        "credentialSecretsBlindingFactors"
    );

    java_safe_set_string_field!(
        _env,
        result_jobject,
        nonce_credential_str,
        "userNonce"
    );

    result_jobject.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_selectivedisclosure_NativeInterface_userBlindCredentialSignature(
    _env: JNIEnv,
    _class: JClass,
    credential_signature_jstring: JString,
    credential_info_jstring: JString,
    credential_template_jstring: JString,
    master_secret_jstring: JString,
    credential_secrets_blinding_factors_jstring: JString,
    nonce_credential_jstring: JString,
) -> jobject
{
    // new jobject
    let result_jobject = get_result_jobject(&_env);

    let credential_signature_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_signature_jstring,
        CredentialSignature
    );

    let credential_info_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_info_jstring,
        CredentialInfo
    );

    let credential_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_template_jstring,
        CredentialTemplate
    );

    let master_secret = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        master_secret_jstring
    );
    let credential_secrets_blinding_factors = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        credential_secrets_blinding_factors_jstring
    );
    let nonce_credential = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        nonce_credential_jstring
    );

    let new_credential_signature =
        match selective_disclosure::user::blind_credential_signature(
            &credential_signature_pb,
            &credential_info_pb,
            &credential_template_pb,
            &master_secret,
            &credential_secrets_blinding_factors,
            &nonce_credential,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "user blind_credential_signature failed, err = {:?}",
                        e
                    ),
                )
            },
        };

    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        new_credential_signature,
        "credentialSignature"
    );

    result_jobject.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_selectivedisclosure_NativeInterface_userProveCredentialInfo(
    _env: JNIEnv,
    _class: JClass,
    verification_predicate_rule_jstring: JString,
    credential_signature_jstring: JString,
    credential_info_jstring: JString,
    credential_template_jstring: JString,
    master_secret_jstring: JString,
) -> jobject
{
    // new jobject
    let result_jobject = get_result_jobject(&_env);

    let verification_predicate_rule_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        verification_predicate_rule_jstring,
        VerificationRule
    );

    let credential_signature_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_signature_jstring,
        CredentialSignature
    );

    let credential_info_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_info_jstring,
        CredentialInfo
    );

    let credential_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_template_jstring,
        CredentialTemplate
    );

    let master_secret = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        master_secret_jstring
    );

    let request =
        match selective_disclosure::user::prove_selected_credential_info(
            &verification_predicate_rule_pb,
            &credential_signature_pb,
            &credential_info_pb,
            &credential_template_pb,
            &master_secret,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "user prove_selected_credential_info failed, err = \
                         {:?}",
                        e
                    ),
                )
            },
        };

    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        request,
        "verificationRequest"
    );

    result_jobject.into_inner()
}
