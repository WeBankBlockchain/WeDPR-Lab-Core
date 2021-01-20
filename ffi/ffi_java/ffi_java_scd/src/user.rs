// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a certificate user (holder) in
//! SCD solution, targeting Java-compatible architectures (including Android).

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

use wedpr_s_selective_certificate_disclosure;

use wedpr_protos::generated::scd::{
    AttributeDict, CertificateSignature, CertificateTemplate,
    VerificationRuleSet,
};

use wedpr_crypto::utils::bytes_to_string;

const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/scd/UserResult";

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

/// Java interface for
/// 'com.webank.wedpr.scd.NativeInterface->userFillCertificate'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_scd_NativeInterface_userFillCertificate(
    _env: JNIEnv,
    _class: JClass,
    attribute_dict_jstring: JString,
    certificate_template_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let attribute_dict_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        attribute_dict_jstring,
        AttributeDict
    );
    let certificate_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        certificate_template_jstring,
        CertificateTemplate
    );

    let (
        sign_certificate_request,
        user_private_key_str,
        certificate_secrets_blinding_factors_str,
        user_nonce_str,
    ) = match wedpr_s_selective_certificate_disclosure::user::fill_certificate(
        &attribute_dict_pb,
        &certificate_template_pb,
    ) {
        Ok(v) => v,
        Err(e) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("user fill_certificate failed, err = {:?}", e),
            )
        },
    };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        sign_certificate_request,
        "signCertificateRequest"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        user_private_key_str,
        "userPrivateKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        certificate_secrets_blinding_factors_str,
        "certificateSecretsBlindingFactors"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        user_nonce_str,
        "userNonce"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.scd.NativeInterface->userBlindCertificateSignature'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_scd_NativeInterface_userBlindCertificateSignature(
    _env: JNIEnv,
    _class: JClass,
    certificate_signature_jstring: JString,
    attribute_dict_jstring: JString,
    certificate_template_jstring: JString,
    user_private_key_jstring: JString,
    certificate_secrets_blinding_factors_jstring: JString,
    issuer_nonce_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let certificate_signature_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        certificate_signature_jstring,
        CertificateSignature
    );
    let attribute_dict_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        attribute_dict_jstring,
        AttributeDict
    );
    let certificate_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        certificate_template_jstring,
        CertificateTemplate
    );
    let user_private_key = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        user_private_key_jstring
    );
    let certificate_secrets_blinding_factors = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        certificate_secrets_blinding_factors_jstring
    );
    let issuer_nonce = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        issuer_nonce_jstring
    );

    let blinded_certificate_signature =
        match wedpr_s_selective_certificate_disclosure::user::blind_certificate_signature(
            &certificate_signature_pb,
            &attribute_dict_pb,
            &certificate_template_pb,
            &user_private_key,
            &certificate_secrets_blinding_factors,
            &issuer_nonce,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "user blind_certificate_signature failed, err = {:?}",
                        e
                    ),
                )
            },
        };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        blinded_certificate_signature,
        "certificateSignature"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.scd.NativeInterface->userProveSelectiveDisclosure'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_scd_NativeInterface_userProveSelectiveDisclosure(
    _env: JNIEnv,
    _class: JClass,
    rule_set_jstring: JString,
    certificate_signature_jstring: JString,
    attribute_dict_jstring: JString,
    certificate_template_jstring: JString,
    user_private_key_jstring: JString,
    verification_nonce_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let rule_set_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        rule_set_jstring,
        VerificationRuleSet
    );
    let certificate_signature_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        certificate_signature_jstring,
        CertificateSignature
    );
    let attribute_dict_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        attribute_dict_jstring,
        AttributeDict
    );
    let certificate_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        certificate_template_jstring,
        CertificateTemplate
    );
    let user_private_key = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        user_private_key_jstring
    );
    let verification_nonce = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        verification_nonce_jstring
    );

    let verify_request =
        match wedpr_s_selective_certificate_disclosure::user::prove_selective_disclosure(
            &rule_set_pb,
            &certificate_signature_pb,
            &attribute_dict_pb,
            &certificate_template_pb,
            &user_private_key,
            &verification_nonce,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "user prove_selective_disclosure failed, err = {:?}",
                        e
                    ),
                )
            },
        };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        verify_request,
        "verifyRequest"
    );
    result_jobject.into_inner()
}
