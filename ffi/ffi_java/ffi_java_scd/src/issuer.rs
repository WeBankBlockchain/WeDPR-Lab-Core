// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of a certificate issuer in SCD
//! solution, targeting Java-compatible architectures (including Android).

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

use selective_certificate_disclosure;

use wedpr_protos::generated::scd::{
    CertificateSchema, CertificateTemplate, SignCertificateRequest,
    TemplatePrivateKey,
};

use wedpr_crypto::utils::bytes_to_string;

const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/scd/IssuerResult";

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

/// Java interface for
/// 'com.webank.wedpr.scd.NativeInterface->issuerMakeCertificateTemplate'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_scd_NativeInterface_issuerMakeCertificateTemplate(
    _env: JNIEnv,
    _class: JClass,
    schema_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let schema_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        schema_jstring,
        CertificateSchema
    );

    let (certificate_template, template_private_key) =
        match selective_certificate_disclosure::issuer::make_certificate_template(
            &schema_pb,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "issuer make_certificate_template failed, err = {:?}",
                        e
                    ),
                )
            },
        };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        certificate_template,
        "certificateTemplate"
    );
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        template_private_key,
        "templatePrivateKey"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.scd.NativeInterface->issuerSignCertificate'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_scd_NativeInterface_issuerSignCertificate(
    _env: JNIEnv,
    _class: JClass,
    certificate_template_jstring: JString,
    template_private_key_jstring: JString,
    sign_request_jstring: JString,
    user_id_jstring: JString,
    user_nonce_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let certificate_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        certificate_template_jstring,
        CertificateTemplate
    );
    let template_private_key_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        template_private_key_jstring,
        TemplatePrivateKey
    );
    let sign_request_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        sign_request_jstring,
        SignCertificateRequest
    );
    let user_id =
        java_safe_jstring_to_string!(_env, result_jobject, user_id_jstring);
    let user_nonce_str =
        java_safe_jstring_to_string!(_env, result_jobject, user_nonce_jstring);

    let (certificate_signature, issuer_nonce_str) =
        match selective_certificate_disclosure::issuer::sign_certificate(
            &certificate_template_pb,
            &template_private_key_pb,
            &sign_request_pb,
            &user_id,
            &user_nonce_str,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("issuer sign_certificate failed, err = {:?}", e),
                )
            },
        };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        certificate_signature,
        "certificateSignature"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        issuer_nonce_str,
        "issuerNonce"
    );
    result_jobject.into_inner()
}
