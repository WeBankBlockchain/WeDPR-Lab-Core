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
    AttributeTemplate, CredentialSignatureRequest, CredentialTemplate,
    TemplateSecretKey,
};

use wedpr_crypto::utils::bytes_to_string;

const RESULT_JAVA_CLASS_NAME: &str =
    "com/webank/wedpr/selectivedisclosure/IssuerResult";

fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_selectivedisclosure_NativeInterface_issuerMakeCredentialTemplate(
    _env: JNIEnv,
    _class: JClass,
    attribute_template_jstring: JString,
) -> jobject
{
    // new jobject
    let result_jobject = get_result_jobject(&_env);

    let attribute_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        attribute_template_jstring,
        AttributeTemplate
    );

    let (credential_template, template_secret_key) =
        match selective_disclosure::issuer::make_credential_template(
            &attribute_template_pb,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "issuer make_credential_template failed, err = {:?}",
                        e
                    ),
                )
            },
        };

    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        credential_template,
        "credentialTemplate"
    );
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        template_secret_key,
        "templateSecretKey"
    );
    result_jobject.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_selectivedisclosure_NativeInterface_issuerSignCredential(
    _env: JNIEnv,
    _class: JClass,
    credential_template_jstring: JString,
    template_secret_key_jstring: JString,
    credential_request_jstring: JString,
    user_id_jstring: JString,
    nonce_jstring: JString,
) -> jobject
{
    // new jobject
    let result_jobject = get_result_jobject(&_env);

    let credential_template_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_template_jstring,
        CredentialTemplate
    );

    let template_secret_key_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        template_secret_key_jstring,
        TemplateSecretKey
    );

    let credential_request_pb = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        credential_request_jstring,
        CredentialSignatureRequest
    );

    let user_id =
        java_safe_jstring_to_string!(_env, result_jobject, user_id_jstring);

    let nonce_str =
        java_safe_jstring_to_string!(_env, result_jobject, nonce_jstring);

    let (credential_signature, cred_issuance_nonce_str) =
        match selective_disclosure::issuer::sign_credential(
            &credential_template_pb,
            &template_secret_key_pb,
            &credential_request_pb,
            &user_id,
            &nonce_str,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("issuer sign_credential failed, err = {:?}", e),
                )
            },
        };

    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        credential_signature,
        "credentialSignature"
    );

    java_safe_set_string_field!(
        _env,
        result_jobject,
        cred_issuance_nonce_str,
        "issuerNonce"
    );

    result_jobject.into_inner()
}
