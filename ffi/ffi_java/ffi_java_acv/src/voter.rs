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
    bytes_to_string, java_jstring_to_bytes, java_new_jobject,
    java_set_error_field_and_extract_jobject,
};

use wedpr_s_anonymous_ciphertext_voting;

use wedpr_s_protos::generated::acv::{
    PollParametersStorage, RegistrationResponse, VoteChoices, VoterSecret,
};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.acv'.

// Result class name is 'com.webank.wedpr.acv.CoordinatorResult'.
const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/acv/VoterResult";
fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

// Java interface section.
// All functions are under class name 'com.webank.wedpr.acv.NativeInterface'.
/// Java interface for 'com.webank.wedpr.acv.NativeInterface->makeVoterSecret'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_makeVoterSecret(
    _env: JNIEnv,
    _class: JClass,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let secret =
        wedpr_s_anonymous_ciphertext_voting::voter::make_voter_secret();
    // write the secret
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        secret,
        "voter_secret"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->generateRegistrationBlindingPoint'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_generateRegistrationBlindingPoint(
    _env: JNIEnv,
    _class: JClass,
    vote_secret: JString,
    poll_parameters: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_vote_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_secret,
        VoterSecret
    );
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let registration_blinding_point = match wedpr_s_anonymous_ciphertext_voting::voter::generate_registration_blinding_point(
        &pb_vote_secret, &pb_poll_parameters
    )
    {
        Ok(v) => v,
        Err(e)=>{
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("generateRegistrationBlindingPoint failed, err = {:?}", e),
            )
        },
    };
    // write registration_blinding_point
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        registration_blinding_point,
        "registration_blinding_point"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->makeUnboundedRegistrationRequest'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_makeUnboundedRegistrationRequest(
    _env: JNIEnv,
    _class: JClass,
    zero_secret: JString,
    vote_secret: JString,
    poll_parameters: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_zero_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        zero_secret,
        VoterSecret
    );
    let pb_vote_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_secret,
        VoterSecret
    );
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let registration_request = match wedpr_s_anonymous_ciphertext_voting::voter::make_unbounded_registration_request(
        &pb_zero_secret, &pb_vote_secret, &pb_poll_parameters
    )
    {
        Ok(v) => v,
        Err(e)=>{
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("makeUnboundedRegistrationRequest failed, err = {:?}", e),
            )
        },
    };
    // write the registration_request
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        registration_request,
        "registration_request"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.acv.NativeInterface->vote'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_vote(
    _env: JNIEnv,
    _class: JClass,
    voter_secret: JString,
    vote_choices: JString,
    registration_response: JString,
    poll_parameters: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_voter_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        voter_secret,
        VoterSecret
    );
    let pb_vote_choices = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_choices,
        VoteChoices
    );
    let pb_registration_response = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        registration_response,
        RegistrationResponse
    );
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let vote_request = match wedpr_s_anonymous_ciphertext_voting::voter::vote(
        &pb_voter_secret,
        &pb_vote_choices,
        &pb_registration_response,
        &pb_poll_parameters,
    ) {
        Ok(v) => v,
        Err(e) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("vote failed, err = {:?}", e),
            )
        },
    };
    // write the vote request
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        vote_request,
        "vote_request"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.acv.NativeInterface->voteUnbounded'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_voteUnbounded(
    _env: JNIEnv,
    _class: JClass,
    voter_secret: JString,
    zero_secret: JString,
    vote_choices: JString,
    registration_response: JString,
    poll_parameters: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_voter_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        voter_secret,
        VoterSecret
    );
    let pb_zero_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        zero_secret,
        VoterSecret
    );
    let pb_vote_choices = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_choices,
        VoteChoices
    );
    let pb_registration_response = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        registration_response,
        RegistrationResponse
    );
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let vote_request =
        match wedpr_s_anonymous_ciphertext_voting::voter::vote_unbounded(
            &pb_voter_secret,
            &pb_zero_secret,
            &pb_vote_choices,
            &pb_registration_response,
            &pb_poll_parameters,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("voteUnbounded failed, err = {:?}", e),
                )
            },
        };
    // write the vote request
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        vote_request,
        "vote_request"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->voteUnboundedUnlisted'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_voteUnboundedUnlisted(
    _env: JNIEnv,
    _class: JClass,
    voter_secret: JString,
    zero_secret: JString,
    vote_choices: JString,
    registration_response: JString,
    poll_parameters: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_voter_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        voter_secret,
        VoterSecret
    );
    let pb_zero_secret = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        zero_secret,
        VoterSecret
    );
    let pb_vote_choices = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_choices,
        VoteChoices
    );
    let pb_registration_response = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        registration_response,
        RegistrationResponse
    );
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let vote_request =
        match wedpr_s_anonymous_ciphertext_voting::voter::vote_unbounded_unlisted(
            &pb_voter_secret,
            &pb_zero_secret,
            &pb_vote_choices,
            &pb_registration_response,
            &pb_poll_parameters,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("voteUnboundedUnlisted failed, err = {:?}", e),
                )
            },
        };
    // write the vote request
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        vote_request,
        "vote_request"
    );
    result_jobject.into_inner()
}
