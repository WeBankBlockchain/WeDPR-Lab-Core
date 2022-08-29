// Copyright 2022 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of ACV solution, targeting
//! Java-compatible architectures (including Android).
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};

use jni::sys::jbyteArray;
use protobuf::{self, Message};
use wedpr_ffi_common::utils::{
    java_jbytes_to_bytes, java_jstring_to_bytes, java_new_jobject,
    java_set_error_field_and_extract_jobject,
};

use wedpr_l_crypto_zkp_utils::bytes_to_point;

use wedpr_s_anonymous_ciphertext_voting;

use wedpr_s_protos::generated::acv::{
    DecryptedResultPartStorage, PollParametersStorage, RegistrationRequest,
    RegistrationResponse, VoteRequest, VoteResultStorage, VoteStorage,
};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.acv'.

// Result class name is 'com.webank.wedpr.acv.CoordinatorResult'.
const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/acv/VerifierResult";
fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

// Java interface section.
// All functions are under class name 'com.webank.wedpr.acv.NativeInterface'.
/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->verifyVoteRequest'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_verifyVoteRequest(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    vote_request: JString,
    public_key_bytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_vote_request = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_request,
        VoteRequest
    );
    let public_key =
        java_safe_jbytes_to_bytes!(_env, result_jobject, public_key_bytes);
    let verify_result =
        match wedpr_s_anonymous_ciphertext_voting::verifier::verify_vote_request(
            &pb_poll_parameters,
            &pb_vote_request,
            &public_key,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("verifyVoteRequest failed, err = {:?}", e),
                )
            },
        };
    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        verify_result,
        "verifyResult"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->verifyUnboundedVoteRequest'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_verifyUnboundedVoteRequest(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    vote_request: JString,
    public_key_bytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_vote_request = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_request,
        VoteRequest
    );
    let public_key =
        java_safe_jbytes_to_bytes!(_env, result_jobject, public_key_bytes);
    let verify_result = match wedpr_s_anonymous_ciphertext_voting::verifier::verify_unbounded_vote_request(&pb_poll_parameters,
    &pb_vote_request, &public_key)
    {
        Ok(v) => v,
        Err(e)=>{
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("verifyUnboundedVoteRequest failed, err = {:?}", e),
            )
        },
    };
    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        verify_result,
        "verifyResult"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->verifyUnboundedVoteRequestUnlisted'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_verifyUnboundedVoteRequestUnlisted(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    vote_request: JString,
    public_key_bytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_vote_request = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_request,
        VoteRequest
    );
    let public_key =
        java_safe_jbytes_to_bytes!(_env, result_jobject, public_key_bytes);
    let verify_result = match wedpr_s_anonymous_ciphertext_voting::verifier::verify_unbounded_vote_request_unlisted(&pb_poll_parameters,
    &pb_vote_request, &public_key)
    {
        Ok(v) => v,
        Err(e)=>{
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("verifyUnboundedVoteRequestUnlisted failed, err = {:?}", e),
            )
        },
    };
    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        verify_result,
        "verifyResult"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->verifyCountRequest'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_verifyCountRequest(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    encrypted_vote_sum: JString,
    counter_share: jbyteArray,
    partially_decrypted_result: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_encrypted_vote_sum = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        encrypted_vote_sum,
        VoteStorage
    );
    let pb_partially_decrypted_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        partially_decrypted_result,
        DecryptedResultPartStorage
    );
    let counter_share_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, counter_share);
    let counter_share_point =
        match bytes_to_point(&counter_share_bytes.to_vec()) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "verifyCountRequestUnlisted failed for covert \
                         counter_share error, err = {:?}",
                        e
                    ),
                )
            },
        };
    let verify_result = match wedpr_s_anonymous_ciphertext_voting::verifier::verify_count_request(&pb_poll_parameters,
    &pb_encrypted_vote_sum, &counter_share_point, &pb_partially_decrypted_result)
    {
        Ok(v) => v,
        Err(e)=>{
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("verifyCountRequest failed, err = {:?}", e),
            )
        },
    };
    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        verify_result,
        "verifyResult"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->verifyCountRequestUnlisted'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_verifyCountRequestUnlisted(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    encrypted_vote_sum: JString,
    counter_share: jbyteArray,
    partially_decrypted_result: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_encrypted_vote_sum = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        encrypted_vote_sum,
        VoteStorage
    );
    let pb_partially_decrypted_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        partially_decrypted_result,
        DecryptedResultPartStorage
    );
    let counter_share_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, counter_share);
    let counter_share_point =
        match bytes_to_point(&counter_share_bytes.to_vec()) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "verifyCountRequestUnlisted failed for covert \
                         counter_share error, err = {:?}",
                        e
                    ),
                )
            },
        };
    let verify_result = match wedpr_s_anonymous_ciphertext_voting::verifier::verify_count_request_unlisted(&pb_poll_parameters,
    &counter_share_point, &pb_encrypted_vote_sum, &pb_partially_decrypted_result)
    {
        Ok(v) => v,
        Err(e)=>{
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("verifyCountRequestUnlisted failed, err = {:?}", e),
            )
        },
    };
    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        verify_result,
        "verifyResult"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.acv.NativeInterface->verifyVoteResult'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_verifyVoteResult(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    vote_sum: JString,
    aggregated_decrypted_result: JString,
    vote_result: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_vote_sum =
        java_safe_jstring_to_pb!(_env, result_jobject, vote_sum, VoteStorage);
    let pb_aggregated_decrypted_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        aggregated_decrypted_result,
        DecryptedResultPartStorage
    );
    let pb_vote_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        vote_result,
        VoteResultStorage
    );
    let verify_result =
        match wedpr_s_anonymous_ciphertext_voting::verifier::verify_vote_result(
            &pb_poll_parameters,
            &pb_vote_sum,
            &pb_aggregated_decrypted_result,
            &pb_vote_result,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("verifyVoteResult failed, err = {:?}", e),
                )
            },
        };
    java_safe_set_boolean_field!(
        _env,
        result_jobject,
        verify_result,
        "verifyResult"
    );
    result_jobject.into_inner()
}

// Java interface section.
// All functions are under class name 'com.webank.wedpr.acv.NativeInterface'.
/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->verifyBlankBallot'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_verifyBlankBallot(
    _env: JNIEnv,
    _class: JClass,
    registration_request: JString,
    registration_response: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_registration_request = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        registration_request,
        RegistrationRequest
    );
    let pb_registration_response = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        registration_response,
        RegistrationResponse
    );
    let result =
        match wedpr_s_anonymous_ciphertext_voting::voter::verify_blank_ballot(
            &pb_registration_request,
            &pb_registration_response,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("verifyBlankBallot failed, err = {:?}", e),
                )
            },
        };
    // write verify_result
    java_safe_set_boolean_field!(_env, result_jobject, result, "verifyResult");
    result_jobject.into_inner()
}
