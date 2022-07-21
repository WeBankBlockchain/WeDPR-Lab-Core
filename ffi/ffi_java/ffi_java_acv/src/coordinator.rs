// Copyright 2022 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of ACV solution, targeting
//! Java-compatible architectures (including Android).
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jlong, jobject},
    JNIEnv,
};

use protobuf::{self, Message};
use wedpr_ffi_common::utils::{
    bytes_to_string, java_jstring_to_bytes, java_new_jobject,
    java_set_error_field_and_extract_jobject,
};

use wedpr_s_anonymous_ciphertext_voting;
use wedpr_s_protos::generated::acv::{
    CandidateList, CounterParametersStorage, DecryptedResultPartStorage,
    PollParametersStorage, RegistrationRequest, VoteStorage,
};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.acv'.

// Result class name is 'com.webank.wedpr.acv.CoordinatorResult'.
const RESULT_JAVA_CLASS_NAME: &str = "com/webank/wedpr/acv/CoordinatorResult";
fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_CLASS_NAME)
}

// Java interface section.
// All functions are under class name 'com.webank.wedpr.acv.NativeInterface'.
/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->makePollParameters'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_makePollParameters(
    _env: JNIEnv,
    _class: JClass,
    candidate_list: JString,
    counter_parameters: JString,
) -> jobject {
    // get the result object
    let result_jobject = get_result_jobject(&_env);
    let pb_candidate_list = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        candidate_list,
        CandidateList
    );
    let pb_counter_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        counter_parameters,
        CounterParametersStorage
    );
    let poll_parameters =
        match wedpr_s_anonymous_ciphertext_voting::coordinator::make_poll_parameters(
            &pb_candidate_list,
            &pb_counter_parameters,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("make_poll_parameters failed, err = {:?}", e),
                )
            },
        };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        poll_parameters,
        "poll_parameters"
    );
    result_jobject.into_inner()
}

/// Java interface for 'com.webank.wedpr.acv.NativeInterface->certifyVoter'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_certifyVoter(
    _env: JNIEnv,
    _class: JClass,
    secret_key_data: JString,
    registration_request: JString,
    voter_weight: jint,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let certify_result =
        match wedpr_s_anonymous_ciphertext_voting::coordinator::certify_voter(
            &java_safe_jstring_to_bytes!(_env, result_jobject, secret_key_data),
            &java_safe_jstring_to_pb!(
                _env,
                result_jobject,
                registration_request,
                RegistrationRequest
            ),
            voter_weight as u32,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("certifyVoter failed, err = {:?}", e),
                )
            },
        };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        certify_result,
        "registration_response"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->certifyUnboundedVoter'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_certifyUnboundedVoter(
    _env: JNIEnv,
    _class: JClass,
    secret_key_data: JString,
    registration_request: JString,
    voter_weight: jint,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let certify_result =
        match wedpr_s_anonymous_ciphertext_voting::coordinator::certify_unbounded_voter(
            &java_safe_jstring_to_bytes!(_env, result_jobject, secret_key_data),
            &java_safe_jstring_to_pb!(
                _env,
                result_jobject,
                registration_request,
                RegistrationRequest
            ),
            voter_weight as u32,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("certifyUnboundedVoter failed, err = {:?}", e),
                )
            },
        };
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        certify_result,
        "registration_response"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->aggregateVoteSumResponse'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_aggregateVoteSumResponse(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    vote_part: JString,
    vote_sum: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_vote_part =
        java_safe_jstring_to_pb!(_env, result_jobject, vote_part, VoteStorage);
    let mut pb_vote_sum =
        java_safe_jstring_to_pb!(_env, result_jobject, vote_sum, VoteStorage);
    // aggregate_vote_sum_response
    let ret =
        match wedpr_s_anonymous_ciphertext_voting::coordinator::aggregate_vote_sum_response(
            &pb_poll_parameters,
            &pb_vote_part,
            &mut pb_vote_sum,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("aggregateVoteSumResponse failed, err = {:?}", e),
                )
            },
        };
    if !ret {
        return java_set_error_field_and_extract_jobject(
            &_env,
            &result_jobject,
            &format!("aggregateVoteSumResponse failed"),
        );
    }
    // write back pb_vote_sum
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        pb_vote_sum,
        "vote_sum"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->aggregateVoteSumResponseUnlisted'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_aggregateVoteSumResponseUnlisted(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    vote_part: JString,
    vote_sum: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_vote_part =
        java_safe_jstring_to_pb!(_env, result_jobject, vote_part, VoteStorage);
    let mut pb_vote_sum =
        java_safe_jstring_to_pb!(_env, result_jobject, vote_sum, VoteStorage);
    // aggregate_vote_sum_response
    let ret = match wedpr_s_anonymous_ciphertext_voting::coordinator::aggregate_vote_sum_response_unlisted(
            &pb_poll_parameters,
            &pb_vote_part,
            &mut pb_vote_sum,
        ) {
        Ok(v) => v,
        Err(e) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("aggregateVoteSumResponse failed, err = {:?}", e),
            )
        },
    };
    if !ret {
        return java_set_error_field_and_extract_jobject(
            &_env,
            &result_jobject,
            &format!("aggregateVoteSumResponse failed"),
        );
    }
    // write back pb_vote_sum
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        pb_vote_sum,
        "vote_sum"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->aggregateDecryptedPartSum'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_aggregateDecryptedPartSum(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    partially_decrypted_result: JString,
    aggregated_decrypted_result: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_partially_decrypted_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        partially_decrypted_result,
        DecryptedResultPartStorage
    );
    let mut pb_aggregated_decrypted_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        aggregated_decrypted_result,
        DecryptedResultPartStorage
    );
    let result =
        match wedpr_s_anonymous_ciphertext_voting::coordinator::aggregate_decrypted_part_sum(
            &pb_poll_parameters,
            &pb_partially_decrypted_result,
            &mut pb_aggregated_decrypted_result,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("aggregateDecryptedPartSum failed, err = {:?}", e),
                )
            },
        };
    if !result {
        return java_set_error_field_and_extract_jobject(
            &_env,
            &result_jobject,
            &format!("aggregateDecryptedPartSum failed"),
        );
    }
    // write back pb_aggregated_decrypted_result
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        pb_aggregated_decrypted_result,
        "aggregated_decrypted_result"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->aggregateDecryptedPartSumUnlisted'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_aggregateDecryptedPartSumUnlisted(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    partially_decrypted_result: JString,
    aggregated_decrypted_result: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let pb_poll_parameters = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        poll_parameters,
        PollParametersStorage
    );
    let pb_partially_decrypted_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        partially_decrypted_result,
        DecryptedResultPartStorage
    );
    let mut pb_aggregated_decrypted_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        aggregated_decrypted_result,
        DecryptedResultPartStorage
    );
    let result = match wedpr_s_anonymous_ciphertext_voting::coordinator::aggregate_decrypted_part_sum_unlisted(
            &pb_poll_parameters,
            &pb_partially_decrypted_result,
            &mut pb_aggregated_decrypted_result,
        ) {
        Ok(v) => v,
        Err(e) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "aggregateDecryptedPartSumUnlisted failed, err = {:?}",
                    e
                ),
            )
        },
    };
    if !result {
        return java_set_error_field_and_extract_jobject(
            &_env,
            &result_jobject,
            &format!("aggregateDecryptedPartSumUnlisted failed"),
        );
    }
    // write back pb_aggregated_decrypted_result
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        pb_aggregated_decrypted_result,
        "aggregated_decrypted_result"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->finalizeVoteResult'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_finalizeVoteResult(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    vote_sum: JString,
    aggregated_decrypted_result: JString,
    max_vote_limit: jlong,
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
    let vote_result =
        match wedpr_s_anonymous_ciphertext_voting::coordinator::finalize_vote_result(
            &pb_poll_parameters,
            &pb_vote_sum,
            &pb_aggregated_decrypted_result,
            max_vote_limit as i64
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("finalizeVoteResult failed, err = {:?}", e),
                )
            },
        };
    // write vote_result
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        vote_result,
        "vote_result"
    );
    result_jobject.into_inner()
}

/// Java interface for
/// 'com.webank.wedpr.acv.NativeInterface->finalizeVoteResultUnlisted'.
#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_acv_NativeInterface_finalizeVoteResultUnlisted(
    _env: JNIEnv,
    _class: JClass,
    poll_parameters: JString,
    vote_sum: JString,
    aggregated_decrypted_result: JString,
    max_vote_limit: jlong,
    max_candidate_num: jlong,
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
    let mut pb_aggregated_decrypted_result = java_safe_jstring_to_pb!(
        _env,
        result_jobject,
        aggregated_decrypted_result,
        DecryptedResultPartStorage
    );
    let vote_result =
        match wedpr_s_anonymous_ciphertext_voting::coordinator::finalize_vote_result_unlisted(
            &pb_poll_parameters,
            &pb_vote_sum,
            &mut pb_aggregated_decrypted_result,
            max_vote_limit as i64,
            max_candidate_num as i64,
        ) {
            Ok(v) => v,
            Err(e) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!("finalizeVoteResult failed, err = {:?}", e),
                )
            },
        };
    // write vote_result
    java_safe_set_encoded_pb_field!(
        _env,
        result_jobject,
        vote_result,
        "vote_result"
    );
    result_jobject.into_inner()
}
