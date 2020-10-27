// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros for FFI (adapting Rust to other programming languages).

// Java FFI macros.

// Type conversion section.

/// Converts Java String to Rust bytes, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_jstring_to_bytes {
    ($_env:expr, $result_jobject:expr, $java_string:expr) => {
        match java_jstring_to_bytes(&$_env, $java_string) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "jstring to bytes failed, input={}",
                        stringify!($java_string)
                    ),
                )
            },
        }
    };
}

/// Converts Java bytes to Rust bytes, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_jbytes_to_bytes {
    ($_env:expr, $result_jobject:expr, $java_bytes:expr) => {
        match java_jbytes_to_bytes(&$_env, $java_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "jbytes to bytes failed, input={}",
                        stringify!($java_bytes)
                    ),
                )
            },
        }
    };
}

/// Converts Java String to Rust String, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_jstring_to_string {
    ($_env:expr, $result_jobject:expr, $java_string:expr) => {
        match java_jstring_to_string(&$_env, $java_string) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "jstring to string failed, input={}",
                        stringify!($java_string)
                    ),
                )
            },
        }
    };
}

/// Converts Rust String to Java String, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_string_to_jstring {
    ($_env:expr, $result_jobject:expr, $rust_string:expr) => {
        JObject::from(match $_env.new_string($rust_string) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "string to jstring failed, input={}",
                        stringify!($rust_string)
                    ),
                )
            },
        })
    };
}

/// Converts Java String to Rust protobuf, and returns an error object if
/// failed.
#[macro_export]
macro_rules! java_safe_jstring_to_pb {
    ($_env:expr, $result_jobject:expr, $java_string:expr, $pb_type:ty) => {
        java_safe_bytes_to_pb!(
            $_env,
            $result_jobject,
            java_safe_jstring_to_bytes!($_env, $result_jobject, $java_string),
            $pb_type
        )
    };
}

/// Converts Rust bytes to Rust protobuf, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_bytes_to_pb {
    ($_env:expr, $result_jobject:expr, $rust_bytes:expr, $pb_type:ty) => {
        match protobuf::parse_from_bytes::<$pb_type>(&$rust_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "bytes to protobuf failed, input={}, protobuf type={}",
                        stringify!($rust_bytes),
                        stringify!($pb_type),
                    ),
                )
            },
        }
    };
}

/// Converts Rust protobuf to Rust bytes, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_pb_to_bytes {
    ($_env:expr, $result_jobject:expr, $rust_pb:expr) => {
        match $rust_pb.write_to_bytes() {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "protobuf to bytes failed, input={}",
                        stringify!($rust_pb)
                    ),
                )
            },
        }
    };
}

// Field setting section.

/// Sets a field of a Java object, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_field {
    (
        $_env:expr,
        $result_jobject:expr,
        $rust_value:expr,
        $field_name:expr,
        $field_type:expr
    ) => {
        match $_env.set_field(
            $result_jobject,
            $field_name,
            $field_type,
            JValue::from($rust_value),
        ) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!(
                        "Set Java field failed, field name={}, field type={}",
                        stringify!($field_name),
                        stringify!($field_type)
                    ),
                )
            },
        }
    };
}

/// Sets a field of long type, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_long_field {
    ($_env:expr, $result_jobject:expr, $rust_value:expr, $field_name:expr) => {
        java_safe_set_field!(
            $_env,
            $result_jobject,
            $rust_value,
            $field_name,
            "J"
        )
    };
}

/// Sets a field of boolean type, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_boolean_field {
    ($_env:expr, $result_jobject:expr, $rust_value:expr, $field_name:expr) => {
        java_safe_set_field!(
            $_env,
            $result_jobject,
            $rust_value,
            $field_name,
            "Z"
        )
    };
}

/// Sets a field of int type, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_int_field {
    ($_env:expr, $result_jobject:expr, $rust_value:expr, $field_name:expr) => {
        java_safe_set_field!(
            $_env,
            $result_jobject,
            $rust_value,
            $field_name,
            "I"
        )
    };
}

/// Sets a field of byte type, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_byte_field {
    ($_env:expr, $result_jobject:expr, $rust_value:expr, $field_name:expr) => {
        java_safe_set_field!(
            $_env,
            $result_jobject,
            $rust_value,
            $field_name,
            "B"
        )
    };
}

/// Sets a field of String type, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_string_field {
    ($_env:expr, $result_jobject:expr, $rust_string:expr, $field_name:expr) => {
        java_safe_set_field!(
            $_env,
            $result_jobject,
            java_safe_string_to_jstring!($_env, $result_jobject, $rust_string),
            $field_name,
            "Ljava/lang/String;"
        )
    };
}

/// Sets a field of bytes type, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_bytes_field {
    ($_env:expr, $result_jobject:expr, $rust_bytes:expr, $field_name:expr) => {
        java_safe_set_string_field!(
            $_env,
            $result_jobject,
            bytes_to_string(&$rust_bytes),
            $field_name
        )
    };
}

/// Sets a field of encoded protobuf type, and returns an error object if
/// failed.
#[macro_export]
macro_rules! java_safe_set_encoded_pb_field {
    ($_env:expr, $result_jobject:expr, $rust_pb:expr, $field_name:expr) => {
        java_safe_set_bytes_field!(
            $_env,
            $result_jobject,
            java_safe_pb_to_bytes!($_env, $result_jobject, $rust_pb),
            $field_name
        )
    };
}

// C/C++ FFI macros.

/// Converts C char pointer to Rust string, and returns a specified error value
/// if failed.
#[macro_export]
macro_rules! c_safe_c_char_pointer_to_string_with_error_value {
    ($c_char_pointer:expr, $error_value:expr) => {
        match c_char_pointer_to_string($c_char_pointer) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "C char pointer to string failed, pointer_name={}",
                    stringify!($c_char_pointer)
                );
                return $error_value;
            },
        }
    };
}

/// Converts C char pointer to Rust string, and returns NULL if failed.
#[macro_export]
macro_rules! c_safe_c_char_pointer_to_string {
    ($c_char_pointer:expr) => {
        c_safe_c_char_pointer_to_string_with_error_value!(
            $c_char_pointer,
            ptr::null_mut()
        )
    };
}

/// Converts C char pointer to Rust bytes, and returns a specified error value
/// if failed.
#[macro_export]
macro_rules! c_safe_c_char_pointer_to_bytes_with_error_value {
    ($c_char_pointer:expr, $error_value:expr) => {
        match string_to_bytes(
            &c_safe_c_char_pointer_to_string_with_error_value!(
                $c_char_pointer,
                $error_value
            ),
        ) {
            Ok(v) => v,
            Err(_) => return $error_value,
        }
    };
}

/// Converts C char pointer to Rust bytes, and returns NULL if failed.
#[macro_export]
macro_rules! c_safe_c_char_pointer_to_bytes {
    ($c_char_pointer:expr) => {
        c_safe_c_char_pointer_to_bytes_with_error_value!(
            $c_char_pointer,
            ptr::null_mut()
        )
    };
}

/// Converts C char pointer to Rust proto, and returns a specified error value
/// if failed.
#[macro_export]
macro_rules! c_safe_c_char_pointer_to_proto_with_error_value {
    ($c_char_pointer:expr, $pb_type:ty, $error_value:expr) => {
        match protobuf::parse_from_bytes::<$pb_type>(
            &c_safe_c_char_pointer_to_bytes_with_error_value!(
                $c_char_pointer,
                $error_value
            ),
        ) {
            Ok(v) => v,
            Err(_) => return $error_value,
        }
    };
}

/// Converts C char pointer to Rust proto, and returns NULL if failed.
#[macro_export]
macro_rules! c_safe_c_char_pointer_to_proto {
    ($c_char_pointer:expr, $pb_type:ty) => {
        c_safe_c_char_pointer_to_proto_with_error_value!(
            $c_char_pointer,
            $pb_type,
            ptr::null_mut()
        )
    };
}

/// Converts Rust string to C char pointer, and returns a specified error value
/// if failed.
#[macro_export]
macro_rules! c_safe_string_to_c_char_pointer_with_error_value {
    ($rust_string:expr, $error_value:expr) => {
        match CString::new($rust_string) {
            Ok(v) => v.into_raw(),
            Err(_) => return $error_value,
        }
    };
}

/// Converts Rust string to C char pointer, and returns NULL if failed.
#[macro_export]
macro_rules! c_safe_string_to_c_char_pointer {
    ($rust_string:expr) => {
        c_safe_string_to_c_char_pointer_with_error_value!(
            $rust_string,
            ptr::null_mut()
        )
    };
}

/// Converts Rust bytes to C char pointer, and returns NULL if failed.
#[macro_export]
macro_rules! c_safe_bytes_to_c_char_pointer {
    ($rust_string:expr) => {
        c_safe_string_to_c_char_pointer!(bytes_to_string($rust_string))
    };
}

/// Converts Rust protobuf to C char pointer, and returns NULL if failed.
#[macro_export]
macro_rules! c_safe_proto_to_c_char_pointer {
    ($rust_proto:expr) => {
        c_safe_bytes_to_c_char_pointer!(&match $rust_proto.write_to_bytes() {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        })
    };
}

/// Converts encodable Rust struct to Rust string, which a implemented encode
/// function.
#[macro_export]
macro_rules! encodable_struct_to_string {
    ($rust_struct:expr) => {
        bytes_to_string(
            &$rust_struct
                .encode()
                .write_to_bytes()
                .expect("struct to bytes should not fail"),
        )
    };
}

/// Returns C data, and returns a specified error value if any exception
/// occurred.
#[macro_export]
macro_rules! c_safe_return_with_error_value {
    ($result:expr, $error_value:expr) => {
        match $result {
            Ok(v) => v,
            Err(_) => $error_value,
        }
    };
}

/// Returns C data, and returns NULL if any exception occurred.
#[macro_export]
macro_rules! c_safe_return {
    ($result:expr) => {
        c_safe_return_with_error_value!($result, ptr::null_mut())
    };
}
