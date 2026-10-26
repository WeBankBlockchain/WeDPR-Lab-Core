// Copyright 2026 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use libc::c_char;
use wedpr_l_utils::error::WedprError;

// Non-null inputs must still point to valid, NUL-terminated caller-owned
// memory.
pub(crate) fn c_char_pointer_to_string(
    input: *const c_char,
) -> Result<String, WedprError> {
    if input.is_null() {
        return Err(WedprError::ArgumentError);
    }
    wedpr_ffi_common::utils::c_char_pointer_to_string(input)
}
