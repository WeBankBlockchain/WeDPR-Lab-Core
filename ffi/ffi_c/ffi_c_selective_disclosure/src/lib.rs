// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of selective_disclosure solution,
//! targeting C/C++ compatible architectures (including iOS).

// C/C++ FFI: C-style interfaces will be generated.

pub mod issuer;
pub mod user;
pub mod verifier;

#[macro_use]
extern crate wedpr_ffi_macros;
#[macro_use]
extern crate wedpr_macros;
