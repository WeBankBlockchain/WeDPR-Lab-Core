// Copyright 2022 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of ACV solution, targeting
//! Java-compatible architectures (including Android).

extern crate jni;

#[macro_use]
extern crate wedpr_ffi_macros;

pub mod coordinator;
pub mod counter;
pub mod verifier;
pub mod voter;
